//! BabyJubJub elliptic curve operations over BN254 Fr.
//!
//! Twisted Edwards: `a*x^2 + y^2 = 1 + d*x^2*y^2`
//! Constants (iden3 standard): `a = 168700`, `d = 168696`
//!
//! Generator B8 (= 8 * base point, iden3 standard):
//!   Bx = 5299619240641551281634865583518297030282874472190772894086521144482721001553
//!   By = 16950150798460657717958625567821834550301663161624707787222815936182638968203
//!
//! ## Re-encryption verification
//!
//! One secret seed per transition, chained through SHA-256 to produce every
//! per-ciphertext offset scalar. `H(bytes) = sha256(bytes)` read as a
//! big-endian 256-bit integer, reduced mod r. The chain starts at
//! `r_0 = H(b"davinci-reenc-v1" || be32(seed) || be32(old_root))` and
//! advances with `r_{t+1} = H(be32(r_t))`. Each ACTIVE field consumes one
//! chain element (in block order, then field order) — `newC1 = origC1 + r_t*B8`
//! and `newC2 = origC2 + r_t*pubKey` — then the chain advances. Padded fields
//! (`i >= num_fields`) keep the identity assertion and consume nothing.
//!
//! The seed is the only source of secrecy; the tag and `old_root` are public
//! and only serve to move chains from different transitions onto distinct
//! starting points, so no scalar can repeat within or across transitions
//! (a scalar used twice would let anyone holding both originals link them
//! to their stored ciphertexts).
//!
//! ## Hardware acceleration
//!
//! Point addition is a single `babyjubjub_add` precompile call (affine in/out,
//! complete twisted-Edwards law, so doubling is `add(P, P)`).  Points are kept in
//! affine coordinates throughout: no projective Z, no `to_affine` inversion, and
//! re-encryption equality is a direct coordinate compare against the precompile's
//! canonical output.  Re-encryption scalar muls use 4-bit fixed-base window
//! tables (built once per batch for B8 and the election public key), cutting each
//! 256-bit mul to at most 63 precompile adds with no doublings.  The per-field
//! offset scalar is chained with SHA-256 (`sha256f` precompile), and the curve
//! membership check still uses the `arith256_mod`-backed `bn254_fr` field ops.

use crate::bn254_fr::{self, BnFr};
use crate::hash::sha256_once;
use crate::types::{
    BallotData, BjjCiphertext, FrRaw, ReencEntry, BALLOT_FIELDS, FAIL_REENC, FAIL_REFRESH,
    NUM_FIELDS,
};
use ziskos::syscalls::{syscall_babyjubjub_add, SyscallBabyJubJubAddParams, SyscallPoint256};
extern crate alloc;
use alloc::vec::Vec;

/// `H(bytes) = sha256(bytes)` read as a big-endian 256-bit integer, reduced
/// into BN254 Fr. Shared by the chain start (arbitrary-length preimage) and
/// each chain step (32-byte preimage).
fn sha256_to_scalar_bytes(preimage: &[u8]) -> FrRaw {
    let digest = sha256_once(preimage);
    // 32-byte big-endian digest → raw [u64; 4] LE limbs (may be ≥ r).
    let mut raw = [0u64; 4];
    for i in 0..4 {
        let off = (3 - i) * 8;
        raw[i] = u64::from_be_bytes(digest[off..off + 8].try_into().unwrap());
    }
    bn254_fr::reduce(&raw)
}

/// Serialize an FrRaw as its 32-byte big-endian encoding.
#[inline]
fn fr_to_be32(k: &FrRaw) -> [u8; 32] {
    let mut buf = [0u8; 32];
    for i in 0..4 {
        let off = (3 - i) * 8;
        buf[off..off + 8].copy_from_slice(&k[i].to_be_bytes());
    }
    buf
}

/// One step of the offset-scalar chain: `H(be32(k))`. Runs on the `sha256f`
/// precompile and closes with a single `arith256_mod` reduction.
fn sha256_to_scalar(k: &FrRaw) -> FrRaw {
    sha256_to_scalar_bytes(&fr_to_be32(k))
}

/// Domain tag for the re-encryption chain start. 16 bytes; keep in sync with
/// the producer (`elgamal.NewReencChain` in go-sdk).
const REENC_CHAIN_TAG: &[u8; 16] = b"davinci-reenc-v1";

/// Chain start: `r_0 = H(tag || be32(seed) || be32(old_root))`. The seed is
/// the per-batch sequencer secret; `old_root` is the STATETX `old_root` word
/// as the guest holds it. Binding the start to `old_root` keeps chains from
/// different transitions disjoint even if a producer reuses a seed.
pub fn reenc_chain_start(seed: &FrRaw, old_root: &FrRaw) -> FrRaw {
    let mut buf = [0u8; 16 + 32 + 32];
    buf[..16].copy_from_slice(REENC_CHAIN_TAG);
    buf[16..48].copy_from_slice(&fr_to_be32(seed));
    buf[48..80].copy_from_slice(&fr_to_be32(old_root));
    sha256_to_scalar_bytes(&buf)
}

// Curve constants

/// a = 168700 as BN254 Fr element.
const CURVE_A: BnFr = [168700, 0, 0, 0];

/// d = 168696 as BN254 Fr element.
const CURVE_D: BnFr = [168696, 0, 0, 0];

/// B8 generator x = 5299619240641551281634865583518297030282874472190772894086521144482721001553
const B8X_LE: FrRaw = [
    0x2893f3f6bb957051,
    0x2ab8d8010534e0b6,
    0x4eacb2e09d6277c1,
    0x0bb77a6ad63e739b,
];
/// B8 generator y = 16950150798460657717958625567821834550301663161624707787222815936182638968203
const B8Y_LE: FrRaw = [
    0x4b3c257a872d7d8b,
    0xfce0051fb9e13377,
    0x25572e1cd16bf9ed,
    0x25797203f7a0b249,
];

/// BabyJubJub prime-order subgroup order l =
/// 2736030358979909402780800718157159386076813972158567259200215660948447373041
/// (r_bjj = 8 * l is the full curve order). Any point on the curve that also
/// satisfies `l * P = O` sits in the prime-order subgroup B8 generates.
const BJJ_SUBGROUP_L: FrRaw = [
    0x677297dc392126f1,
    0xab3eedb83920ee0a,
    0x370a08b6d0302b0b,
    0x060c89ce5c263405,
];

// Affine twisted Edwards point ops, backed by the BabyJubJub precompile.

/// `a + b` via the `babyjubjub_add` precompile. The TE addition law is complete,
/// so the same call doubles when `a == b`, and the identity `(0, 1)` is neutral.
/// Coordinates must be on-curve and in Fr range; the result is canonical affine.
fn affine_add(a: &BjjAffine, b: &BjjAffine) -> BjjAffine {
    let mut p1 = SyscallPoint256 { x: a.0, y: a.1 };
    let p2 = SyscallPoint256 { x: b.0, y: b.1 };
    {
        let mut params = SyscallBabyJubJubAddParams { p1: &mut p1, p2: &p2 };
        syscall_babyjubjub_add(&mut params);
    }
    (p1.x, p1.y)
}

/// Canonicalize an untrusted affine point. The precompile requires both
/// coordinates to be in Fr range and does not reduce them itself, but stored
/// and parsed coordinates are raw 256-bit words: the SMT leaf hash binds bytes,
/// not residues, so `x + p` reaches us as a legitimate encoding of `x`. Reduce
/// once here, at the boundary, so `affine_add` stays syscall-only on the hot
/// path (tables and scalar_mult only ever see canonical points).
fn canon(p: &BjjAffine) -> BjjAffine {
    (bn254_fr::reduce(&p.0), bn254_fr::reduce(&p.1))
}

// Scalar multiplication

/// Scalar multiply: `scalar * point` using double-and-add (LSB-first),
/// stopping at the highest set bit (small scalars like CP's `msg` cost
/// proportionally less). Doubling reuses the complete add law.
fn scalar_mult(point: &BjjAffine, scalar: &FrRaw) -> BjjAffine {
    let top = match (0..4).rev().find(|&i| scalar[i] != 0) {
        None => return bjj_identity(),
        Some(t) => t,
    };
    let mut result = bjj_identity();
    let mut exp = *point;
    for i in 0..=top {
        let mut word = scalar[i];
        let bits = if i == top { 64 - word.leading_zeros() } else { 64 };
        for _ in 0..bits {
            if (word & 1) == 1 {
                result = affine_add(&result, &exp);
            }
            exp = affine_add(&exp, &exp);
            word >>= 1;
        }
    }
    result
}

/// Precomputed window table for a fixed base point (4- or 8-bit windows).
///
/// `windows[w][v-1] = (v << bits*w) * P`, so a 256-bit scalar mul is at most
/// `256/bits - 1` point additions (zero windows skipped) with no doublings.
/// 4-bit: 64x15 table, ~960 point ops to build, ~60 adds per mul.
/// 8-bit: 32x255 table, ~8160 point ops to build, ~32 adds per mul.
/// Breakeven is ~256 muls per table, so `new` picks the width from the
/// expected mul count for the batch.
struct BjjFixedBase {
    bits: u32,
    windows: Vec<Vec<BjjAffine>>,
}

impl BjjFixedBase {
    fn new(x: &FrRaw, y: &FrRaw, expected_muls: usize) -> Self {
        // ponytail: only 4 and 8 — both divide 64, so windows never straddle limbs.
        let bits: u32 = if expected_muls >= 256 { 8 } else { 4 };
        let vmax = (1usize << bits) - 1;
        let nwin = 256 / bits as usize;
        let mut windows = Vec::with_capacity(nwin);
        let mut base: BjjAffine = (*x, *y);
        for w in 0..nwin {
            // The precompile costs one syscall per op, so doubling is no cheaper
            // than adding: build the entries with a running sum.
            let mut entries: Vec<BjjAffine> = Vec::with_capacity(vmax);
            let mut acc = bjj_identity();
            for _ in 1..=vmax {
                acc = affine_add(&acc, &base);
                entries.push(acc);
            }
            windows.push(entries);
            if w + 1 < nwin {
                for _ in 0..bits {
                    base = affine_add(&base, &base);
                }
            }
        }
        BjjFixedBase { bits, windows }
    }

    fn mul(&self, scalar: &FrRaw) -> BjjAffine {
        let mask = (1u64 << self.bits) - 1;
        let per_limb = (64 / self.bits) as usize;
        let mut result = bjj_identity();
        for i in 0..4 {
            let mut word = scalar[i];
            for j in 0..per_limb {
                let v = (word & mask) as usize;
                if v != 0 {
                    result = affine_add(&result, &self.windows[i * per_limb + j][v - 1]);
                }
                word >>= self.bits;
            }
        }
        result
    }
}

/// Fixed-base mul `scalar * B8` via the compile-time 8-bit affine window
/// table (`b8_table.rs`): zero windows skipped, no runtime table build.
fn b8_mul(scalar: &FrRaw) -> BjjAffine {
    let mut result = bjj_identity();
    for i in 0..4 {
        let mut word = scalar[i];
        for j in 0..8 {
            let v = (word & 0xFF) as usize;
            if v != 0 {
                let e = &crate::b8_table::B8_WINDOWS[(i * 8 + j) * 255 + v - 1];
                result = affine_add(&result, &(e[0], e[1]));
            }
            word >>= 8;
        }
    }
    result
}

// Curve membership

/// Check that `(x, y)` satisfies the BabyJubJub twisted Edwards equation:
///   `a*x² + y² = 1 + d*x²*y²`  (with a = 168700, d = 168696).
fn is_on_bjj_curve(x: &BnFr, y: &BnFr) -> bool {
    let x2 = bn254_fr::sqr(x);
    let y2 = bn254_fr::sqr(y);
    let lhs = bn254_fr::add(&bn254_fr::mul(&CURVE_A, &x2), &y2);  // a*x² + y²
    let rhs = bn254_fr::add(&bn254_fr::ONE, &bn254_fr::mul(&CURVE_D, &bn254_fr::mul(&x2, &y2))); // 1 + d*x²*y²
    lhs == rhs
}

// Public API

/// Verify that `reencrypted[i] = original[i] + encZero(r_t, pubKey)` for every
/// ACTIVE field, threading the batch-scoped chain `chain` through the entry.
/// For each active field the current chain value is used once
/// (`newC1 = origC1 + r_t*B8`, `newC2 = origC2 + r_t*pubKey`), then the chain
/// advances via `sha256_to_scalar`. Padded fields (`i >= num_fields`) keep the
/// TE-identity assertion and consume nothing, so the next entry resumes exactly
/// where this one left off. `pk_table` is the fixed-base window table for the
/// (already curve-validated) ElGamal public key; B8 uses the compile-time table.
fn verify_reencryption(
    chain: &mut FrRaw,
    pk_table: &BjjFixedBase,
    num_fields: usize,
    original: &[BjjCiphertext],
    reencrypted: &[BjjCiphertext],
) -> bool {
    if original.len() != reencrypted.len() {
        return false;
    }

    for i in 0..original.len() {
        if i >= num_fields {
            // Padded slot: assert identity on both sides, skip EC work and
            // do not advance the chain.
            let o = &original[i];
            let r = &reencrypted[i];
            if o.c1x != bn254_fr::ZERO || o.c1y != bn254_fr::ONE
                || o.c2x != bn254_fr::ZERO || o.c2y != bn254_fr::ONE
                || r.c1x != bn254_fr::ZERO || r.c1y != bn254_fr::ONE
                || r.c2x != bn254_fr::ZERO || r.c2y != bn254_fr::ONE {
                return false;
            }
            continue;
        }
        let delta1 = b8_mul(chain);
        let delta2 = pk_table.mul(chain);

        // newC = origC + delta; compare against the claimed affine point. The
        // precompile returns canonical coordinates, and the producer emits
        // canonical TE coords, so a direct equality is exact.
        let expected1 = affine_add(&canon(&(original[i].c1x, original[i].c1y)), &delta1);
        if expected1 != (reencrypted[i].c1x, reencrypted[i].c1y) {
            return false;
        }

        let expected2 = affine_add(&canon(&(original[i].c2x, original[i].c2y)), &delta2);
        if expected2 != (reencrypted[i].c2x, reencrypted[i].c2y) {
            return false;
        }

        // Advance the chain for the next active field.
        *chain = sha256_to_scalar(chain);
    }
    true
}

/// Identity ballot: every field is `((0,1),(0,1))`. Used as the initial value
/// of `refresh_delta` and as the "new" ciphertexts for padded slots.
fn identity_ballot() -> BallotData {
    let mut b: BallotData = [bn254_fr::ZERO; BALLOT_FIELDS];
    let mut f = 0;
    while f < NUM_FIELDS {
        // c1 = (0, 1), c2 = (0, 1)
        b[f * 4] = bn254_fr::ZERO;
        b[f * 4 + 1] = bn254_fr::ONE;
        b[f * 4 + 2] = bn254_fr::ZERO;
        b[f * 4 + 3] = bn254_fr::ONE;
        f += 1;
    }
    b
}

/// Re-encrypt one refresh entry in-guest. For each active field: draw the next
/// chain element, add `chain*B8` and `chain*pubKey` to the old ciphertexts, and
/// fold the same two deltas into `refresh_delta[i]`. For padded slots the old
/// ciphertext must be the TE identity `((0,1),(0,1))` (else FAIL_REFRESH) and
/// the new ciphertext is identity too; the chain is not advanced (mirrors
/// `verify_reencryption`).
fn refresh_one(
    chain: &mut FrRaw,
    pk_table: &BjjFixedBase,
    num_fields: usize,
    old: &BallotData,
    new: &mut BallotData,
    refresh_delta: &mut BallotData,
) -> bool {
    for i in 0..NUM_FIELDS {
        let base = i * 4;
        if i >= num_fields {
            // Padded slot must be the TE identity on the old side; the guest
            // fills identity on the new side and does no EC work.
            if old[base] != bn254_fr::ZERO || old[base + 1] != bn254_fr::ONE
                || old[base + 2] != bn254_fr::ZERO || old[base + 3] != bn254_fr::ONE
            {
                return false;
            }
            new[base] = bn254_fr::ZERO;
            new[base + 1] = bn254_fr::ONE;
            new[base + 2] = bn254_fr::ZERO;
            new[base + 3] = bn254_fr::ONE;
            continue;
        }
        let delta1 = b8_mul(chain);
        let delta2 = pk_table.mul(chain);
        let old_c1 = canon(&(old[base], old[base + 1]));
        let old_c2 = canon(&(old[base + 2], old[base + 3]));
        let new_c1 = affine_add(&old_c1, &delta1);
        let new_c2 = affine_add(&old_c2, &delta2);
        new[base] = new_c1.0;
        new[base + 1] = new_c1.1;
        new[base + 2] = new_c2.0;
        new[base + 3] = new_c2.1;
        // Fold the deltas into the accumulator. The initial value is identity,
        // so the first add is `identity + delta = delta`.
        let d1 = (refresh_delta[base], refresh_delta[base + 1]);
        let d2 = (refresh_delta[base + 2], refresh_delta[base + 3]);
        let acc1 = affine_add(&d1, &delta1);
        let acc2 = affine_add(&d2, &delta2);
        refresh_delta[base] = acc1.0;
        refresh_delta[base + 1] = acc1.1;
        refresh_delta[base + 2] = acc2.0;
        refresh_delta[base + 3] = acc2.1;
        *chain = sha256_to_scalar(chain);
    }
    true
}

/// Verify all re-encryption entries from the ParsedInput REENCBLK and the
/// silent-refresh chain from STATETX. Returns `(ok, refreshed_new,
/// refresh_delta)`.
///
/// - `ok`: true iff both the batch re-encryptions and the refresh work are
///   valid. An absent REENCBLK sets `FAIL_MISSING_BLOCK`; batch re-encryption
///   failures set `FAIL_REENC`; refresh failures set `FAIL_REFRESH`.
/// - `refreshed_new`: newly re-encrypted ballots computed for each refresh
///   entry, same order as `refreshed_old`. Padded slots are identity.
/// - `refresh_delta`: per-field sum of the deltas added across all refresh
///   entries, in the flat 64-Fr `BallotData` layout. Fed into
///   `results::verify_results` so the accumulator picks up the refresh work
///   (without this the accumulator identifies the overwrite set — §5.1).
///
/// The chain is started ONCE per batch from `(reenc_seed, old_root)` and
/// threaded through every REENCBLK entry, then continues through every refresh
/// entry in order. Every chain element is consumed by exactly one active
/// ciphertext, refresh included. The public key is curve-checked once and its
/// fixed-base window table sized to cover the batch's REENC entries plus the
/// refresh entries; B8 uses the compile-time table.
pub fn verify_batch_from_parsed(
    reenc_pub_key: &Option<(FrRaw, FrRaw)>,
    reenc_seed: &FrRaw,
    old_root: &FrRaw,
    reenc_entries: &[ReencEntry],
    refreshed_old: &[BallotData],
    num_fields: usize,
    fail_mask: &mut u32,
) -> (bool, Vec<BallotData>, BallotData) {
    let mut refresh_delta = identity_ballot();
    let (pub_key_x, pub_key_y) = match reenc_pub_key {
        None => {
            *fail_mask |= crate::types::FAIL_MISSING_BLOCK;
            return (false, Vec::new(), refresh_delta);
        }
        Some(pk) => pk,
    };
    // No REENC entries and no refreshes: nothing to do, skip the table build.
    if reenc_entries.is_empty() && refreshed_old.is_empty() {
        return (true, Vec::new(), refresh_delta);
    }
    if !is_on_bjj_curve(pub_key_x, pub_key_y) {
        *fail_mask |= FAIL_REENC;
        return (false, Vec::new(), refresh_delta);
    }
    // Prime-order subgroup check on the encryption key. BabyJubJub has
    // cofactor 8; a small-order pk would let a hostile sequencer collapse
    // `r_t * pk` onto a bounded set of deltas, leaking scalars across ballots.
    // Reject identity and require l * pk = O (~400 precompile adds, once per
    // batch).
    let pk = canon(&(*pub_key_x, *pub_key_y));
    if pk == bjj_identity() || scalar_mult(&pk, &BJJ_SUBGROUP_L) != bjj_identity() {
        *fail_mask |= FAIL_REENC;
        return (false, Vec::new(), refresh_delta);
    }
    let expected_muls = (reenc_entries.len() + refreshed_old.len()) * num_fields;
    let pk_table = BjjFixedBase::new(pub_key_x, pub_key_y, expected_muls);
    let mut chain = reenc_chain_start(reenc_seed, old_root);

    for entry in reenc_entries {
        if !verify_reencryption(
            &mut chain,
            &pk_table,
            num_fields,
            &entry.original,
            &entry.reencrypted,
        ) {
            *fail_mask |= FAIL_REENC;
            return (false, Vec::new(), refresh_delta);
        }
    }

    // Silent refreshes continue the SAME chain so no scalar repeats.
    let mut refreshed_new: Vec<BallotData> = Vec::with_capacity(refreshed_old.len());
    for old in refreshed_old {
        let mut new: BallotData = [bn254_fr::ZERO; BALLOT_FIELDS];
        if !refresh_one(&mut chain, &pk_table, num_fields, old, &mut new, &mut refresh_delta) {
            *fail_mask |= FAIL_REFRESH;
            return (false, Vec::new(), refresh_delta);
        }
        refreshed_new.push(new);
    }
    (true, refreshed_new, refresh_delta)
}

// Affine point API (TE coordinates) for the Chaum-Pedersen verifier.

/// Affine BabyJubJub point in standard Twisted Edwards coordinates.
pub type BjjAffine = (FrRaw, FrRaw);

/// The identity point (0, 1).
pub fn bjj_identity() -> BjjAffine {
    (bn254_fr::ZERO, bn254_fr::ONE)
}

/// The iden3 generator B8.
pub fn bjj_generator() -> BjjAffine {
    (B8X_LE, B8Y_LE)
}

/// `a + b` in affine TE coordinates. Inputs may be non-canonical.
pub fn bjj_add(a: &BjjAffine, b: &BjjAffine) -> BjjAffine {
    affine_add(&canon(a), &canon(b))
}

/// `scalar * p`, scalar as raw 256-bit LE limbs (not reduced).
pub fn bjj_mul(p: &BjjAffine, scalar: &FrRaw) -> BjjAffine {
    scalar_mult(&canon(p), scalar)
}

/// `-p` = (-x, y) in twisted Edwards form. `neg` reduces x; y is reduced here
/// so the pair stays in range for the precompile.
pub fn bjj_neg(p: &BjjAffine) -> BjjAffine {
    (bn254_fr::neg(&p.0), bn254_fr::reduce(&p.1))
}

/// Running affine point sum. Each step is one precompile add.
pub struct BjjAccumulator(BjjAffine);

impl BjjAccumulator {
    pub fn new(p: &BjjAffine) -> Self {
        BjjAccumulator(canon(p))
    }

    pub fn add(&mut self, p: &BjjAffine) {
        self.0 = affine_add(&self.0, &canon(p));
    }

    /// Homomorphic subtraction: add the group inverse `(-x, y)`.
    pub fn sub(&mut self, p: &BjjAffine) {
        let n = bjj_neg(p);
        self.0 = affine_add(&self.0, &n);
    }

    pub fn finish(&self) -> BjjAffine {
        self.0
    }
}

/// Curve membership check for an affine TE point.
pub fn bjj_on_curve(p: &BjjAffine) -> bool {
    is_on_bjj_curve(&p.0, &p.1)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCALARS: [[u64; 4]; 4] = [
        [1, 0, 0, 0],
        [0xF0F0F0F0F0F0F0F0, 0x0123456789ABCDEF, 0xFFFFFFFFFFFFFFFF, 0x0000000000000001],
        [0xDEADBEEFCAFEBABE, 0, 0x8000000000000000, 0x00FFFFFFFFFFFFFF],
        [0, 0, 0, 0],
    ];

    #[test]
    fn identity_is_neutral() {
        let b8 = bjj_generator();
        assert_eq!(affine_add(&b8, &bjj_identity()), b8);
        assert_eq!(affine_add(&bjj_identity(), &b8), b8);
    }

    #[test]
    fn neg_roundtrip() {
        // P + (-P) = identity for a generic multiple of B8.
        let p = scalar_mult(&bjj_generator(), &SCALARS[1]);
        assert!(bjj_on_curve(&p));
        assert_eq!(affine_add(&p, &bjj_neg(&p)), bjj_identity());
    }

    #[test]
    fn fixed_base_matches_double_and_add() {
        // Window decomposition vs LSB-first bit decomposition must agree.
        let b8 = bjj_generator();
        // 0 muls -> 4-bit table, 4096 muls -> 8-bit table.
        for expected in [0usize, 4096] {
            let table = BjjFixedBase::new(&B8X_LE, &B8Y_LE, expected);
            for s in &SCALARS {
                assert_eq!(table.mul(s), scalar_mult(&b8, s));
            }
        }
    }

    #[test]
    fn b8_const_table_matches_runtime_build() {
        let table = BjjFixedBase::new(&B8X_LE, &B8Y_LE, 4096); // 8-bit
        for w in 0..32 {
            for v in 1..=255usize {
                let e = &crate::b8_table::B8_WINDOWS[w * 255 + v - 1];
                assert_eq!(table.windows[w][v - 1], (e[0], e[1]), "w={w} v={v}");
            }
        }
    }

    #[test]
    fn b8_mul_matches_double_and_add() {
        let b8 = bjj_generator();
        for s in &SCALARS {
            assert_eq!(b8_mul(s), scalar_mult(&b8, s));
        }
    }

    // Re-encryption chain

    /// Big-endian hex to FrRaw limbs (test helper).
    fn fr_from_be_hex(hex: &str) -> FrRaw {
        let bytes: Vec<u8> = (0..64)
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let mut out = [0u64; 4];
        for i in 0..4 {
            let off = (3 - i) * 8;
            out[i] = u64::from_be_bytes(bytes[off..off + 8].try_into().unwrap());
        }
        out
    }

    /// Frozen vector shared with the Go producer: seed = 1, old_root = 2.
    #[test]
    fn reenc_chain_test_vector() {
        let r0 = reenc_chain_start(&[1, 0, 0, 0], &[2, 0, 0, 0]);
        let r1 = sha256_to_scalar(&r0);
        let r2 = sha256_to_scalar(&r1);
        assert_eq!(r0, fr_from_be_hex("0a63922a58b3fe4dbec15e6db1be5438713862d2fa6fa543af70812000d38d7d"));
        assert_eq!(r1, fr_from_be_hex("1d7152578cfe912cf8cc3185201ade4d7d81f22d91173f16fb8e88da028240ed"));
        assert_eq!(r2, fr_from_be_hex("2848f34e5de5c01ed168f2be00d066ba64d30e1229318b7ed98ab934f78a2137"));
    }

    /// Round trip: build two entries whose reencrypted ciphertexts are the
    /// original + encZero(r_t, pubKey) sequence produced by the chain, then
    /// check that swapping entries, mutating old_root, or mutating the seed
    /// makes verification fail.
    #[test]
    fn reenc_batch_roundtrip_and_tamper_detection() {
        use crate::types::{BjjCiphertext, ReencEntry};

        let seed: FrRaw = [42, 0, 0, 0];
        let old_root: FrRaw = [0xdead_beef, 0, 0, 0];

        // Public key = 7 * B8 (small, valid on-curve point in the prime-order
        // subgroup, since B8 generates the subgroup).
        let pk_scalar: FrRaw = [7, 0, 0, 0];
        let pk = b8_mul(&pk_scalar);
        assert!(bjj_on_curve(&pk));

        // Two entries, num_fields = 3 (so field slots 3..NUM_FIELDS are padded).
        let num_fields = 3usize;
        let pk_table = BjjFixedBase::new(&pk.0, &pk.1, 2 * num_fields);
        // Identity ciphertext: ((0,1),(0,1)).
        let identity_ct = BjjCiphertext {
            c1x: bn254_fr::ZERO, c1y: bn254_fr::ONE,
            c2x: bn254_fr::ZERO, c2y: bn254_fr::ONE,
        };

        // Build entries by picking distinct originals for each active field
        // (each original is a small multiple of B8, so on-curve) and computing
        // the reencrypted ciphertexts from the chain.
        let mut chain = reenc_chain_start(&seed, &old_root);
        let mut entries: Vec<ReencEntry> = Vec::with_capacity(2);
        for e in 0..2u64 {
            let mut original: [BjjCiphertext; crate::types::NUM_FIELDS] = Default::default();
            let mut reencrypted: [BjjCiphertext; crate::types::NUM_FIELDS] = Default::default();
            for i in 0..crate::types::NUM_FIELDS {
                if i < num_fields {
                    // Pick distinct originals: c1 = (10 + e*100 + i)*B8, c2 = (20 + e*100 + i)*B8.
                    let s1: FrRaw = [10 + e * 100 + i as u64, 0, 0, 0];
                    let s2: FrRaw = [20 + e * 100 + i as u64, 0, 0, 0];
                    let c1 = b8_mul(&s1);
                    let c2 = b8_mul(&s2);
                    original[i] = BjjCiphertext { c1x: c1.0, c1y: c1.1, c2x: c2.0, c2y: c2.1 };

                    let delta1 = b8_mul(&chain);
                    let delta2 = pk_table.mul(&chain);
                    let new_c1 = affine_add(&canon(&c1), &delta1);
                    let new_c2 = affine_add(&canon(&c2), &delta2);
                    reencrypted[i] = BjjCiphertext {
                        c1x: new_c1.0, c1y: new_c1.1,
                        c2x: new_c2.0, c2y: new_c2.1,
                    };
                    chain = sha256_to_scalar(&chain);
                } else {
                    // Identity in padded slots.
                    original[i] = identity_ct.clone();
                    reencrypted[i] = identity_ct.clone();
                }
            }
            entries.push(ReencEntry { original, reencrypted });
        }

        // Sanity: valid batch verifies.
        let mut mask = 0u32;
        let (ok, _rn, _rd) = verify_batch_from_parsed(
            &Some((pk.0, pk.1)), &seed, &old_root, &entries, &[], num_fields, &mut mask,
        );
        assert!(ok && mask == 0, "valid batch should pass, mask={mask:#x}");

        // Swap entries -> fails.
        let mut mask = 0u32;
        let swapped = vec![entries[1].clone(), entries[0].clone()];
        let (ok, _, _) = verify_batch_from_parsed(
            &Some((pk.0, pk.1)), &seed, &old_root, &swapped, &[], num_fields, &mut mask,
        );
        assert!(!ok && (mask & FAIL_REENC) != 0, "swapped entries must fail");

        // Different old_root -> fails.
        let mut mask = 0u32;
        let bad_root: FrRaw = [0xdead_beef ^ 1, 0, 0, 0];
        let (ok, _, _) = verify_batch_from_parsed(
            &Some((pk.0, pk.1)), &seed, &bad_root, &entries, &[], num_fields, &mut mask,
        );
        assert!(!ok && (mask & FAIL_REENC) != 0, "different old_root must fail");

        // Different seed -> fails.
        let mut mask = 0u32;
        let bad_seed: FrRaw = [42 ^ 1, 0, 0, 0];
        let (ok, _, _) = verify_batch_from_parsed(
            &Some((pk.0, pk.1)), &bad_seed, &old_root, &entries, &[], num_fields, &mut mask,
        );
        assert!(!ok && (mask & FAIL_REENC) != 0, "different seed must fail");

        // Missing block -> FAIL_MISSING_BLOCK.
        let mut mask = 0u32;
        let (ok, _, _) = verify_batch_from_parsed(
            &None, &seed, &old_root, &entries, &[], num_fields, &mut mask,
        );
        assert!(!ok && (mask & crate::types::FAIL_MISSING_BLOCK) != 0, "missing block must set FAIL_MISSING_BLOCK");
    }

    /// Roundtrip a refresh: build old ballots as small multiples of B8, run
    /// `verify_batch_from_parsed` with no REENC entries and the refreshes only,
    /// then re-derive the deltas by hand and check both `refreshed_new` and
    /// `refresh_delta` match. `refresh_delta` must equal Σ (new_i - old_i)
    /// across all refreshes per active field (which is Σ delta_i).
    #[test]
    fn refresh_roundtrip_delta_matches_sum() {
        use crate::types::{BALLOT_FIELDS, BjjCiphertext, NUM_FIELDS};

        let seed: FrRaw = [0x1234, 0, 0, 0];
        let old_root: FrRaw = [0xabcd, 0, 0, 0];
        let pk_scalar: FrRaw = [11, 0, 0, 0];
        let pk = b8_mul(&pk_scalar);
        assert!(bjj_on_curve(&pk));

        let num_fields = 3usize;
        let identity_ct = BjjCiphertext {
            c1x: bn254_fr::ZERO, c1y: bn254_fr::ONE,
            c2x: bn254_fr::ZERO, c2y: bn254_fr::ONE,
        };
        let _ = identity_ct;

        // Two refresh entries. Active-field ciphertexts are distinct small
        // multiples of B8, padded slots are identity.
        let mut refreshed_old: Vec<BallotData> = Vec::with_capacity(2);
        for e in 0..2u64 {
            let mut b: BallotData = [bn254_fr::ZERO; BALLOT_FIELDS];
            for i in 0..NUM_FIELDS {
                if i < num_fields {
                    let s1: FrRaw = [500 + e * 50 + i as u64, 0, 0, 0];
                    let s2: FrRaw = [600 + e * 50 + i as u64, 0, 0, 0];
                    let c1 = b8_mul(&s1);
                    let c2 = b8_mul(&s2);
                    b[i * 4] = c1.0; b[i * 4 + 1] = c1.1;
                    b[i * 4 + 2] = c2.0; b[i * 4 + 3] = c2.1;
                } else {
                    b[i * 4] = bn254_fr::ZERO; b[i * 4 + 1] = bn254_fr::ONE;
                    b[i * 4 + 2] = bn254_fr::ZERO; b[i * 4 + 3] = bn254_fr::ONE;
                }
            }
            refreshed_old.push(b);
        }

        // Precompute expected deltas + accumulator by hand from the chain.
        let pk_table = BjjFixedBase::new(&pk.0, &pk.1, refreshed_old.len() * num_fields);
        let mut expected_new: Vec<BallotData> = Vec::with_capacity(refreshed_old.len());
        let mut expected_delta = identity_ballot();
        {
            let mut chain = reenc_chain_start(&seed, &old_root);
            for old in &refreshed_old {
                let mut new: BallotData = [bn254_fr::ZERO; BALLOT_FIELDS];
                for i in 0..NUM_FIELDS {
                    let base = i * 4;
                    if i >= num_fields {
                        new[base] = bn254_fr::ZERO; new[base + 1] = bn254_fr::ONE;
                        new[base + 2] = bn254_fr::ZERO; new[base + 3] = bn254_fr::ONE;
                        continue;
                    }
                    let d1 = b8_mul(&chain);
                    let d2 = pk_table.mul(&chain);
                    let nc1 = affine_add(&canon(&(old[base], old[base + 1])), &d1);
                    let nc2 = affine_add(&canon(&(old[base + 2], old[base + 3])), &d2);
                    new[base] = nc1.0; new[base + 1] = nc1.1;
                    new[base + 2] = nc2.0; new[base + 3] = nc2.1;
                    let e1 = affine_add(&(expected_delta[base], expected_delta[base + 1]), &d1);
                    let e2 = affine_add(&(expected_delta[base + 2], expected_delta[base + 3]), &d2);
                    expected_delta[base] = e1.0; expected_delta[base + 1] = e1.1;
                    expected_delta[base + 2] = e2.0; expected_delta[base + 3] = e2.1;
                    chain = sha256_to_scalar(&chain);
                }
                expected_new.push(new);
            }
        }

        let mut mask = 0u32;
        let (ok, refreshed_new, refresh_delta) = verify_batch_from_parsed(
            &Some((pk.0, pk.1)),
            &seed,
            &old_root,
            &[],
            &refreshed_old,
            num_fields,
            &mut mask,
        );
        assert!(ok && mask == 0, "refresh should verify, mask={mask:#x}");
        assert_eq!(refreshed_new.len(), expected_new.len());
        for i in 0..expected_new.len() {
            assert_eq!(refreshed_new[i], expected_new[i], "refreshed_new[{i}] mismatch");
        }
        assert_eq!(refresh_delta, expected_delta, "refresh_delta mismatch");
    }

    /// The order-2 point (0, -1) is on the curve but sits in the cofactor
    /// subgroup, so the prime-order check must reject it as an encryption key.
    #[test]
    fn reenc_rejects_small_order_pk() {
        use crate::types::FAIL_REENC;
        // y = -1 mod p, x = 0. On the curve: a*0 + (-1)^2 = 1 = 1 + d*0*1. Yes.
        let neg_one = bn254_fr::neg(&bn254_fr::ONE);
        let pk_x: FrRaw = bn254_fr::ZERO;
        let pk_y: FrRaw = neg_one;
        assert!(bjj_on_curve(&(pk_x, pk_y)));
        // 2 * (0, -1) = (0, 1) = identity, so order divides 2; fails l * P = O check
        // (l is odd).
        let seed: FrRaw = [1, 0, 0, 0];
        let old_root: FrRaw = [2, 0, 0, 0];
        let mut mask = 0u32;
        // A dummy REENC entry so we get past the empty-batch shortcut.
        let identity_ct = crate::types::BjjCiphertext {
            c1x: bn254_fr::ZERO, c1y: bn254_fr::ONE,
            c2x: bn254_fr::ZERO, c2y: bn254_fr::ONE,
        };
        let mut original: [crate::types::BjjCiphertext; crate::types::NUM_FIELDS] = Default::default();
        let mut reencrypted: [crate::types::BjjCiphertext; crate::types::NUM_FIELDS] = Default::default();
        for i in 0..crate::types::NUM_FIELDS {
            original[i] = identity_ct.clone();
            reencrypted[i] = identity_ct.clone();
        }
        let entries = alloc::vec![crate::types::ReencEntry { original, reencrypted }];
        let (ok, _, _) = verify_batch_from_parsed(
            &Some((pk_x, pk_y)), &seed, &old_root, &entries, &[], 0, &mut mask,
        );
        assert!(!ok, "small-order pk must be rejected");
        assert!(mask & FAIL_REENC != 0, "FAIL_REENC not set, mask={mask:#x}");
    }

    /// Any multiple of B8 sits in the prime-order subgroup, so a batch keyed on
    /// pk = k*B8 must pass the new prime-order check (feed it one all-identity
    /// entry so the shortcut doesn't skip the check).
    #[test]
    fn reenc_accepts_b8_multiple_pk() {
        use crate::types::{BjjCiphertext, NUM_FIELDS, ReencEntry};
        let seed: FrRaw = [7, 0, 0, 0];
        let old_root: FrRaw = [11, 0, 0, 0];
        let pk = b8_mul(&[13, 0, 0, 0]);
        let identity_ct = BjjCiphertext {
            c1x: bn254_fr::ZERO, c1y: bn254_fr::ONE,
            c2x: bn254_fr::ZERO, c2y: bn254_fr::ONE,
        };
        let mut original: [BjjCiphertext; NUM_FIELDS] = Default::default();
        let mut reencrypted: [BjjCiphertext; NUM_FIELDS] = Default::default();
        for i in 0..NUM_FIELDS {
            original[i] = identity_ct.clone();
            reencrypted[i] = identity_ct.clone();
        }
        // num_fields = 0 so every slot is padded (identity) and no chain elements
        // are consumed — the check runs but no re-encryption arithmetic does.
        let entries = alloc::vec![ReencEntry { original, reencrypted }];
        let mut mask = 0u32;
        let (ok, _, _) = verify_batch_from_parsed(
            &Some((pk.0, pk.1)), &seed, &old_root, &entries, &[], 0, &mut mask,
        );
        assert!(ok, "B8 multiple must be accepted, mask={mask:#x}");
    }

    #[test]
    fn refresh_rejects_non_identity_padded_slot() {
        use crate::types::{BALLOT_FIELDS, NUM_FIELDS};
        let seed: FrRaw = [1, 0, 0, 0];
        let old_root: FrRaw = [2, 0, 0, 0];
        let pk = b8_mul(&[3, 0, 0, 0]);
        let num_fields = 2usize;

        // Padded slot 2 carries a non-identity ciphertext.
        let mut b: BallotData = [bn254_fr::ZERO; BALLOT_FIELDS];
        for i in 0..NUM_FIELDS {
            b[i * 4] = bn254_fr::ZERO; b[i * 4 + 1] = bn254_fr::ONE;
            b[i * 4 + 2] = bn254_fr::ZERO; b[i * 4 + 3] = bn254_fr::ONE;
        }
        // Poison field 2 (which is padded because num_fields=2).
        let p = b8_mul(&[5, 0, 0, 0]);
        b[2 * 4] = p.0; b[2 * 4 + 1] = p.1;

        let mut mask = 0u32;
        let (ok, _rn, _rd) = verify_batch_from_parsed(
            &Some((pk.0, pk.1)), &seed, &old_root, &[], &[b], num_fields, &mut mask,
        );
        assert!(!ok, "non-identity padded slot must fail");
        assert!(mask & FAIL_REFRESH != 0, "FAIL_REFRESH must be set, got mask={mask:#x}");
    }

    /// Regenerates `src/b8_table.rs`. Run manually after changing the layout:
    /// `cargo test -p circuit-primitives --release gen_b8_table -- --ignored`
    #[test]
    #[ignore]
    fn gen_b8_table() {
        use std::fmt::Write as _;
        let table = BjjFixedBase::new(&B8X_LE, &B8Y_LE, 4096); // force 8-bit
        let mut out = String::with_capacity(1 << 21);
        out.push_str(
            "//! Generated by `gen_b8_table` in babyjubjub.rs - do not edit.\n\
             //! 8-bit window table for the BabyJubJub base B8, affine coordinates:\n\
             //! `B8_WINDOWS[w * 255 + v - 1] = [x, y]` limbs of `(v << 8w) * B8`.\n\n\
             pub static B8_WINDOWS: [[[u64; 4]; 2]; 8160] = [\n",
        );
        for w in 0..32 {
            for (x, y) in &table.windows[w] {
                writeln!(
                    out,
                    "[[{:#x},{:#x},{:#x},{:#x}],[{:#x},{:#x},{:#x},{:#x}]],",
                    x[0], x[1], x[2], x[3], y[0], y[1], y[2], y[3]
                )
                .unwrap();
            }
        }
        out.push_str("];\n");
        std::fs::write(concat!(env!("CARGO_MANIFEST_DIR"), "/src/b8_table.rs"), out).unwrap();
    }
}
