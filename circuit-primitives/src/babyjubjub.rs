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
//! Per-field offset scalar chained through SHA-256: `k_0 = H(k)`,
//! `k_{i+1} = H(k_i)`, where `H(x) = sha256(x_be32) mod r`.
//! For each field i: `newC1[i] = origC1[i] + k_i*B8`, `newC2[i] = origC2[i] + k_i*pubKey`.
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
use crate::types::{FrRaw, BjjCiphertext, ReencEntry, FAIL_REENC};
use ziskos::syscalls::{syscall_babyjubjub_add, SyscallBabyJubJubAddParams, SyscallPoint256};

/// One step of the re-encryption offset-scalar chain: `sha256(k_be32)` read as a
/// big-endian 256-bit integer, reduced into BN254 Fr. Mirrors the producer
/// (davinci-node `elgamal` re-encryption). Replaces the former Poseidon chain to
/// move the work onto the `sha256f` precompile.
fn sha256_to_scalar(k: &FrRaw) -> FrRaw {
    // k (< r) → 32-byte big-endian.
    let mut buf = [0u8; 32];
    for i in 0..4 {
        let off = (3 - i) * 8;
        buf[off..off + 8].copy_from_slice(&k[i].to_be_bytes());
    }
    let digest = sha256_once(&buf);
    // 32-byte big-endian digest → raw [u64; 4] LE limbs (may be ≥ r).
    let mut raw = [0u64; 4];
    for i in 0..4 {
        let off = (3 - i) * 8;
        raw[i] = u64::from_be_bytes(digest[off..off + 8].try_into().unwrap());
    }
    bn254_fr::reduce(&raw)
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

/// Verify that `reencrypted[i] = original[i] + encZero(k_i, pubKey)` for all
/// active fields, where each field uses a *distinct* scalar chained through
/// SHA-256: `k_0 = H(k)`, `k_{i+1} = H(k_i)` with `H(x) = sha256(x_be32) mod r`.
/// This matches davinci-node `Ballot.Reencrypt`/`EncryptedZero`, which advances
/// the offset scalar once per field. `k` is the raw re-encryption seed.
/// Padded fields `i >= num_fields` carry the TE identity on both sides and are
/// asserted (cheap field compares) rather than re-encrypted, so their per-field
/// scalar mults are skipped entirely.
/// `pk_table` is the fixed-base window table for the (already
/// curve-validated) ElGamal public key; B8 uses the compile-time table.
fn verify_reencryption(
    k: &FrRaw,
    pk_table: &BjjFixedBase,
    num_fields: usize,
    original: &[BjjCiphertext],
    reencrypted: &[BjjCiphertext],
) -> bool {
    if original.len() != reencrypted.len() {
        return false;
    }

    // Per-field offset scalar, chained through SHA-256. k_0 = H(k).
    let mut k_i = sha256_to_scalar(k);

    // For each active field: delta1_i = k_i * B8, delta2_i = k_i * pubKey, then
    // newC1 = origC1 + delta1_i, newC2 = origC2 + delta2_i. Advance k_i once
    // per field.
    for i in 0..original.len() {
        if i >= num_fields {
            // Padded slot: assert identity on both sides, skip EC work.
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
        let delta1 = b8_mul(&k_i);
        let delta2 = pk_table.mul(&k_i);

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

        // Advance the offset scalar for the next field.
        k_i = sha256_to_scalar(&k_i);
    }
    true
}

/// Verify all re-encryption entries from the ParsedInput REENCBLK.
/// Returns true if all are valid (or if the block is absent).
/// The public key is curve-checked once and its fixed-base window table
/// built once, shared by all entries; B8 uses the compile-time table.
pub fn verify_batch_from_parsed(
    reenc_pub_key: &Option<(FrRaw, FrRaw)>,
    reenc_entries: &[ReencEntry],
    num_fields: usize,
    fail_mask: &mut u32,
) -> bool {
    let (pub_key_x, pub_key_y) = match reenc_pub_key {
        None => {
            *fail_mask |= crate::types::FAIL_MISSING_BLOCK;
            return false;
        }
        Some(pk) => pk,
    };
    // No entries: nothing to re-encrypt, so skip the fixed-base table build.
    if reenc_entries.is_empty() {
        return true;
    }
    if !is_on_bjj_curve(pub_key_x, pub_key_y) {
        *fail_mask |= FAIL_REENC;
        return false;
    }
    let expected_muls = reenc_entries.len() * num_fields;
    let pk_table = BjjFixedBase::new(pub_key_x, pub_key_y, expected_muls);
    for entry in reenc_entries {
        if !verify_reencryption(
            &entry.k,
            &pk_table,
            num_fields,
            &entry.original,
            &entry.reencrypted,
        ) {
            *fail_mask |= FAIL_REENC;
            return false;
        }
    }
    true
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
