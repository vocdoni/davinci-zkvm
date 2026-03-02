//! KZG EIP-4844 blob barycentric evaluation verifier.
//!
//! Verifies that `Y = P(Z)`, where `P` is the polynomial encoding the blob data
//! and `(Z, Y)` is a claimed evaluation point over the BLS12-381 scalar field Fr.
//!
//! **What is verified:** `Y = barycentric_eval(blob, Z)`.
//! The KZG commitment/opening proof is NOT verified here (that would require
//! BLS12-381 pairings, not yet available as a ZisK precompile).  This is
//! consistent with the Gnark `VerifyBarycentricEvaluation` circuit.
//!
//! **Evaluation point Z** is derived deterministically:
//!   `Z = SHA-256(processID_be32 ‖ rootHashBefore_be32 ‖ commitment_48bytes) mod p_bls`
//!
//! Using SHA-256 (hardware-accelerated via ZisK precompile) instead of Poseidon
//! keeps proving cost low while domain-separating Z from the blob data.
//!
//! **Barycentric formula** (degree-4095 polynomial in evaluation form):
//!   `Y = (Z^N − 1) / N · Σᵢ ( dᵢ · ωᵢ / (Z − ωᵢ) )`
//!
//! `ωᵢ` are the 4096 EIP-4844 roots of unity in BLS12-381 Fr, in the
//! bit-reversed order used by go-ethereum / go-eth-kzg / davinci-node.
//!
//! # Performance
//!
//! All BLS12-381 Fr field multiplications use the ZisK `arith256_mod` precompile
//! via `crate::bls_fr`, replacing ~50 Fibonacci SM rows per multiplication with
//! 1 dedicated ArithMod row.  The hot path performs approximately:
//!   - 4115 multiplications in `gen_omega_table` (20 squarings + 4095 products)
//!   - 8190 multiplications in `batch_inverse` (prefix + back-substitution)
//!   - ~383 arith256_mod calls for the single `inv` inside `batch_inverse`
//!   - ~16000 field operations in the barycentric sum loop
//!
//! # Reference implementation
//! `davinci-node/crypto/blobs/barycentric.go` → `EvaluateBarycentricNative`

use crate::bls_fr::{self, BlsFrRaw, ONE, ZERO};
use crate::hash::sha256_once;
use crate::types::{FrRaw, KZGBlock, FAIL_KZG};

/// Number of cells in an EIP-4844 blob.
const N: usize = 4096;
/// log₂(N) used for the bit-reversal permutation and `Z^N` via 12 squarings.
const LOG_N: usize = 12;
/// N as a BLS12-381 Fr element (used for the `1/N` factor).
const N_FR: BlsFrRaw = [4096, 0, 0, 0];

// ─── Evaluation point ────────────────────────────────────────────────────────

/// Compute the KZG evaluation point `Z` from the process context.
///
/// `Z = SHA-256(processID_be32 ‖ rootHashBefore_be32 ‖ commitment_48bytes) mod p_bls`
///
/// The 32-byte SHA-256 digest is interpreted as a big-endian integer and reduced
/// modulo the BLS12-381 Fr modulus via `arith256_mod`.  The statistical bias is
/// at most 3 / p_bls ≈ 3 / 2^254.8, which is negligible.
pub fn compute_z(process_id: &FrRaw, root_hash_before: &FrRaw, commitment: &[u8; 48]) -> BlsFrRaw {
    let mut preimage = [0u8; 112]; // 32 (processID) + 32 (rootBefore) + 48 (commitment)

    // Encode BN254 FrRaw (4×u64 LE) as 32 big-endian bytes.
    for i in 0..4 {
        preimage[(3 - i) * 8..(4 - i) * 8].copy_from_slice(&process_id[i].to_be_bytes());
    }
    for i in 0..4 {
        preimage[32 + (3 - i) * 8..32 + (4 - i) * 8]
            .copy_from_slice(&root_hash_before[i].to_be_bytes());
    }
    preimage[64..112].copy_from_slice(commitment);

    let hash = sha256_once(&preimage);
    // Reduce mod p_bls (SHA-256 output may be ≥ p).
    bls_fr::from_be32_mod(&hash)
}

// ─── Omega table ─────────────────────────────────────────────────────────────

/// BLS12-381 Fr primitive root of unity with order 2^32 (used by go-eth-kzg).
///
/// Value: `10238227357739495823651030575849232062558860180284477541189508159991286009131`
/// Hex BE: `16a2a19edfe81f20d09b681922c813b4b63683508c2280b93829971f439f0d2b`
const ROU_BYTES: [u8; 32] = [
    0x16, 0xa2, 0xa1, 0x9e, 0xdf, 0xe8, 0x1f, 0x20,
    0xd0, 0x9b, 0x68, 0x19, 0x22, 0xc8, 0x13, 0xb4,
    0xb6, 0x36, 0x83, 0x50, 0x8c, 0x22, 0x80, 0xb9,
    0x38, 0x29, 0x97, 0x1f, 0x43, 0x9f, 0x0d, 0x2b,
];

/// Generate the 4096 EIP-4844 roots of unity in bit-reversed order.
///
/// All field arithmetic uses `arith256_mod` (20 squarings for generator
/// derivation + 4095 multiplications for the natural-order domain).
///
/// Matches `omegaHex[4096]` in `davinci-node/crypto/blobs/omega.go` and the
/// domain ordering used by `EvaluateBarycentricNative`.
fn gen_omega_table() -> [BlsFrRaw; N] {
    // rou is < p by construction (verified constant).
    let rou = bls_fr::from_be32_raw(&ROU_BYTES);

    // generator = rou^(2^20)  →  order = 4096 = 2^12
    let mut generator = rou;
    for _ in 0..20 {
        generator = bls_fr::sqr(&generator);
    }

    // Natural-order domain: domain[i] = generator^i
    let mut domain = [ZERO; N];
    domain[0] = ONE;
    for i in 1..N {
        domain[i] = bls_fr::mul(&domain[i - 1], &generator);
    }

    // Bit-reversal permutation (12-bit indices)
    let mut omega = [ZERO; N];
    for i in 0..N {
        omega[i] = domain[bit_reverse(i, LOG_N)];
    }
    omega
}

/// Reverse the low `log2n` bits of `n`.
#[inline(always)]
fn bit_reverse(n: usize, log2n: usize) -> usize {
    let mut rev = 0usize;
    let mut x = n;
    for _ in 0..log2n {
        rev = (rev << 1) | (x & 1);
        x >>= 1;
    }
    rev
}

// ─── Barycentric evaluation ───────────────────────────────────────────────────

/// Evaluate the blob polynomial at `z` using the barycentric formula.
///
/// `blob` is a flat byte slice of exactly `N × 32` bytes.  Cell `i` occupies
/// bytes `[i*32 .. (i+1)*32]` as a big-endian BLS12-381 Fr element, matching
/// the EIP-4844 / go-eth-kzg blob layout.
///
/// ## Formula
///   `Y = (z^N − 1) / N · Σᵢ ( dᵢ · ωᵢ / (z − ωᵢ) )`
///
/// ## Early exit
/// When `z = ωₖ` for some k, the formula degenerates and `blob[k]` is returned
/// directly (matching the optimisation in `EvaluateBarycentricNative`).
pub fn evaluate_barycentric(blob: &[u8], z: BlsFrRaw) -> BlsFrRaw {
    debug_assert_eq!(blob.len(), N * 32, "blob must be exactly 4096×32 bytes");

    let omega = gen_omega_table();

    // ── Early exit: z is a domain point ──────────────────────────────────────
    for (k, w) in omega.iter().enumerate() {
        if *w == z {
            let cell: &[u8; 32] = blob[k * 32..(k + 1) * 32].try_into().unwrap();
            return bls_fr::from_be32_raw(cell);
        }
    }

    // ── Differences: z − ωᵢ  (none is zero — guaranteed by early exit) ───────
    let diffs: [BlsFrRaw; N] = core::array::from_fn(|i| bls_fr::sub(&z, &omega[i]));

    // ── Batch inversion: 1/diff[i] for all i (1 inv + 2N muls) ──────────────
    let inv_diffs = batch_inverse(&diffs);

    // ── Barycentric sum: Σᵢ dᵢ · ωᵢ · (z − ωᵢ)⁻¹ ───────────────────────────
    let mut sum = ZERO;
    for i in 0..N {
        let cell: &[u8; 32] = blob[i * 32..(i + 1) * 32].try_into().unwrap();
        let d = bls_fr::from_be32_raw(cell);
        if d == ZERO {
            continue; // skip zero cells (common in sparse blobs)
        }
        // term = d · ω[i] · (z − ω[i])⁻¹
        let term = bls_fr::mul(&bls_fr::mul(&d, &omega[i]), &inv_diffs[i]);
        sum = bls_fr::add(&sum, &term);
    }

    // ── Factor: (z^N − 1) / N  (z^4096 via 12 squarings) ────────────────────
    let mut z_pow_n = z;
    for _ in 0..LOG_N {
        z_pow_n = bls_fr::sqr(&z_pow_n);
    }
    // (z^N − 1) / N = (z^N − 1) · N⁻¹
    let z_pow_n_minus_1 = bls_fr::sub(&z_pow_n, &ONE);
    let n_inv = bls_fr::inv(&N_FR);
    let factor = bls_fr::mul(&z_pow_n_minus_1, &n_inv);

    bls_fr::mul(&factor, &sum)
}

/// Montgomery batch inversion: `1/v[i]` for all `i`, using one field inversion.
///
/// Requires: every element of `v` is non-zero (guaranteed by the early exit above).
///
/// Complexity: `N` prefix multiplications + 1 Fermat inversion (~383 arith256_mod
/// calls) + `N` back-substitution multiplications = `2·N + 383` arith256_mod calls.
fn batch_inverse(v: &[BlsFrRaw; N]) -> [BlsFrRaw; N] {
    // Prefix products: prefix[i] = v[0] · v[1] · … · v[i]
    let mut prefix = [ZERO; N];
    prefix[0] = v[0];
    for i in 1..N {
        prefix[i] = bls_fr::mul(&prefix[i - 1], &v[i]);
    }

    // Single Fermat inversion of the full product
    let mut acc = bls_fr::inv(&prefix[N - 1]);

    // Back-substitute: acc tracks 1/(v[0]·…·v[i]) as i decreases
    let mut result = [ZERO; N];
    for i in (1..N).rev() {
        // result[i] = prefix[i-1] · acc = 1/v[i]
        result[i] = bls_fr::mul(&prefix[i - 1], &acc);
        // acc → 1/(v[0]·…·v[i-1])
        acc = bls_fr::mul(&acc, &v[i]);
    }
    result[0] = acc; // = 1/v[0]
    result
}

// ─── Block verification ───────────────────────────────────────────────────────

/// Verify the KZG blob barycentric evaluation block.
///
/// Returns `(ok, commitment)`:
/// - `ok = true`  when the block is absent (trivially pass) or `Y` is correct.
/// - `ok = false` on mismatch; sets `FAIL_KZG` in `fail_mask`.
/// - `commitment` is the 48-byte KZG commitment (zero-padded when absent).
pub fn verify_kzg(kzg: &Option<KZGBlock>, fail_mask: &mut u32) -> (bool, [u8; 48]) {
    let block = match kzg {
        None => return (true, [0u8; 48]),
        Some(b) => b,
    };

    let z = compute_z(&block.process_id, &block.root_hash_before, &block.commitment);
    let y_computed = evaluate_barycentric(&block.blob, z);
    let y_bytes = bls_fr::to_be32(&y_computed);

    let ok = y_bytes == block.y_claimed;
    if !ok {
        *fail_mask |= FAIL_KZG;
    }

    (ok, block.commitment)
}

/// Extract the three 128-bit commitment limbs from a 48-byte compressed G1 point.
///
/// Limb layout matches `types.KZGCommitment.ToLimbs()` in davinci-node:
///   `limb[0]` = commitment[0..16]  (most-significant 16 bytes)
///   `limb[1]` = commitment[16..32]
///   `limb[2]` = commitment[32..48]  (least-significant 16 bytes)
///
/// Each 128-bit limb is stored as 4 × u32 little-endian words.
pub fn commitment_to_limb_u32s(commitment: &[u8; 48]) -> [[u32; 4]; 3] {
    let mut limbs = [[0u32; 4]; 3];
    for (l, chunk) in commitment.chunks(16).enumerate() {
        let mut v: u128 = 0;
        for &b in chunk {
            v = (v << 8) | b as u128;
        }
        limbs[l][0] = (v & 0xFFFF_FFFF) as u32;
        limbs[l][1] = ((v >> 32) & 0xFFFF_FFFF) as u32;
        limbs[l][2] = ((v >> 64) & 0xFFFF_FFFF) as u32;
        limbs[l][3] = ((v >> 96) & 0xFFFF_FFFF) as u32;
    }
    limbs
}
