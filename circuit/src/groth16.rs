//! Groth16 batch verification with the random linear combination computed in-guest.
//!
//! # Algorithm
//!
//! Given `n` proofs `(A_i, B_i, C_i)` with public inputs `pubs_i` (derived
//! in-guest, see `publics.rs`) and a verification key `vk`, the batch check
//! reduces to a single multi-pairing equation:
//!
//! ```text
//! e(-(Σrᵢ)·α, β) · e(-Σrᵢ·Lᵢ, γ) · e(-Σrᵢ·Cᵢ, δ) · Π e(rᵢ·Aᵢ, Bᵢ) = GT_ONE
//! ```
//!
//! where `Lᵢ = γ_abc[0] + Σⱼ pubsᵢⱼ·γ_abc[j+1]` and the `rᵢ` are independent
//! 128-bit Fiat-Shamir coefficients derived in-guest from SHA-256 of the full
//! proof transcript (`r₀ = 1`), which covers every proof and all 71 of its
//! public inputs.
//!
//! # Cost model
//!
//! - The γ-side term is aggregated across proofs instead of building each `Lᵢ`:
//!   `Σᵢ rᵢ·Lᵢ = (Σᵢrᵢ)·γ_abc[0] + Σⱼ (Σᵢ rᵢ·pubsᵢⱼ)·γ_abc[j+1]`. The inner
//!   sums are Fr muladds (one arith256_mod row each).
//! - Inputs that are the same for every proof (process id, ballot mode, the
//!   encryption key, and the identity coordinates of padded fields) are folded
//!   once per batch into
//!   `IC₀' = γ_abc[0] + Σ_{j=2..5} cⱼ·γ_abc[j+1] + Σ_{f ≥ num_fields} (γ_abc[9+4f] + γ_abc[11+4f])`
//!   (the identity is `(0, 1)`: x terms vanish, y terms are 1), so
//!   `Σᵢ rᵢ·Lᵢ = (Σᵢrᵢ)·IC₀' + Σ_{j varying} (Σᵢ rᵢ·pubsᵢⱼ)·γ_abc[j+1]` over
//!   the address, vote id, weight and the `4·num_fields` live coordinates: a
//!   batch pays `8 + 4·num_fields` scalar muls on the γ side. Pure algebra:
//!   the point is identical.
//! - The coefficients are independent 128-bit values rather than 254-bit powers
//!   `r_shiftⁱ`. `scalar_mul_bn254` starts its double-and-add at the scalar's
//!   MSB, so the per-proof `rᵢ·Aᵢ` and `rᵢ·Cᵢ` muls cost half. With every
//!   point canonical and in its group, the small-exponents batch test
//!   (Bellare–Garay–Rabin) gives soundness error 2⁻¹²⁷ per Fiat-Shamir attempt
//!   (the all-zero coefficient maps to 1, which doubles that value's odds) —
//!   beyond BN254's own ~100-bit security.
//! - The transcript is hashed as it is produced (`Sha256Words`), never
//!   buffered (2.5 KB per proof).
//!
//! # Why the MSM is done in-guest
//!
//! The aggregated points (`scaled_a`, `neg_alpha_rsum`, `neg_g_ic`,
//! `neg_acc_c`) must not come from the host as hints: the pairing equation
//! does not validate them implicitly, because one GT equation cannot bind n+3
//! free G1 points. A malicious host could pick `Bᵢ = cᵢ·β` and
//! `scaled_a[i] = sᵢ·G1`, set `neg_alpha_rsum = -(Σ sᵢ·cᵢ)·G1` and zero out the
//! γ/δ terms, satisfying the equation for arbitrary forged proofs. The guest
//! computes every scalar multiplication itself, so the equation binds the actual
//! proof points, public inputs and VK to the in-guest challenge.

use crate::bn254::{g1_identity, g1_is_valid, g2_is_valid, gt_eq, gt_one};
use crate::bn254_fr;
use crate::hash::{sha256_once, Sha256Words};
use crate::io::ParsedInput;
use crate::publics::{Publics, PUB_ADDRESS, PUB_CONSTANTS, PUB_FIELDS, PUB_VOTE_ID, PUB_WEIGHT};
use crate::types::*;
use ziskos::zisklib::{add_bn254, neg_bn254, pairing_batch_bn254, scalar_mul_bn254};

/// Transcript domain tag, `b"groth16-batch-v3"` as two LE words.
const TRANSCRIPT_TAG: [u64; 2] = [
    u64::from_le_bytes(*b"groth16-"),
    u64::from_le_bytes(*b"batch-v3"),
];

/// The i-th batch coefficient: `r₀ = 1`, `rᵢ = lo128(SHA256(digest ‖ i))`.
///
/// 128-bit values are trivially canonical Fr elements, so no reduction retry
/// loop is needed. The 2⁻¹²⁸ all-zero case maps to 1 (a zero coefficient would
/// leave that proof unverified).
fn batch_coeff(digest: &[u8; 32], i: usize) -> FrRaw {
    if i == 0 {
        return [1, 0, 0, 0];
    }
    let mut buf = [0u8; 40];
    buf[..32].copy_from_slice(digest);
    buf[32..].copy_from_slice(&(i as u64).to_le_bytes());
    let d = sha256_once(&buf);
    let lo = u64::from_le_bytes(d[0..8].try_into().unwrap());
    let hi = u64::from_le_bytes(d[8..16].try_into().unwrap());
    if lo == 0 && hi == 0 {
        return [1, 0, 0, 0];
    }
    [lo, hi, 0, 0]
}

/// `a + b` with 𝒪 handled: `add_bn254` needs non-𝒪 inputs (it handles `a = ±b`).
fn g1_add(a: &G1, b: &G1) -> G1 {
    if *a == g1_identity() {
        *b
    } else if *b == g1_identity() {
        *a
    } else {
        add_bn254(a, b)
    }
}

/// `acc += k·p` for a non-𝒪 `p`; `0·p = 𝒪` is skipped.
fn g1_add_mul(acc: &mut G1, p: &G1, k: &FrRaw) {
    if *k != ZERO_FR {
        *acc = g1_add(acc, &scalar_mul_bn254(p, k));
    }
}

/// Verify a Groth16 batch against the derived public inputs. Returns `true`
/// if the batch passes. `publics` is `None` when the derivation failed
/// (`FAIL_BINDING` is already set).
///
/// # Fail-mask bits
/// - `FAIL_CURVE` (bit 1): a canonical-encoding, curve or subgroup check
///   failed on a VK or proof point, or the VK has `delta == gamma` (no
///   phase-2 contribution)
/// - `FAIL_PAIRING` (bit 2): the batch pairing equation did not hold
pub fn verify_batch(parsed: &ParsedInput, publics: Option<&Publics>, fail_mask: &mut u32) -> bool {
    // Skip expensive work if we already know the input is malformed.
    if *fail_mask & FAIL_PARSE != 0 {
        return false;
    }
    let Some(publics) = publics else {
        return false;
    };

    // --- Validate curve points ---
    // Before the transcript and before any curve operation, every VK and
    // proof point must have canonical coordinates (< q), be on its curve and
    // not be the identity; G2 points (β, γ, δ and every proof's B) must also
    // be in the prime-order subgroup. The transcript hashes raw limbs, so a
    // non-canonical coordinate would be a second encoding of the same proof;
    // and the random coefficients scale the G1 slot of each pairing, which
    // is sound only for B in G2 (r₀ = 1 then needs no randomisation).
    let mut points_ok = true;
    points_ok &= g1_is_valid(&parsed.vk_alpha_g1);
    points_ok &= g2_is_valid(&parsed.vk_beta_g2);
    points_ok &= g2_is_valid(&parsed.vk_gamma_g2);
    points_ok &= g2_is_valid(&parsed.vk_delta_g2);
    for p in &parsed.vk_gamma_abc {
        points_ok &= g1_is_valid(p);
    }
    for i in 0..parsed.nproofs {
        points_ok &= g1_is_valid(&parsed.proofs[i].a);
        points_ok &= g2_is_valid(&parsed.proofs[i].b);
        points_ok &= g1_is_valid(&parsed.proofs[i].c);
    }
    // A VK whose delta equals gamma has no phase-2 contribution: anyone who
    // knows the phase-1 transcript can forge proofs under it.
    if !points_ok || parsed.vk_delta_g2 == parsed.vk_gamma_g2 {
        *fail_mask |= FAIL_CURVE;
        return false;
    }
    // io.rs flags FAIL_PARSE unless gamma_abc has N_PUBLIC + 1 points.
    let ic = &parsed.vk_gamma_abc;

    // --- Fiat-Shamir transcript → per-proof coefficients ---
    //
    // "groth16-batch-v3" ‖ (A ‖ B ‖ C ‖ pubs[71]) per proof, as LE words.
    // Each coefficient is then one 40-byte SHA-256 of (digest ‖ index).
    let nproofs = parsed.nproofs;
    let mut transcript = Sha256Words::new();
    transcript.push_all(&TRANSCRIPT_TAG);
    for i in 0..nproofs {
        let proof = &parsed.proofs[i];
        transcript.push_all(&proof.a);
        transcript.push_all(&proof.b);
        transcript.push_all(&proof.c);
        for x in publics.proof(i).iter() {
            transcript.push_all(x);
        }
    }
    let digest = transcript.finish();

    // --- In-guest random linear combination ---
    //
    // Every scaled point is computed here in the guest; nothing proof-related
    // is taken on trust from the host. Only the inputs that vary per proof
    // get an Fr accumulator; the batch constants ride on IC₀'.
    let live_end = PUB_FIELDS + 4 * publics.num_fields;
    let mut r_sum = ZERO_FR;
    let mut acc_c = g1_identity(); // Σ rᵢ·Cᵢ
    let mut coeffs = [ZERO_FR; N_PUBLIC]; // Σᵢ rᵢ·pubsᵢⱼ for the varying j
    let mut eq_g1 = Vec::<G1>::with_capacity(3 + nproofs);
    let mut eq_g2 = Vec::<G2>::with_capacity(3 + nproofs);

    for i in 0..nproofs {
        let proof = &parsed.proofs[i];
        let r_i = batch_coeff(&digest, i);

        // rᵢ·Aᵢ pairs with Bᵢ.
        eq_g1.push(scalar_mul_bn254(&proof.a, &r_i));
        eq_g2.push(proof.b);

        // acc_c += rᵢ·Cᵢ  (0 < rᵢ < r and Cᵢ ≠ 𝒪 on the cofactor-1 G1, so
        // terms are never 𝒪; a 2⁻²⁵⁴ Fiat-Shamir cancellation is handled by
        // the identity branch)
        acc_c = g1_add(&acc_c, &scalar_mul_bn254(&proof.c, &r_i));

        let pubs = publics.proof(i);
        for j in [PUB_ADDRESS, PUB_VOTE_ID, PUB_WEIGHT].into_iter().chain(PUB_FIELDS..live_end) {
            coeffs[j] = bn254_fr::muladd(&pubs[j], &r_i, &coeffs[j]);
        }
        r_sum = bn254_fr::add(&r_sum, &r_i);
    }

    // IC₀' = γ_abc[0] + Σ_{j=2..5} cⱼ·γ_abc[j+1] + Σ_{f ≥ nf} (γ_abc[9+4f] + γ_abc[11+4f]).
    let mut ic0 = ic[0];
    for (k, c) in publics.constants.iter().enumerate() {
        g1_add_mul(&mut ic0, &ic[PUB_CONSTANTS + k + 1], c);
    }
    for f in publics.num_fields..NUM_FIELDS {
        let c1y = PUB_FIELDS + 4 * f + 1;
        ic0 = g1_add(&ic0, &ic[c1y + 1]);
        ic0 = g1_add(&ic0, &ic[c1y + 3]);
    }

    // Σᵢ rᵢ·Lᵢ = (Σᵢrᵢ)·IC₀' + Σ_{j varying} coeffs[j]·γ_abc[j+1].
    // r_sum ∈ [1, n·2¹²⁸] is never 0 mod r.
    let mut g_ic_acc = g1_identity();
    if ic0 != g1_identity() {
        g_ic_acc = scalar_mul_bn254(&ic0, &r_sum);
    }
    for j in [PUB_ADDRESS, PUB_VOTE_ID, PUB_WEIGHT].into_iter().chain(PUB_FIELDS..live_end) {
        g1_add_mul(&mut g_ic_acc, &ic[j + 1], &coeffs[j]);
    }

    // VK-side aggregates, negated: e(-(Σrᵢ)α, β) · e(-ΣrᵢLᵢ, γ) · e(-ΣrᵢCᵢ, δ).
    // neg_bn254(𝒪) = 𝒪, and the pairing skips 𝒪 terms — correct semantics.
    eq_g1.push(neg_bn254(&scalar_mul_bn254(&parsed.vk_alpha_g1, &r_sum)));
    eq_g2.push(parsed.vk_beta_g2);
    eq_g1.push(neg_bn254(&g_ic_acc));
    eq_g2.push(parsed.vk_gamma_g2);
    eq_g1.push(neg_bn254(&acc_c));
    eq_g2.push(parsed.vk_delta_g2);

    let ok = gt_eq(&pairing_batch_bn254(&eq_g1, &eq_g2), &gt_one());
    if !ok {
        *fail_mask |= FAIL_PAIRING;
    }
    ok
}
