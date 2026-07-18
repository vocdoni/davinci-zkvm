//! Groth16 batch verification with the random linear combination computed in-guest.
//!
//! # Algorithm
//!
//! Given `n` proofs `(A_i, B_i, C_i, pubs_i)` and a verification key `vk`, the batch
//! check reduces to a single multi-pairing equation:
//!
//! ```text
//! e(-(Σrᵢ)·α, β) · e(-Σrᵢ·Lᵢ, γ) · e(-Σrᵢ·Cᵢ, δ) · Π e(rᵢ·Aᵢ, Bᵢ) = GT_ONE
//! ```
//!
//! where `Lᵢ = γ_abc[0] + Σⱼ pubsᵢⱼ·γ_abc[j+1]` and the `rᵢ` are independent
//! 128-bit Fiat-Shamir coefficients derived in-guest from SHA-256 of the full
//! proof transcript (`r₀ = 1`).
//!
//! # Cost model
//!
//! Two structural optimisations keep the in-guest MSM cheap without touching
//! soundness:
//!
//! - The γ-side term is aggregated across proofs instead of building each `Lᵢ`:
//!   `Σᵢ rᵢ·Lᵢ = (Σᵢrᵢ)·γ_abc[0] + Σⱼ (Σᵢ rᵢ·pubsᵢⱼ)·γ_abc[j+1]`.
//!   The inner sums are Fr muladds (one arith256_mod row each), leaving only
//!   `n_public + 1` scalar muls for the whole batch instead of
//!   `n·(n_public + 1)`. This is pure algebra — the resulting point is
//!   identical.
//! - The coefficients are independent 128-bit values rather than 254-bit powers
//!   `r_shiftⁱ`. `scalar_mul_bn254` starts its double-and-add at the scalar's
//!   MSB, so the per-proof `rᵢ·Aᵢ` and `rᵢ·Cᵢ` muls cost half. The
//!   small-exponents batch test (Bellare–Garay–Rabin) gives soundness error
//!   2⁻¹²⁸ per Fiat-Shamir attempt — beyond BN254's own ~100-bit security.
//!
//! # Why the MSM is done in-guest
//!
//! A previous version let the host supply the aggregated points (`scaled_a`,
//! `neg_alpha_rsum`, `neg_g_ic`, `neg_acc_c`) as hints, on the theory that the
//! pairing equation "validates them implicitly". That is false: one GT equation
//! cannot bind n+3 free G1 points. A malicious host could pick `Bᵢ = cᵢ·β` and
//! `scaled_a[i] = sᵢ·G1`, set `neg_alpha_rsum = -(Σ sᵢ·cᵢ)·G1` and zero out the
//! γ/δ terms, satisfying the equation for arbitrary forged proofs. The guest now
//! computes every scalar multiplication itself, so the equation binds the actual
//! proof points, public inputs and VK to the in-guest challenge.

use crate::bn254::{g1_identity, g2_is_valid, gt_eq, gt_one};
use crate::bn254_fr;
use crate::hash::sha256_once;
use crate::io::ParsedInput;
use crate::types::*;
use ziskos::zisklib::{
    add_bn254, is_on_curve_bn254, is_on_curve_twist_bn254, neg_bn254, pairing_batch_bn254,
    scalar_mul_bn254,
};

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

/// Verify a Groth16 batch.  Returns `true` if the batch passes.
///
/// # Fail-mask bits
/// - `FAIL_CURVE` (bit 1): a curve/subgroup check failed on a VK or proof point
/// - `FAIL_PAIRING` (bit 2): the batch pairing equation did not hold
pub fn verify_batch(parsed: &ParsedInput, fail_mask: &mut u32) -> bool {
    // Skip expensive work if we already know the input is malformed.
    if *fail_mask & FAIL_PARSE != 0 {
        return false;
    }

    // --- Validate curve points ---
    // VK G1 points, gamma_abc and the proof A/C points must be strictly
    // on-curve (non-infinity): the in-guest scalar multiplication requires
    // non-zero points. VK G2 points additionally need the subgroup check.
    // Proof B is on-curve-only: subgroup soundness comes from the randomized
    // batch coefficients (the transcript commits to B before the coefficients
    // exist).
    let mut points_ok = true;
    points_ok &= is_on_curve_bn254(&parsed.vk_alpha_g1);
    points_ok &= g2_is_valid(&parsed.vk_beta_g2);
    points_ok &= g2_is_valid(&parsed.vk_gamma_g2);
    points_ok &= g2_is_valid(&parsed.vk_delta_g2);
    for p in &parsed.vk_gamma_abc {
        points_ok &= is_on_curve_bn254(p);
    }
    for i in 0..parsed.nproofs {
        points_ok &= is_on_curve_bn254(&parsed.proofs[i].a);
        points_ok &= is_on_curve_twist_bn254(&parsed.proofs[i].b);
        points_ok &= is_on_curve_bn254(&parsed.proofs[i].c);
    }
    if !points_ok {
        *fail_mask |= FAIL_CURVE;
        return false;
    }

    // --- Fiat-Shamir transcript → per-proof coefficients ---
    //
    // Pre-hash the full transcript to 32 bytes; each coefficient is then one
    // 40-byte SHA-256 of (digest ‖ index).
    let nproofs = parsed.nproofs;
    let n_public = parsed.n_public;
    let cap = 16 + nproofs * (64 + 128 + 64 + n_public * 32);
    let mut transcript = Vec::<u8>::with_capacity(cap);
    transcript.extend_from_slice(b"groth16-batch-v2");
    for i in 0..nproofs {
        for w in parsed.proofs[i].a.iter() {
            transcript.extend_from_slice(&w.to_le_bytes());
        }
        for w in parsed.proofs[i].b.iter() {
            transcript.extend_from_slice(&w.to_le_bytes());
        }
        for w in parsed.proofs[i].c.iter() {
            transcript.extend_from_slice(&w.to_le_bytes());
        }
        for j in 0..n_public {
            for w in parsed.proofs[i].public_inputs[j].iter() {
                transcript.extend_from_slice(&w.to_le_bytes());
            }
        }
    }
    let digest = sha256_once(&transcript);
    drop(transcript); // free ~36 KB before allocating pairing inputs

    // --- In-guest random linear combination ---
    //
    // Every scaled point is computed here in the guest; nothing proof-related
    // is taken on trust from the host. The γ-side pub scalars are accumulated
    // in Fr and applied to γ_abc once, after the loop (see module docs).
    let mut r_sum = ZERO_FR;
    let mut acc_c = g1_identity(); // Σ rᵢ·Cᵢ
    let mut pub_coeffs = vec![ZERO_FR; n_public]; // Σᵢ rᵢ·pubsᵢⱼ per j
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
        let rc = scalar_mul_bn254(&proof.c, &r_i);
        acc_c = if acc_c == g1_identity() {
            rc
        } else {
            add_bn254(&acc_c, &rc)
        };

        // muladd reduces mod r, so raw (non-canonical) pubs contribute their
        // residue — same semantics scalar_mul_bn254 would give them.
        for (j, coeff) in pub_coeffs.iter_mut().enumerate() {
            *coeff = bn254_fr::muladd(&proof.public_inputs[j], &r_i, coeff);
        }
        r_sum = bn254_fr::add(&r_sum, &r_i);
    }

    // Σᵢ rᵢ·Lᵢ = (Σᵢrᵢ)·γ_abc[0] + Σⱼ pub_coeffs[j]·γ_abc[j+1].
    // r_sum ∈ [1, n·2¹²⁸] is never 0 mod r, so the first term is non-𝒪.
    let mut g_ic_acc = scalar_mul_bn254(&parsed.vk_gamma_abc[0], &r_sum);
    for j in 0..n_public {
        if pub_coeffs[j] == ZERO_FR {
            continue; // 0·P = 𝒪; add_bn254 needs non-𝒪
        }
        let t = scalar_mul_bn254(&parsed.vk_gamma_abc[j + 1], &pub_coeffs[j]);
        g_ic_acc = if g_ic_acc == g1_identity() {
            t
        } else {
            add_bn254(&g_ic_acc, &t)
        };
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
