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
//! where `Lᵢ = γ_abc[0] + Σⱼ pubsᵢⱼ·γ_abc[j+1]` and `rᵢ = r_shiftⁱ`, with `r_shift`
//! a Fiat-Shamir challenge derived in-guest from SHA-256 of the full proof transcript.
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
    add_bn254, is_on_curve_bn254, is_on_curve_twist_bn254,
    neg_bn254, pairing_batch_bn254, scalar_mul_bn254,
};

/// Derive a non-zero BN254 scalar field challenge from a 32-byte digest.
///
/// Uses a double-SHA-256 wide-reduction loop.  Stack-allocated 41-byte buffers
/// avoid heap allocation in the retry path.  Loops until a non-zero invertible
/// value is found (statistically immediate for random digests).
fn challenge_fr(digest: &[u8; 32]) -> Option<FrRaw> {
    let mut counter = 0u64;
    loop {
        let mut buf0 = [0u8; 41];
        buf0[..32].copy_from_slice(digest);
        buf0[32..40].copy_from_slice(&counter.to_be_bytes());
        buf0[40] = 0;
        let d0 = sha256_once(&buf0);

        // BN254 Fr has 254-bit modulus: only 32 bytes needed for Fiat-Shamir.
        if let Some(v) = bn254_fr::from_random_bytes_32(&d0) {
            return Some(v);
        }
        counter = counter.wrapping_add(1);
    }
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
    // batch coefficients (the transcript commits to B before r_shift exists).
    let mut points_ok = true;
    points_ok &= is_on_curve_bn254(&parsed.vk_alpha_g1);
    points_ok &= g2_is_valid(&parsed.vk_beta_g2);
    points_ok &= g2_is_valid(&parsed.vk_gamma_g2);
    points_ok &= g2_is_valid(&parsed.vk_delta_g2);
    for p in &parsed.vk_gamma_abc { points_ok &= is_on_curve_bn254(p); }
    for i in 0..parsed.nproofs {
        points_ok &= is_on_curve_bn254(&parsed.proofs[i].a);
        points_ok &= is_on_curve_twist_bn254(&parsed.proofs[i].b);
        points_ok &= is_on_curve_bn254(&parsed.proofs[i].c);
    }
    if !points_ok {
        *fail_mask |= FAIL_CURVE;
        return false;
    }

    // --- Fiat-Shamir transcript → challenge r_shift ---
    //
    // Pre-hash the full transcript to 32 bytes before calling challenge_fr.
    // This halves SHA-256 AIR rows and avoids large heap clones in
    // challenge_fr's retry loop.
    let nproofs  = parsed.nproofs;
    let n_public = parsed.n_public;
    let cap = 16 + nproofs * (64 + 128 + 64 + n_public * 32);
    let mut transcript = Vec::<u8>::with_capacity(cap);
    transcript.extend_from_slice(b"groth16-batch-v1");
    for i in 0..nproofs {
        for w in parsed.proofs[i].a.iter()         { transcript.extend_from_slice(&w.to_le_bytes()); }
        for w in parsed.proofs[i].b.iter()         { transcript.extend_from_slice(&w.to_le_bytes()); }
        for w in parsed.proofs[i].c.iter()         { transcript.extend_from_slice(&w.to_le_bytes()); }
        for j in 0..n_public {
            for w in parsed.proofs[i].public_inputs[j].iter() {
                transcript.extend_from_slice(&w.to_le_bytes());
            }
        }
    }
    let digest = sha256_once(&transcript);
    drop(transcript); // free ~36 KB before allocating pairing inputs

    let r_shift = match challenge_fr(&digest) {
        Some(r) if r != ZERO_FR => r,
        _ => { *fail_mask |= FAIL_PAIRING; return false; }
    };

    // --- In-guest random linear combination ---
    //
    // r_i = r_shift^i (r_0 = 1). Every scaled point is computed here in the
    // guest; nothing proof-related is taken on trust from the host.
    let mut r_i: FrRaw = [1, 0, 0, 0];
    let mut r_sum = ZERO_FR;
    let mut acc_c = g1_identity();   // Σ rᵢ·Cᵢ
    let mut g_ic_acc = g1_identity(); // Σ rᵢ·Lᵢ
    let mut eq_g1 = Vec::<G1>::with_capacity(3 + nproofs);
    let mut eq_g2 = Vec::<G2>::with_capacity(3 + nproofs);

    for i in 0..nproofs {
        let proof = &parsed.proofs[i];

        // rᵢ·Aᵢ pairs with Bᵢ.
        eq_g1.push(scalar_mul_bn254(&proof.a, &r_i));
        eq_g2.push(proof.b);

        // acc_c += rᵢ·Cᵢ  (rᵢ ≠ 0 and Cᵢ ≠ 𝒪, so terms are never 𝒪)
        let rc = scalar_mul_bn254(&proof.c, &r_i);
        acc_c = if acc_c == g1_identity() { rc } else { add_bn254(&acc_c, &rc) };

        // Lᵢ = γ_abc[0] + Σⱼ pubsᵢⱼ·γ_abc[j+1];  g_ic_acc += rᵢ·Lᵢ
        let mut l_i = parsed.vk_gamma_abc[0];
        for j in 0..n_public {
            let s = &proof.public_inputs[j];
            if *s == ZERO_FR { continue; } // 0·P = 𝒪; add_bn254 needs non-𝒪
            let t = scalar_mul_bn254(&parsed.vk_gamma_abc[j + 1], s);
            l_i = add_bn254(&l_i, &t);
        }
        let rg = scalar_mul_bn254(&l_i, &r_i);
        g_ic_acc = if g_ic_acc == g1_identity() { rg } else { add_bn254(&g_ic_acc, &rg) };

        r_sum = bn254_fr::add(&r_sum, &r_i);
        r_i = bn254_fr::mul(&r_i, &r_shift);
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
    if !ok { *fail_mask |= FAIL_PAIRING; }
    ok
}
