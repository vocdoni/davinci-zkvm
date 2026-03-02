#![no_main]
ziskos::entrypoint!(main);

mod babyjubjub;
mod bls_fr;
mod bn254;
mod bn254_fr;
mod census;
mod consistency;
mod ecdsa;
mod groth16;
mod hash;
mod io;
mod kzg;
mod poseidon;
mod smt;
mod types;

use crate::types::{FrRaw, ZERO_FR};
use ziskos::{read_input_slice, set_output};

// ─── Output register layout ─────────────────────────────────────────────────
//
// Indices 0-1: circuit status
//   [0]  overall_ok            — 1 = all checks passed, 0 = at least one failed
//   [1]  fail_mask             — per-check failure bits (see types.rs FAIL_* constants)
//
// Indices 2-27: public inputs mirroring the davinci-node StateTransitionCircuit
//   [2..9]   RootHashBefore    — 256-bit Arbo SHA-256 root BEFORE batch (8 × u32, LE)
//   [10..17] RootHashAfter     — 256-bit Arbo SHA-256 root AFTER  batch (8 × u32, LE)
//   [18]     VotersCount       — number of real (non-dummy) votes in the batch
//   [19]     OverwrittenVotesCount — number of ballots that replaced an existing vote
//   [20..27] CensusRoot        — 256-bit lean-IMT Poseidon census root (8 × u32, LE)
//
// Indices 28-39: BlobCommitmentLimbs (3 × 128-bit, 12 × u32)
//   Populated from the KZG commitment when a KZGBLK block is present, zero otherwise.
//   [28..31] BlobCommitment limb 0 (128 bits)
//   [32..35] BlobCommitment limb 1 (128 bits)
//   [36..39] BlobCommitment limb 2 (128 bits)
//
// Indices 40-45: diagnostic / auxiliary outputs
//   [40] batch_ok    — Groth16 batch verification result
//   [41] ecdsa_ok    — ECDSA signature batch result
//   [42] smt_ok      — legacy SMTBLK batch (1=ok, 2=absent, 0=fail)
//   [43] nproofs     — number of Groth16 proofs verified
//   [44] n_public    — number of public inputs per proof
//   [45] log_n       — log₂ of the aggregation tree depth

/// Emit a 256-bit `FrRaw` (4 × u64 LE words) as 8 consecutive u32 output registers
/// starting at `base`.  Each u64 word is split into lo (bits 0-31) and hi (bits 32-63).
#[inline(always)]
fn set_fr_output(base: usize, v: &FrRaw) {
    for i in 0..4 {
        set_output(base + i * 2,     (v[i] & 0xFFFF_FFFF) as u32);
        set_output(base + i * 2 + 1, (v[i] >> 32) as u32);
    }
}

fn main() {
    let input = read_input_slice();
    let mut fail_mask: u32 = 0;

    let parsed       = io::parse_input(&input, &mut fail_mask);
    let batch_ok     = groth16::verify_batch(&parsed, &mut fail_mask);
    let ecdsa_ok     = ecdsa::verify_batch(&parsed, &mut fail_mask);
    let smt_ok       = smt::verify_batch(&parsed, &mut fail_mask);

    // State-transition block verification (STATETX).
    let (state_ok, old_root, new_root, voters, overwritten) =
        smt::verify_state(&parsed, &mut fail_mask);

    // Consistency: voteID + ballot namespace and binding checks.
    let consistency_ok = consistency::verify_consistency(&parsed, &mut fail_mask);

    // Census lean-IMT Poseidon proof verification.
    let census_ok = census::verify_batch(&parsed, &mut fail_mask);

    // Re-encryption verification (BabyJubJub ElGamal).
    let reenc_ok = babyjubjub::verify_batch_from_parsed(
        &parsed.reenc_pub_key,
        &parsed.reenc_entries,
        &mut fail_mask,
    );

    // KZG blob barycentric evaluation (KZGBLK!! magic). Absent = trivially pass.
    let (kzg_ok, kzg_commitment) = kzg::verify_kzg(&parsed.kzg, &mut fail_mask);

    // overall_ok: all mandatory verifications pass.
    // smt_ok semantics: 1 = valid, 0 = invalid, 2 = absent (legacy SMTBLK not provided).
    // The legacy SMTBLK and the full STATETX block are independent; absence of SMTBLK
    // is normal when using STATETX. state_ok covers STATETX validity.
    let overall_ok = fail_mask == 0
        && batch_ok
        && ecdsa_ok
        && (smt_ok == 1 || smt_ok == 2)
        && state_ok
        && consistency_ok
        && census_ok
        && reenc_ok
        && kzg_ok;

    // Extract census root: all proofs use the same root (validated in census.rs).
    let census_root: FrRaw = parsed.census_proofs
        .first()
        .map(|cp| cp.root)
        .unwrap_or(ZERO_FR);

    // ── Status ──────────────────────────────────────────────────────────────
    set_output(0, overall_ok as u32);
    set_output(1, fail_mask);

    // ── Public inputs (davinci-node StateTransitionCircuit) ─────────────────
    set_fr_output( 2, &old_root);      // RootHashBefore
    set_fr_output(10, &new_root);      // RootHashAfter
    set_output(18, voters as u32);     // VotersCount
    set_output(19, overwritten as u32);// OverwrittenVotesCount
    set_fr_output(20, &census_root);   // CensusRoot

    // BlobCommitmentLimbs: populated from KZG commitment when present, zero otherwise.
    // Each 128-bit limb is stored as 4 × u32 LE (slots 28-31, 32-35, 36-39).
    let limb_u32s = kzg::commitment_to_limb_u32s(&kzg_commitment);
    for (l, limb) in limb_u32s.iter().enumerate() {
        for (w, &word) in limb.iter().enumerate() {
            set_output(28 + l * 4 + w, word);
        }
    }

    // ── Diagnostics ─────────────────────────────────────────────────────────
    set_output(40, batch_ok as u32);
    set_output(41, ecdsa_ok as u32);
    set_output(42, smt_ok);
    set_output(43, parsed.nproofs as u32);
    set_output(44, parsed.n_public as u32);
    set_output(45, parsed.log_n as u32);
}
