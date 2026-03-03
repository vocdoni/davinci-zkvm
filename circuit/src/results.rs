//! Result accumulator and ballot leaf hash verification.
//!
//! Implements the homomorphic ballot tally check from the DAVINCI protocol:
//!   NewResultsAdd = OldResultsAdd + Σ(all voter ballots)
//!   NewResultsSub = OldResultsSub + Σ(overwritten ballots)
//!
//! Each ballot is 32 BN254 Fr field elements (8 ElGamal ciphertexts × 4 coordinates).
//! Addition is performed element-wise using the `bn254_fr::add` precompile.
//!
//! Additionally verifies that each ballot SMT leaf value equals SHA-256 of the
//! serialized ballot data, binding the re-encrypted ballot to the state tree.

use crate::bn254_fr;
use crate::hash;
use crate::types::{BallotData, FrRaw, StateBlock, ZERO_FR, FAIL_RESULT_ACCUM, FAIL_LEAF_HASH};

/// Number of Fr elements per ballot (8 ciphertexts × 4 coordinates).
const BALLOT_FIELDS: usize = 32;

/// Element-wise field addition of two ballots: out[i] = a[i] + b[i].
fn ballot_add(a: &BallotData, b: &BallotData) -> BallotData {
    let mut out = [ZERO_FR; BALLOT_FIELDS];
    for i in 0..BALLOT_FIELDS {
        out[i] = bn254_fr::add(&a[i], &b[i]);
    }
    out
}

/// Serialize a ballot into bytes for hashing: each Fr element is written as 32 bytes
/// big-endian (matching arbo's SHA-256 leaf hash convention).
fn serialize_ballot(b: &BallotData) -> Vec<u8> {
    let mut buf = Vec::with_capacity(BALLOT_FIELDS * 32);
    for fr in b.iter() {
        // FrRaw is [u64; 4] LE limbs → convert to 32-byte big-endian
        let mut be = [0u8; 32];
        for (i, &limb) in fr.iter().enumerate() {
            let bytes = limb.to_be_bytes();
            // limb 0 (LS) → bytes[24..32], limb 3 (MS) → bytes[0..8]
            let dst = (3 - i) * 8;
            be[dst..dst + 8].copy_from_slice(&bytes);
        }
        buf.extend_from_slice(&be);
    }
    buf
}

/// Compute SHA-256 of the serialized ballot → FrRaw (LE limbs).
/// This hash should match the SMT leaf `new_value` for ballot insertions.
fn ballot_leaf_hash(b: &BallotData) -> FrRaw {
    let serialized = serialize_ballot(b);
    let digest = hash::sha256_once(&serialized);
    // Convert 32-byte hash (big-endian) to FrRaw [u64; 4] LE limbs (arbo convention)
    let mut fr = ZERO_FR;
    for i in 0..4 {
        let off = (3 - i) * 8;
        fr[i] = u64::from_be_bytes(digest[off..off + 8].try_into().unwrap());
    }
    fr
}

/// Verify the result accumulator and ballot leaf hashes.
/// Checks:
/// 1. **Ballot leaf hashes**: For each voter ballot in `voter_ballots`, verify that
///    `SHA256(serialize(ballot)) == ballot_chain[i].new_value`. This binds the
///    re-encrypted ballot data to the SMT leaf, preventing the prover from inserting
///    arbitrary leaf values.
/// 2. **ResultsAdd accumulation**: `NewResultsAdd = OldResultsAdd + Σ(voter_ballots)`.
///    The sum uses element-wise BN254 Fr addition (homomorphic under ElGamal).
///    The new value is verified against `results_add.new_value` in the SMT.
/// 3. **ResultsSub accumulation**: `NewResultsSub = OldResultsSub + Σ(overwritten_ballots)`.
///    Only overwritten (UPDATE) votes contribute to ResultsSub.
/// Returns `true` if all checks pass. Sets `FAIL_LEAF_HASH` or `FAIL_RESULT_ACCUM`
/// in `fail_mask` on failure.
pub fn verify_results(state: &StateBlock, fail_mask: &mut u32) -> bool {
    // When no voter ballots are provided and no voters exist, nothing to check.
    // When voters exist but ballot data is absent, that's a protocol violation.
    if state.voter_ballots.is_empty() && state.overwritten_ballots.is_empty() {
        if state.n_voters > 0 {
            *fail_mask |= FAIL_RESULT_ACCUM;
            return false;
        }
        return true;
    }

    let mut ok = true;

    // Ballot leaf hash verification
    // Each voter_ballots[i] must match ballot_chain[i].new_value via SHA-256.
    if state.voter_ballots.len() != state.ballot_chain.len() {
        *fail_mask |= FAIL_LEAF_HASH;
        return false;
    }
    for i in 0..state.voter_ballots.len() {
        let expected_hash = ballot_leaf_hash(&state.voter_ballots[i]);
        if expected_hash != state.ballot_chain[i].new_value {
            *fail_mask |= FAIL_LEAF_HASH;
            ok = false;
            break;
        }
    }

    // Overwritten ballot leaf hash verification
    // For UPDATE entries, the old_value must match the hash of the overwritten ballot.
    let update_indices: Vec<usize> = state.ballot_chain.iter()
        .enumerate()
        .filter(|(_, t)| !t.fnc0 && t.fnc1) // UPDATE = fnc0=false, fnc1=true
        .map(|(i, _)| i)
        .collect();

    if state.overwritten_ballots.len() != update_indices.len() {
        *fail_mask |= FAIL_LEAF_HASH;
        return false;
    }
    for (ob_idx, &chain_idx) in update_indices.iter().enumerate() {
        let expected_hash = ballot_leaf_hash(&state.overwritten_ballots[ob_idx]);
        if expected_hash != state.ballot_chain[chain_idx].old_value {
            *fail_mask |= FAIL_LEAF_HASH;
            ok = false;
            break;
        }
    }

    // ResultsAdd accumulation
    // NewResultsAdd = OldResultsAdd + Σ(all voter ballots)
    if let Some(ref r_add) = state.results_add {
        let mut sum = state.old_results_add;
        for vb in &state.voter_ballots {
            sum = ballot_add(&sum, vb);
        }
        let expected_new_hash = ballot_leaf_hash(&sum);
        if expected_new_hash != r_add.new_value {
            *fail_mask |= FAIL_RESULT_ACCUM;
            ok = false;
        }
        // Also verify old leaf hash matches OldResultsAdd
        let old_hash = ballot_leaf_hash(&state.old_results_add);
        if old_hash != r_add.old_value {
            *fail_mask |= FAIL_RESULT_ACCUM;
            ok = false;
        }
    } else if !state.voter_ballots.is_empty() {
        // ResultsAdd SMT transition is required when there are voter ballots
        *fail_mask |= FAIL_RESULT_ACCUM;
        ok = false;
    }

    // ResultsSub accumulation
    // NewResultsSub = OldResultsSub + Σ(overwritten ballots)
    if let Some(ref r_sub) = state.results_sub {
        let mut sum = state.old_results_sub;
        for ob in &state.overwritten_ballots {
            sum = ballot_add(&sum, ob);
        }
        let expected_new_hash = ballot_leaf_hash(&sum);
        if expected_new_hash != r_sub.new_value {
            *fail_mask |= FAIL_RESULT_ACCUM;
            ok = false;
        }
        let old_hash = ballot_leaf_hash(&state.old_results_sub);
        if old_hash != r_sub.old_value {
            *fail_mask |= FAIL_RESULT_ACCUM;
            ok = false;
        }
    } else if !state.overwritten_ballots.is_empty() {
        // ResultsSub SMT transition is required when there are overwritten ballots
        *fail_mask |= FAIL_RESULT_ACCUM;
        ok = false;
    }

    ok
}
