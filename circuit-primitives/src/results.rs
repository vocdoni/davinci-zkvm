//! Result accumulator and ballot leaf hash verification.
//!
//! Implements the homomorphic ballot tally check from the DAVINCI protocol,
//! a single net accumulator:
//!   NewResults = OldResults + Σ(all voter ballots) − Σ(overwritten ballots)
//!
//! Each ballot is 32 BN254 Fr field elements (8 ElGamal ciphertexts × 4 TE
//! coordinates). Both operations are homomorphic: BabyJubJub point addition
//! and subtraction (group inverse via `bjj_neg`) per ciphertext component,
//! matching davinci-node's `Ballot.Add` / `Ballot.Neg`, so the accumulator
//! stays a decryptable ElGamal ciphertext.
//!
//! Additionally verifies that each ballot SMT leaf value equals SHA-256 of the
//! serialized ballot data, binding the re-encrypted ballot to the state tree.

use crate::babyjubjub::BjjAccumulator;
use crate::hash;
use crate::types::{BallotData, FrRaw, StateBlock, ZERO_FR, BALLOT_FIELDS, NUM_FIELDS, FAIL_RESULT_ACCUM, FAIL_LEAF_HASH};
use crate::bn254_fr::ONE;

/// The identity ballot: every point is the TE identity (0, 1). Matches
/// davinci-node `elgamal.NewBallot` and is the genesis Results leaf value.
pub fn zero_ballot() -> BallotData {
    let mut b = [ZERO_FR; BALLOT_FIELDS];
    let mut i = 1;
    while i < BALLOT_FIELDS {
        b[i] = ONE;
        i += 2;
    }
    b
}

/// Homomorphic net sum `init + Σ add_terms − Σ sub_terms` with the 16 point
/// accumulators kept projective across the whole chain: one field inversion
/// per coordinate pair total, instead of one per added/subtracted ballot.
fn ballot_net(
    init: &BallotData,
    add_terms: &[BallotData],
    sub_terms: &[BallotData],
    num_fields: usize,
) -> BallotData {
    let limit = num_fields * 2;
    let mut accs: Vec<BjjAccumulator> = (0..limit)
        .map(|i| BjjAccumulator::new(&(init[i * 2], init[i * 2 + 1])))
        .collect();
    for t in add_terms {
        for (i, acc) in accs.iter_mut().enumerate() {
            acc.add(&(t[i * 2], t[i * 2 + 1]));
        }
    }
    for t in sub_terms {
        for (i, acc) in accs.iter_mut().enumerate() {
            acc.sub(&(t[i * 2], t[i * 2 + 1]));
        }
    }
    let mut out = [ZERO_FR; BALLOT_FIELDS];
    for (i, acc) in accs.iter().enumerate() {
        let p = acc.finish();
        out[i * 2] = p.0;
        out[i * 2 + 1] = p.1;
    }
    // Padded accumulators: emit identity, skip all add/sub work.
    let mut i = limit;
    while i < BALLOT_FIELDS / 2 {
        out[i * 2] = ZERO_FR;
        out[i * 2 + 1] = ONE;
        i += 1;
    }
    out
}

// Padded ciphertext slots (index >= num_fields) must hold the identity
// point, else a prover could stash data in columns the accumulator skips.
fn padded_is_identity(b: &BallotData, num_fields: usize) -> bool {
    let mut f = num_fields;
    while f < NUM_FIELDS {
        let o = f * 4;
        if b[o] != ZERO_FR || b[o + 1] != ONE
            || b[o + 2] != ZERO_FR || b[o + 3] != ONE {
            return false;
        }
        f += 1;
    }
    true
}

/// Serialize a ballot into bytes for hashing: each Fr element is written as 32 bytes
/// big-endian (matching arbo's SHA-256 leaf hash convention).
pub fn serialize_ballot(b: &BallotData) -> Vec<u8> {
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
pub fn ballot_leaf_hash(b: &BallotData) -> FrRaw {
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
/// 2. **Net Results accumulation**: `NewResults = OldResults + Σ(voter_ballots)
///    − Σ(overwritten_ballots)`. Homomorphic add/sub on BabyJubJub.
///    The new value is verified against `results.new_value` in the SMT.
/// Returns `true` if all checks pass. Sets `FAIL_LEAF_HASH` or `FAIL_RESULT_ACCUM`
/// in `fail_mask` on failure.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::babyjubjub::{bjj_add, bjj_generator, bjj_mul, BjjAffine};

    #[test]
    fn ballot_net_matches_pairwise_ops() {
        // Build a few valid ballots out of small multiples of B8.
        let g = bjj_generator();
        let pt = |s: u64| -> BjjAffine { bjj_mul(&g, &[s, 0, 0, 0]) };
        let mk = |seed: u64| -> BallotData {
            let mut b = [ZERO_FR; BALLOT_FIELDS];
            for i in 0..BALLOT_FIELDS / 2 {
                let p = pt(seed + i as u64 + 1);
                b[i * 2] = p.0;
                b[i * 2 + 1] = p.1;
            }
            b
        };
        let init = zero_ballot();
        let add_terms = [mk(1), mk(100), mk(7777)];
        let sub_terms = [mk(100)];

        let mut expected = init;
        for t in &add_terms {
            for i in 0..BALLOT_FIELDS / 2 {
                let p = bjj_add(
                    &(expected[i * 2], expected[i * 2 + 1]),
                    &(t[i * 2], t[i * 2 + 1]),
                );
                expected[i * 2] = p.0;
                expected[i * 2 + 1] = p.1;
            }
        }
        for t in &sub_terms {
            for i in 0..BALLOT_FIELDS / 2 {
                let neg = crate::babyjubjub::bjj_neg(&(t[i * 2], t[i * 2 + 1]));
                let p = bjj_add(&(expected[i * 2], expected[i * 2 + 1]), &neg);
                expected[i * 2] = p.0;
                expected[i * 2 + 1] = p.1;
            }
        }
        assert_eq!(ballot_net(&init, &add_terms, &sub_terms, NUM_FIELDS), expected);
    }
}

pub fn verify_results(state: &StateBlock, num_fields: usize, fail_mask: &mut u32) -> bool {
    // When no voter ballots are provided and no voters exist, nothing to check.
    // When voters exist but ballot data is absent, that's a protocol violation.
    if state.voter_ballots.is_empty() && state.overwritten_ballots.is_empty() {
        if state.n_voters > 0 {
            *fail_mask |= FAIL_RESULT_ACCUM;
            return false;
        }
        // With no ballots there is nothing to accumulate, so the results
        // transition must be absent (the leaf must not change). Otherwise a
        // prover could supply a valid SMT update of the Results leaf to an
        // arbitrary value and chain it to the new state root, injecting a
        // forged tally without any accumulation check binding it.
        if state.results.is_some() {
            *fail_mask |= FAIL_RESULT_ACCUM;
            return false;
        }
        return true;
    }

    let mut ok = true;

    // Soundness guard: padded slots of every accumulated ballot and the old
    // results must be identity, since the accumulator skips them above.
    for b in &state.voter_ballots {
        if !padded_is_identity(b, num_fields) {
            *fail_mask |= FAIL_RESULT_ACCUM;
            ok = false;
            break;
        }
    }
    for b in &state.overwritten_ballots {
        if !padded_is_identity(b, num_fields) {
            *fail_mask |= FAIL_RESULT_ACCUM;
            ok = false;
            break;
        }
    }
    if !padded_is_identity(&state.old_results, num_fields) {
        *fail_mask |= FAIL_RESULT_ACCUM;
        ok = false;
    }

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

    // Net Results accumulation
    // NewResults = OldResults + Σ(all voter ballots) − Σ(overwritten ballots)
    if let Some(ref r) = state.results {
        let net = ballot_net(&state.old_results, &state.voter_ballots, &state.overwritten_ballots, num_fields);
        let expected_new_hash = ballot_leaf_hash(&net);
        if expected_new_hash != r.new_value {
            *fail_mask |= FAIL_RESULT_ACCUM;
            ok = false;
        }
        // Also verify old leaf hash matches OldResults
        let old_hash = ballot_leaf_hash(&state.old_results);
        if old_hash != r.old_value {
            *fail_mask |= FAIL_RESULT_ACCUM;
            ok = false;
        }
    } else {
        // The Results SMT transition is required when there are any ballots.
        *fail_mask |= FAIL_RESULT_ACCUM;
        ok = false;
    }

    ok
}
