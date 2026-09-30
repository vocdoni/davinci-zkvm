//! Result accumulator and ballot leaf hash verification.
//!
//! Implements the homomorphic ballot tally check from the DAVINCI protocol,
//! a single net accumulator:
//!   NewResults = OldResults + Σ(voter ballots) − Σ(overwritten) + refresh delta
//!
//! Each ballot is 64 BN254 Fr field elements (16 ElGamal ciphertexts × 4 TE
//! coordinates). Both operations are homomorphic: BabyJubJub point addition
//! and subtraction (group inverse via `bjj_neg`) per ciphertext component,
//! matching davinci-node's `Ballot.Add` / `Ballot.Neg`, so the accumulator
//! stays a decryptable ElGamal ciphertext.
//!
//! Additionally verifies that each ballot SMT leaf value equals SHA-256 of the
//! serialized ballot data, binding the re-encrypted ballot to the state tree.

use crate::babyjubjub::BjjAccumulator;
use crate::bn254_fr::ONE;
use crate::hash;
use crate::types::{
    BallotData, FrRaw, StateBlock, BALLOT_FIELDS, FAIL_LEAF_HASH, FAIL_REFRESH, FAIL_RESULT_ACCUM,
    NUM_FIELDS, ZERO_FR,
};

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

/// Homomorphic net sum `init + Σ add_terms − Σ sub_terms + extra_add`, one
/// affine precompile add per term and coordinate pair. `extra_add` (the
/// refresh delta) is folded on active fields only; padded slots stay
/// identity, so passing the identity ballot disables it.
fn ballot_net(
    init: &BallotData,
    add_terms: &[BallotData],
    sub_terms: &[BallotData],
    extra_add: &BallotData,
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
    for (i, acc) in accs.iter_mut().enumerate() {
        acc.add(&(extra_add[i * 2], extra_add[i * 2 + 1]));
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
        if b[o] != ZERO_FR || b[o + 1] != ONE || b[o + 2] != ZERO_FR || b[o + 3] != ONE {
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
    use crate::babyjubjub::{bjj_add, bjj_generator, bjj_mul, bjj_neg, BjjAffine};

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
        let zero = zero_ballot();
        assert_eq!(
            ballot_net(&init, &add_terms, &sub_terms, &zero, NUM_FIELDS),
            expected
        );
    }

    /// x + p (non-canonical encoding of the same residue). x < p, so no carry-out.
    fn plus_modulus(x: &FrRaw) -> FrRaw {
        let m = crate::bn254_fr::BN254_FR_MOD;
        let mut out = [0u64; 4];
        let mut carry = 0u128;
        for i in 0..4 {
            let s = x[i] as u128 + m[i] as u128 + carry;
            out[i] = s as u64;
            carry = s >> 64;
        }
        out
    }

    fn empty_state() -> StateBlock {
        StateBlock {
            n_voters: 0,
            n_overwritten: 0,
            occupied_before: 0,
            process_id: ZERO_FR,
            old_state_root: ZERO_FR,
            new_state_root: ZERO_FR,
            vote_id_chain: Vec::new(),
            ballot_chain: Vec::new(),
            refresh_chain: Vec::new(),
            results: None,
            process_proofs: Vec::new(),
            n_levels: 0,
            old_results: zero_ballot(),
            voter_ballots: Vec::new(),
            overwritten_ballots: Vec::new(),
            refreshed_ballots: Vec::new(),
        }
    }

    fn mk_refresh_update(old_hash: FrRaw, new_hash: FrRaw) -> crate::types::SmtTransition {
        crate::types::SmtTransition {
            old_root: ZERO_FR,
            new_root: ZERO_FR,
            old_key: [0x10, 0, 0, 0],
            old_value: old_hash,
            is_old0: false,
            new_key: [0x10, 0, 0, 0],
            new_value: new_hash,
            fnc0: false,
            fnc1: true,
            siblings: Vec::new(),
        }
    }

    #[test]
    fn refresh_length_mismatch_sets_fail_refresh() {
        // refresh_chain has one entry, refreshed_ballots has one, refreshed_new
        // is empty. The empty-branch guard does not fire (refreshed_ballots is
        // non-empty) so the length-agreement check runs and flags FAIL_REFRESH.
        let mut s = empty_state();
        s.refresh_chain.push(mk_refresh_update(ZERO_FR, ZERO_FR));
        s.refreshed_ballots.push(zero_ballot());
        let zero = zero_ballot();
        let mut m = 0u32;
        let (ok, _net) = verify_results(&s, NUM_FIELDS, &[], &zero, &mut m);
        assert!(!ok);
        assert!(m & FAIL_REFRESH != 0, "mask={:#x}", m);
    }

    #[test]
    fn refresh_new_leaf_hash_mismatch_sets_fail_refresh() {
        // One refresh entry, but new_hash on the SMT side is wrong.
        let mut s = empty_state();
        let old = zero_ballot();
        let new = zero_ballot(); // identity roundtrip; hash should be identical
        let old_hash = ballot_leaf_hash(&old);
        // Bad new_hash: hash of a different ballot.
        let mut different = zero_ballot();
        different[0] = [7, 0, 0, 0];
        different[1] = [11, 0, 0, 0];
        let wrong_new_hash = ballot_leaf_hash(&different);

        s.refresh_chain.push(mk_refresh_update(old_hash, wrong_new_hash));
        s.refreshed_ballots.push(old);
        // Force Results transition to be present so the empty-guard doesn't
        // short-circuit; keep leaf hash bytes coherent so only the refresh
        // new-hash check trips.
        let net_new = ballot_net(&s.old_results, &[], &[], &zero_ballot(), NUM_FIELDS);
        s.results = Some(crate::types::SmtTransition {
            old_root: ZERO_FR,
            new_root: ZERO_FR,
            old_key: [0x04, 0, 0, 0],
            old_value: ballot_leaf_hash(&s.old_results),
            is_old0: false,
            new_key: [0x04, 0, 0, 0],
            new_value: ballot_leaf_hash(&net_new),
            fnc0: false,
            fnc1: true,
            siblings: Vec::new(),
        });

        let zero = zero_ballot();
        let mut m = 0u32;
        let (ok, _net) = verify_results(&s, NUM_FIELDS, &[new], &zero, &mut m);
        assert!(!ok);
        assert!(m & FAIL_REFRESH != 0, "mask={:#x}", m);
    }

    #[test]
    fn refresh_chain_without_ballot_data_sets_fail_refresh() {
        // A refresh entry with no old ballot must not slip through the
        // empty-batch shortcut: it would be an unbound UPDATE of a ballot leaf.
        let mut s = empty_state();
        s.refresh_chain.push(mk_refresh_update(ZERO_FR, ZERO_FR));
        let zero = zero_ballot();
        let mut m = 0u32;
        let (ok, _net) = verify_results(&s, NUM_FIELDS, &[], &zero, &mut m);
        assert!(!ok);
        assert!(m & FAIL_REFRESH != 0, "mask={:#x}", m);
    }

    #[test]
    fn empty_batch_with_refresh_requires_results_transition() {
        // No voters, no overwrites, ONE refresh entry: results transition must
        // be present. Absent → FAIL_RESULT_ACCUM (via the else branch of
        // "if let Some(ref r) = state.results").
        let mut s = empty_state();
        let old = zero_ballot();
        let new = zero_ballot();
        s.refresh_chain.push(mk_refresh_update(ballot_leaf_hash(&old), ballot_leaf_hash(&new)));
        s.refreshed_ballots.push(old);
        s.results = None;
        let zero = zero_ballot();
        let mut m = 0u32;
        let (ok, _net) = verify_results(&s, NUM_FIELDS, &[new], &zero, &mut m);
        assert!(!ok);
        assert!(m & FAIL_RESULT_ACCUM != 0, "mask={:#x}", m);
    }

    #[test]
    fn ballot_net_tolerates_noncanonical_sub_terms() {
        // A stored ballot may carry non-canonical coords (x + p) — the SMT leaf
        // hash binds raw bytes, not residues. Subtraction of such an overwritten
        // ballot must treat the coord as its residue (x), not underflow.
        let g = bjj_generator();
        let p = bjj_mul(&g, &[42, 0, 0, 0]);
        let mut canonical = [ZERO_FR; BALLOT_FIELDS];
        canonical[0] = p.0;
        canonical[1] = p.1;
        // Same ballot with both point coords in non-canonical encoding.
        let mut noncanon = canonical;
        noncanon[0] = plus_modulus(&p.0);
        noncanon[1] = plus_modulus(&p.1);

        let init = zero_ballot();
        let zero = zero_ballot();
        let net_canon = ballot_net(&init, &[], &[canonical], &zero, NUM_FIELDS);
        let net_noncanon = ballot_net(&init, &[], &[noncanon], &zero, NUM_FIELDS);
        assert_eq!(net_canon, net_noncanon);
        // And the result must equal -p in the first ciphertext slot.
        let neg_p = bjj_neg(&p);
        assert_eq!(net_canon[0], neg_p.0);
        assert_eq!(net_canon[1], neg_p.1);
    }
}

pub fn verify_results(
    state: &StateBlock,
    num_fields: usize,
    refreshed_new: &[BallotData],
    refresh_delta: &BallotData,
    fail_mask: &mut u32,
) -> (bool, BallotData) {
    // Every refresh entry needs its old ballot and the guest-computed new
    // one, whatever else the batch carries: a refresh chain without ballot
    // data would be an unbound UPDATE of a ballot leaf. Checked before the
    // empty-batch shortcut below for that reason.
    if state.refreshed_ballots.len() != state.refresh_chain.len()
        || refreshed_new.len() != state.refreshed_ballots.len()
    {
        *fail_mask |= FAIL_REFRESH;
        return (false, state.old_results);
    }

    // 4.4.8': when there is nothing to accumulate (no votes, no overwrites,
    // no refreshes) the Results leaf must not change — otherwise a prover
    // could ship a valid SMT update of Results to an arbitrary value and
    // splice it into the new state root with no accumulation check binding it.
    if state.voter_ballots.is_empty()
        && state.overwritten_ballots.is_empty()
        && state.refreshed_ballots.is_empty()
    {
        if state.n_voters > 0 {
            *fail_mask |= FAIL_RESULT_ACCUM;
            return (false, state.old_results);
        }
        if state.results.is_some() {
            *fail_mask |= FAIL_RESULT_ACCUM;
            return (false, state.old_results);
        }
        return (true, state.old_results);
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
    // Padded slots of the refreshed olds must be TE identity too — the
    // refresh chain skips per-field EC work on them, so any residual data
    // would slip past the reencryption verify and the accumulator alike.
    for b in &state.refreshed_ballots {
        if !padded_is_identity(b, num_fields) {
            *fail_mask |= FAIL_REFRESH;
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
        return (false, state.old_results);
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
    let update_indices: Vec<usize> = state
        .ballot_chain
        .iter()
        .enumerate()
        .filter(|(_, t)| !t.fnc0 && t.fnc1) // UPDATE = fnc0=false, fnc1=true
        .map(|(i, _)| i)
        .collect();

    if state.overwritten_ballots.len() != update_indices.len() {
        *fail_mask |= FAIL_LEAF_HASH;
        return (false, state.old_results);
    }
    for (ob_idx, &chain_idx) in update_indices.iter().enumerate() {
        let expected_hash = ballot_leaf_hash(&state.overwritten_ballots[ob_idx]);
        if expected_hash != state.ballot_chain[chain_idx].old_value {
            *fail_mask |= FAIL_LEAF_HASH;
            ok = false;
            break;
        }
    }

    // 4.5.5 / 4.5.6 — refresh leaf hash checks. Each refresh entry is an
    // UPDATE with old_key == new_key; the ballot payload bytes change from
    // refreshed_old to refreshed_new, but the plaintext does not (the
    // re-encryption check has already tied `new = old + delta`).
    for j in 0..state.refreshed_ballots.len() {
        let old_hash = ballot_leaf_hash(&state.refreshed_ballots[j]);
        if old_hash != state.refresh_chain[j].old_value {
            *fail_mask |= FAIL_REFRESH;
            ok = false;
            break;
        }
        let new_hash = ballot_leaf_hash(&refreshed_new[j]);
        if new_hash != state.refresh_chain[j].new_value {
            *fail_mask |= FAIL_REFRESH;
            ok = false;
            break;
        }
    }

    // 4.4.5' Net Results accumulation with the refresh delta folded in.
    // NewResults = OldResults + Σ voter_ballots − Σ overwritten + Σ (new_j − old_j)
    // where the last sum is `refresh_delta`, already assembled active-field
    // by active-field in `verify_batch_from_parsed`.
    let net = ballot_net(
        &state.old_results,
        &state.voter_ballots,
        &state.overwritten_ballots,
        refresh_delta,
        num_fields,
    );
    if let Some(ref r) = state.results {
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

    (ok, net)
}
