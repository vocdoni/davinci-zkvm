//! Result accumulator and ballot leaf hash verification for ecgfp5 ballots.

use crate::ecgfp5_verify;
use crate::types::{FAIL_LEAF_HASH, FAIL_RESULT_ACCUM, StateBlock};

pub fn verify_results(state: &StateBlock, fail_mask: &mut u32) -> bool {
    if state.voter_ballots_g5.is_empty() && state.overwritten_ballots_g5.is_empty() {
        if state.n_voters > 0 {
            *fail_mask |= FAIL_RESULT_ACCUM;
            return false;
        }
        return true;
    }

    let mut ok = true;
    if state.voter_ballots_g5.len() != state.ballot_chain.len() {
        *fail_mask |= FAIL_LEAF_HASH;
        return false;
    }
    for i in 0..state.voter_ballots_g5.len() {
        let expected = ecgfp5_verify::ballot_leaf_hash(&state.voter_ballots_g5[i]);
        if expected != state.ballot_chain[i].new_value {
            *fail_mask |= FAIL_LEAF_HASH;
            ok = false;
            break;
        }
    }

    let update_indices: Vec<usize> = state
        .ballot_chain
        .iter()
        .enumerate()
        .filter(|(_, t)| !t.fnc0 && t.fnc1)
        .map(|(i, _)| i)
        .collect();
    if state.overwritten_ballots_g5.len() != update_indices.len() {
        *fail_mask |= FAIL_LEAF_HASH;
        return false;
    }
    for (ob_idx, &chain_idx) in update_indices.iter().enumerate() {
        let expected = ecgfp5_verify::ballot_leaf_hash(&state.overwritten_ballots_g5[ob_idx]);
        if expected != state.ballot_chain[chain_idx].old_value {
            *fail_mask |= FAIL_LEAF_HASH;
            ok = false;
            break;
        }
    }

    if let Some(ref r_add) = state.results_add {
        let Some(mut sum) = state.old_results_add_g5 else {
            *fail_mask |= FAIL_RESULT_ACCUM;
            return false;
        };
        for vb in &state.voter_ballots_g5 {
            let Some(next) = ecgfp5_verify::ballot_add(&sum, vb) else {
                *fail_mask |= FAIL_RESULT_ACCUM;
                return false;
            };
            sum = next;
        }
        if ecgfp5_verify::ballot_leaf_hash(&sum) != r_add.new_value {
            *fail_mask |= FAIL_RESULT_ACCUM;
            ok = false;
        }
        if ecgfp5_verify::ballot_leaf_hash(&state.old_results_add_g5.unwrap()) != r_add.old_value {
            *fail_mask |= FAIL_RESULT_ACCUM;
            ok = false;
        }
    } else if !state.voter_ballots_g5.is_empty() {
        *fail_mask |= FAIL_RESULT_ACCUM;
        ok = false;
    }

    if let Some(ref r_sub) = state.results_sub {
        let Some(mut sum) = state.old_results_sub_g5 else {
            *fail_mask |= FAIL_RESULT_ACCUM;
            return false;
        };
        for ob in &state.overwritten_ballots_g5 {
            let Some(next) = ecgfp5_verify::ballot_add(&sum, ob) else {
                *fail_mask |= FAIL_RESULT_ACCUM;
                return false;
            };
            sum = next;
        }
        if ecgfp5_verify::ballot_leaf_hash(&sum) != r_sub.new_value {
            *fail_mask |= FAIL_RESULT_ACCUM;
            ok = false;
        }
        if ecgfp5_verify::ballot_leaf_hash(&state.old_results_sub_g5.unwrap()) != r_sub.old_value {
            *fail_mask |= FAIL_RESULT_ACCUM;
            ok = false;
        }
    } else if !state.overwritten_ballots_g5.is_empty() {
        *fail_mask |= FAIL_RESULT_ACCUM;
        ok = false;
    }

    ok
}
