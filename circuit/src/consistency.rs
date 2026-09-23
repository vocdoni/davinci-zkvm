/// DAVINCI protocol consistency checks:
/// 1. **VoteID namespace**: each `vote_id_chain[i].new_key[0] ∈ [VoteIDMin, VoteIDMax]`
/// 2. **VoteID–proof binding**: `vote_id_chain[i].new_key[0] == proofs[i].public_inputs[1][0]`
/// 3. **Ballot namespace**: each `ballot_chain[i].new_key[0] ∈ [BallotMin, BallotMax]`
/// 4. **Ballot–slot binding**: `ballot_chain[i].new_key[0] == slot(i)`, where the
///    slot is a function of the authenticated census position (see `slot_key`)
/// These checks are only applied when a STATETX block is present.
/// When no state block is present, returns `true` immediately (absence is not a failure).

use crate::io::ParsedInput;

// From davinci-node/spec/params/params.go
const VOTE_ID_MIN: u64 = 0x8000_0000_0000_0000;
const BALLOT_MIN: u64 = 0x0000_0000_0000_0010; // ConfigMax + 1
const BALLOT_MAX: u64 = 0x7FFF_FFFF_FFFF_FFFF; // VoteIDMin - 1

// Public input index of the voteID in the BN254 Groth16 ballot proof.
const PUB_VOTE_ID: usize = 1;

use crate::types::{FAIL_CONSISTENCY, FAIL_BALLOT_NS};

pub fn verify_consistency(parsed: &ParsedInput, fail_mask: &mut u32) -> bool {
    let state = match &parsed.state {
        None => {
            *fail_mask |= crate::types::FAIL_MISSING_BLOCK;
            return false;
        }
        Some(s) => s,
    };

    let n_voters = state.n_voters;
    if n_voters == 0 {
        return true;
    }

    let mut ok = true;

    // VoteID chain consistency
    for i in 0..n_voters {
        if i >= state.vote_id_chain.len() {
            // More voters declared than voteID SMT entries.
            *fail_mask |= FAIL_CONSISTENCY;
            return false;
        }
        let vid_entry = &state.vote_id_chain[i];
        let vid_key = vid_entry.new_key[0];

        // The key is a u64: upper limbs must be zero, or the leaf lands at a
        // key the DA blob (which carries limb 0 only) cannot describe.
        if vid_entry.new_key[1] != 0 || vid_entry.new_key[2] != 0 || vid_entry.new_key[3] != 0 {
            *fail_mask |= FAIL_CONSISTENCY;
            ok = false;
        }

        // Namespace check: key must be in [VoteIDMin, u64::MAX].
        // The entire high-bit range [0x8000_0000_0000_0000, 0xFFFF_FFFF_FFFF_FFFF]
        // is the valid VoteID namespace; u64 can never exceed the upper bound.
        if vid_key < VOTE_ID_MIN {
            *fail_mask |= FAIL_CONSISTENCY;
            ok = false;
        }

        // Binding check: matches Groth16 public input[1] (voteID) for proof i.
        if i < parsed.proofs.len() && parsed.n_public > PUB_VOTE_ID {
            let pubs = &parsed.proofs[i].public_inputs[PUB_VOTE_ID];
            let pub_vote_id = pubs[0];
            // VoteIDs are 64-bit values; upper limbs must be zero.
            if pubs[1] != 0 || pubs[2] != 0 || pubs[3] != 0 {
                *fail_mask |= FAIL_CONSISTENCY;
                ok = false;
            }
            if pub_vote_id != vid_key {
                *fail_mask |= FAIL_CONSISTENCY;
                ok = false;
            }
        }
    }

    // Ballot chain consistency
    // Only check when ballot chain is present (n_voters may exceed ballot_chain.len()
    // in partial batches that only update voteID => not typical but allowed).
    if !state.ballot_chain.is_empty() {
        // censusOrigin lives in process config leaf 0x06 (process_proofs[3]).
        let census_origin = state.process_proofs.get(3).map(|p| p.new_value[0]).unwrap_or(0);
        for i in 0..n_voters {
            if i >= state.ballot_chain.len() {
                *fail_mask |= FAIL_BALLOT_NS;
                return false;
            }
            let ballot_entry = &state.ballot_chain[i];
            let ballot_key = ballot_entry.new_key[0];

            // Same reason as the vote-id keys: the slot key is a u64.
            if ballot_entry.new_key[1] != 0 || ballot_entry.new_key[2] != 0 || ballot_entry.new_key[3] != 0 {
                *fail_mask |= FAIL_BALLOT_NS;
                ok = false;
            }

            // Namespace check: key must be in [BallotMin, BallotMax].
            if ballot_key < BALLOT_MIN || ballot_key > BALLOT_MAX {
                *fail_mask |= FAIL_BALLOT_NS;
                ok = false;
            }

            // Slot binding: the key is derived from the census proof the guest
            // verified for this voter, so a ballot can only land in its owner's
            // slot. The census leaf is bound to the ballot proof's address in
            // main.rs (FAIL_BINDING).
            if slot_key(parsed, census_origin, i) != Some(ballot_key) {
                *fail_mask |= FAIL_BALLOT_NS;
                ok = false;
            }
        }
    }

    ok
}

/// Ballot slot of voter `i`, derived from its authenticated census position.
///
/// Merkle census: `BallotMin + ((1 << n_siblings) | path_bits)`. A lean-IMT
/// proof identifies a leaf by its compact path bits and their count (the
/// leading 1 marks the count), so distinct leaves get distinct slots even
/// when the census is not a power of two. Bits above `n_siblings` are never
/// consumed by the path walk, so they must be zero. CSP census: the index the
/// CSP signed. `None` when the derivation is impossible (missing proof, path
/// too long, index out of the namespace).
fn slot_key(parsed: &ParsedInput, census_origin: u64, i: usize) -> Option<u64> {
    let off = if census_origin == crate::types::CENSUS_ORIGIN_CSP {
        parsed.csp_block.as_ref()?.entries.get(i)?.index
    } else {
        let cp = parsed.census_proofs.get(i)?;
        let n = cp.siblings.len();
        if n > 61 || cp.index >> n != 0 {
            return None;
        }
        (1u64 << n) | cp.index
    };
    let key = BALLOT_MIN.checked_add(off)?;
    (key <= BALLOT_MAX).then_some(key)
}
