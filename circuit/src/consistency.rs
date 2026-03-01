/// DAVINCI protocol consistency checks:
///
/// 1. **VoteID namespace**: each `vote_id_chain[i].new_key[0] ∈ [VoteIDMin, VoteIDMax]`
/// 2. **VoteID–proof binding**: `vote_id_chain[i].new_key[0] == proofs[i].public_inputs[1][0]`
/// 3. **Ballot namespace**: each `ballot_chain[i].new_key[0] ∈ [BallotMin, BallotMax]`
/// 4. **Ballot–address binding**: `(ballot_chain[i].new_key[0] & 0xFFFF) ==
///    (proofs[i].public_inputs[0][0] & 0xFFFF)` (lower 16 bits of address)
///
/// These checks are only applied when a STATETX block is present.
/// When no state block is present, returns `true` immediately (absence is not a failure).

use crate::io::ParsedInput;

// From davinci-node/spec/params/params.go
const VOTE_ID_MIN: u64 = 0x8000_0000_0000_0000;
const BALLOT_MIN: u64 = 0x0000_0000_0000_0010; // ConfigMax + 1
const BALLOT_MAX: u64 = 0x7FFF_FFFF_FFFF_FFFF; // VoteIDMin - 1

// Public input indices (Circom BallotCircuit).
const PUB_ADDRESS: usize = 0;
const PUB_VOTE_ID: usize = 1;

pub fn verify_consistency(parsed: &ParsedInput, fail_mask: &mut u32) -> bool {
    let state = match &parsed.state {
        None => return true, // STATETX absent — no consistency checks to perform
        Some(s) => s,
    };

    let n_voters = state.n_voters;
    if n_voters == 0 {
        return true;
    }

    let mut ok = true;

    // ── VoteID chain consistency ──────────────────────────────────────────────
    for i in 0..n_voters {
        if i >= state.vote_id_chain.len() {
            // More voters declared than voteID SMT entries.
            *fail_mask |= 1 << 14;
            return false;
        }
        let vid_key = state.vote_id_chain[i].new_key[0];

        // Namespace check: key must be in [VoteIDMin, VoteIDMax].
        if vid_key < VOTE_ID_MIN {
            *fail_mask |= 1 << 14;
            ok = false;
        }

        // Binding check: matches Groth16 public input[1] (voteID) for proof i.
        if i < parsed.proofs.len() && parsed.n_public > PUB_VOTE_ID {
            let pub_vote_id = parsed.proofs[i].public_inputs[PUB_VOTE_ID][0];
            if pub_vote_id != vid_key {
                *fail_mask |= 1 << 14;
                ok = false;
            }
        }
    }

    // ── Ballot chain consistency ─────────────────────────────────────────────
    // Only check when ballot chain is present (n_voters may exceed ballot_chain.len()
    // in partial batches that only update voteID — not typical but allowed).
    if !state.ballot_chain.is_empty() {
        for i in 0..n_voters {
            if i >= state.ballot_chain.len() {
                *fail_mask |= 1 << 15;
                return false;
            }
            let ballot_key = state.ballot_chain[i].new_key[0];

            // Namespace check: key must be in [BallotMin, BallotMax].
            if ballot_key < BALLOT_MIN || ballot_key > BALLOT_MAX {
                *fail_mask |= 1 << 15;
                ok = false;
            }

            // Address binding: (ballot_key - BallotMin) lower 16 bits == address lower 16 bits.
            // key = BallotMin + (censusIdx << 16) + (addr & 0xFFFF)
            if ballot_key >= BALLOT_MIN && i < parsed.proofs.len() && parsed.n_public > PUB_ADDRESS {
                let pub_addr_lo16 = parsed.proofs[i].public_inputs[PUB_ADDRESS][0] & 0xFFFF;
                let key_addr_lo16 = (ballot_key.wrapping_sub(BALLOT_MIN)) & 0xFFFF;
                if pub_addr_lo16 != key_addr_lo16 {
                    *fail_mask |= 1 << 15;
                    ok = false;
                }
            }
        }
    }

    ok
}
