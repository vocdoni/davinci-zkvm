//! DAVINCI protocol consistency checks:
//! 1. **VoteID namespace**: each `vote_id_chain[i].new_key[0] ∈ [VoteIDMin, VoteIDMax]`
//!    with zero upper limbs. The key is ballot proof `i`'s public input 1
//!    (`publics.rs`), so the proof itself binds it.
//! 2. **Ballot namespace**: each `ballot_chain[i].new_key[0] ∈ [BallotMin, BallotMax]`
//! 3. **Ballot–slot binding**: `ballot_chain[i].new_key[0] == slot(i)`, where the
//!    slot is derived from the voter's census address or CSP index (see `slot_key`)
//! 4. **Distinct slots**: no two `ballot_chain` entries share a key
//! A missing STATETX block sets `FAIL_MISSING_BLOCK`; a batch without voters
//! passes trivially.

use crate::io::ParsedInput;

// From davinci-node/spec/params/params.go
const VOTE_ID_MIN: u64 = 0x8000_0000_0000_0000;
const BALLOT_MIN: u64 = 0x0000_0000_0000_0010; // ConfigMax + 1
const BALLOT_MAX: u64 = 0x7FFF_FFFF_FFFF_FFFF; // VoteIDMin - 1

use crate::hash::sha256_once;
use crate::types::{FAIL_CONSISTENCY, FAIL_BALLOT_NS, MAX_BATCH_SIZE};

/// Domain tag of the Merkle ballot slot hash.
const SLOT_TAG: &[u8; 15] = b"davinci-slot-v1";

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
            // slot. The census address is the ballot proof's public input 0.
            if slot_key(parsed, census_origin, i) != Some(ballot_key) {
                *fail_mask |= FAIL_BALLOT_NS;
                ok = false;
            }
        }

        // Distinct slots: two leaves for one address, or two addresses whose
        // slots collide, would write one slot twice in a batch. Upper limbs
        // are pinned to zero above, so limb 0 is the whole key.
        let mut keys = [0u64; MAX_BATCH_SIZE];
        let m = state.ballot_chain.len().min(MAX_BATCH_SIZE);
        for (k, t) in keys.iter_mut().zip(&state.ballot_chain) {
            *k = t.new_key[0];
        }
        let keys = &mut keys[..m];
        keys.sort_unstable();
        if keys.windows(2).any(|w| w[0] == w[1]) {
            *fail_mask |= FAIL_BALLOT_NS;
            ok = false;
        }
    }

    ok
}

/// Ballot slot of voter `i`.
///
/// Merkle census: `address_slot` of the 20 bytes the census leaf binds (bits
/// 88..247, the ballot proof's public input 0). The
/// lean-IMT root does not bind a leaf position, so the slot cannot come from
/// the proof. CSP census: `BallotMin + index`, the index the CSP signed.
/// `None` when the derivation is impossible (missing proof, index out of the
/// namespace).
fn slot_key(parsed: &ParsedInput, census_origin: u64, i: usize) -> Option<u64> {
    if census_origin == crate::types::CENSUS_ORIGIN_CSP {
        let off = parsed.csp_block.as_ref()?.entries.get(i)?.index;
        let key = BALLOT_MIN.checked_add(off)?;
        return (key <= BALLOT_MAX).then_some(key);
    }
    let a = crate::extract_address_from_census_leaf(&parsed.census_proofs.get(i)?.leaf);
    let mut addr = [0u8; 20];
    addr[..4].copy_from_slice(&(a[2] as u32).to_be_bytes());
    addr[4..12].copy_from_slice(&a[1].to_be_bytes());
    addr[12..].copy_from_slice(&a[0].to_be_bytes());
    Some(address_slot(&addr))
}

/// `BallotMin + (be64(sha256("davinci-slot-v1" || addr)[0..8]) mod (2^63 - 16))`,
/// always in `[BallotMin, BallotMax]`.
fn address_slot(addr: &[u8; 20]) -> u64 {
    let mut buf = [0u8; 35];
    buf[..15].copy_from_slice(SLOT_TAG);
    buf[15..].copy_from_slice(addr);
    let h = sha256_once(&buf);
    let x = u64::from_be_bytes([h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]]);
    BALLOT_MIN + x % (BALLOT_MAX - BALLOT_MIN + 1)
}
