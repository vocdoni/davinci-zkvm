//! The ballot proofs' public inputs, derived in-guest.
//!
//! The host sends no public inputs: proof `i` is verified against values the
//! guest already holds, each bound to the state root or to the batch, in the
//! circuit's order (davinci-circom `ballot_proof.circom`):
//!
//! | j | input | source |
//! |---|---|---|
//! | 0 | address | Merkle: bits 88..247 of `census_proofs[i].leaf`; CSP: `csp.entries[i].voter_address` |
//! | 1 | vote_id | `state.vote_id_chain[i].new_key[0]` |
//! | 2 | process_id | `state.process_id` |
//! | 3 | packed_ballot_mode | `state.process_proofs[1].new_value` (config key 0x02) |
//! | 4, 5 | encryption key x, y | `reenc_pub_key`, bound to config key 0x03 in main.rs |
//! | 6 | weight | Merkle: low 88 bits of the leaf; CSP: `csp.entries[i].weight` |
//! | 7 + 4f .. 10 + 4f | c1.x, c1.y, c2.x, c2.y of field f | `reenc_entries[i].original[f]` for `f < num_fields`, the TE identity `(0, 1), (0, 1)` above |
//!
//! Inputs 2..5 are the same for every proof of a batch. Above `num_fields`
//! the circuit leaves the cipherfields unconstrained and every SDK fills them
//! with the identity; the re-encryption check asserts the originals there are
//! the identity, so the constant is exact.

use crate::bn254_fr::{self, is_canonical};
use crate::io::ParsedInput;
use crate::types::*;

pub const PUB_ADDRESS: usize = 0;
pub const PUB_VOTE_ID: usize = 1;
/// First of the four batch constants (process id, ballot mode, key x, key y).
pub const PUB_CONSTANTS: usize = 2;
pub const PUB_WEIGHT: usize = 6;
/// First ciphertext coordinate: field `f` is `PUB_FIELDS + 4f ..= PUB_FIELDS + 4f + 3`.
pub const PUB_FIELDS: usize = 7;

/// The derived public inputs of a batch. Each proof's vector is rebuilt on
/// demand from the parsed input rather than stored (71 values per proof).
pub struct Publics<'a> {
    parsed: &'a ParsedInput,
    state: &'a StateBlock,
    csp: Option<&'a CspBlock>,
    /// Inputs 2..5: process id, packed ballot mode, encryption key x and y.
    pub constants: [FrRaw; 4],
    /// Fields carrying real ciphertexts; the rest are the identity.
    pub num_fields: usize,
}

impl<'a> Publics<'a> {
    /// `None`, with `FAIL_BINDING`, when a source is missing for some proof.
    /// The host-supplied values that nothing else binds byte for byte (the
    /// live original coordinates and the CSP weights) must also be canonical
    /// field elements, or `FAIL_BINDING` is set: the pairing would use their
    /// residue while the transcript hashes the raw limbs. The other inputs are
    /// bound to the state root or the census root as raw bytes.
    pub fn derive(
        parsed: &'a ParsedInput,
        census_origin: u64,
        num_fields: usize,
        fail_mask: &mut u32,
    ) -> Option<Self> {
        let n = parsed.proofs.len();
        let (Some(state), Some((pk_x, pk_y))) = (parsed.state.as_ref(), parsed.reenc_pub_key) else {
            *fail_mask |= FAIL_BINDING;
            return None;
        };
        let csp = if census_origin == CENSUS_ORIGIN_CSP {
            match parsed.csp_block.as_ref() {
                Some(c) if c.entries.len() >= n => Some(c),
                _ => {
                    *fail_mask |= FAIL_BINDING;
                    return None;
                }
            }
        } else {
            None
        };
        if state.process_proofs.len() != 5
            || state.vote_id_chain.len() < n
            || parsed.reenc_entries.len() < n
            || (csp.is_none() && parsed.census_proofs.len() < n)
            || num_fields > NUM_FIELDS
        {
            *fail_mask |= FAIL_BINDING;
            return None;
        }
        let constants = [state.process_id, state.process_proofs[1].new_value, pk_x, pk_y];
        let canonical = parsed.reenc_entries[..n].iter().all(|e| {
            e.original[..num_fields].iter().all(|c| {
                is_canonical(&c.c1x) && is_canonical(&c.c1y) && is_canonical(&c.c2x) && is_canonical(&c.c2y)
            })
        }) && csp.map_or(true, |c| c.entries[..n].iter().all(|e| is_canonical(&e.weight)));
        if !canonical {
            *fail_mask |= FAIL_BINDING;
        }
        Some(Publics { parsed, state, csp, constants, num_fields })
    }

    /// Input 0, the voter address (uint160 in LE limbs).
    pub fn address(&self, i: usize) -> FrRaw {
        match self.csp {
            Some(c) => c.entries[i].voter_address,
            None => crate::extract_address_from_census_leaf(&self.parsed.census_proofs[i].leaf),
        }
    }

    /// Input 1, the vote id: limb 0 of the vote-id SMT key (consistency.rs
    /// requires the upper limbs to be zero).
    pub fn vote_id(&self, i: usize) -> u64 {
        self.state.vote_id_chain[i].new_key[0]
    }

    /// Input 6, the voter weight.
    pub fn weight(&self, i: usize) -> FrRaw {
        match self.csp {
            Some(c) => c.entries[i].weight,
            None => {
                let leaf = &self.parsed.census_proofs[i].leaf;
                [leaf[0], leaf[1] & 0xFF_FFFF, 0, 0]
            }
        }
    }

    /// All public inputs of proof `i`, in circuit order.
    pub fn proof(&self, i: usize) -> [FrRaw; N_PUBLIC] {
        let mut p = [ZERO_FR; N_PUBLIC];
        p[PUB_ADDRESS] = self.address(i);
        p[PUB_VOTE_ID] = [self.vote_id(i), 0, 0, 0];
        p[PUB_CONSTANTS..PUB_CONSTANTS + 4].copy_from_slice(&self.constants);
        p[PUB_WEIGHT] = self.weight(i);
        let original = &self.parsed.reenc_entries[i].original;
        for f in 0..NUM_FIELDS {
            let o = PUB_FIELDS + 4 * f;
            if f < self.num_fields {
                let c = &original[f];
                p[o] = c.c1x;
                p[o + 1] = c.c1y;
                p[o + 2] = c.c2x;
                p[o + 3] = c.c2y;
            } else {
                p[o + 1] = bn254_fr::ONE;
                p[o + 3] = bn254_fr::ONE;
            }
        }
        p
    }
}
