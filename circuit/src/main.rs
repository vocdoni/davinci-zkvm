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
mod results;
mod smt;
mod types;

use crate::types::{FrRaw, ZERO_FR};
use ziskos::{read_input_slice, set_output};

/// Extract the Ethereum address (uint160) from a packed census leaf.
///
/// Census leaves encode `PackAddressWeight(address, weight) = (address << 88) | weight`.
/// This function right-shifts the leaf value by 88 bits to recover the address.
/// The returned FrRaw holds the 160-bit address in the lower 3 limbs.
fn extract_address_from_census_leaf(leaf: &FrRaw) -> FrRaw {
    // 88 = 64 + 24, so we shift across word boundaries.
    [
        (leaf[1] >> 24) | (leaf[2] << 40),
        (leaf[2] >> 24) | (leaf[3] << 40),
        leaf[3] >> 24,
        0,
    ]
}

/// Compute the arbo leaf value for the encryption key: SHA-256(X_BE32 || Y_BE32) → FrRaw.
///
/// This encoding matches the sequencer's convention for storing a BabyJubJub public key
/// as a single 256-bit value in the arbo SHA-256 state tree (config key 0x03).
fn hash_enc_key(x: &FrRaw, y: &FrRaw) -> FrRaw {
    let mut buf = [0u8; 64];
    // FrRaw [u64;4] LE limbs → 32-byte big-endian (arbo convention for hash inputs)
    for (i, &limb) in x.iter().enumerate() {
        let bytes = limb.to_be_bytes();
        let dst = (3 - i) * 8;
        buf[dst..dst + 8].copy_from_slice(&bytes);
    }
    for (i, &limb) in y.iter().enumerate() {
        let bytes = limb.to_be_bytes();
        let dst = 32 + (3 - i) * 8;
        buf[dst..dst + 8].copy_from_slice(&bytes);
    }
    let digest = hash::sha256_once(&buf);
    // 32-byte hash (big-endian) → FrRaw [u64;4] LE limbs
    let mut fr = ZERO_FR;
    for i in 0..4 {
        let off = (3 - i) * 8;
        fr[i] = u64::from_be_bytes(digest[off..off + 8].try_into().unwrap());
    }
    fr
}

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
//   [28..31] BlobCommitment limb 0 (128 bits)
//   [32..35] BlobCommitment limb 1 (128 bits)
//   [36..39] BlobCommitment limb 2 (128 bits)
//
// Indices 40-45: diagnostic / auxiliary outputs
//   [40] batch_ok    — Groth16 batch verification result
//   [41] ecdsa_ok    — ECDSA signature batch result
//   [42] (reserved)
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

    // ═════════════════════════════════════════════════════════════════════════
    // INPUT PARSING
    //
    // Decode the binary input blob into structured data. All subsequent phases
    // operate on the parsed representation. Parse errors set FAIL_PARSE.
    // ═════════════════════════════════════════════════════════════════════════
    let parsed = io::parse_input(&input, &mut fail_mask);

    // ═════════════════════════════════════════════════════════════════════════
    // PHASE 1: BALLOT PROOF VERIFICATION
    //
    // Verify the BN254 Groth16 ballot proofs using batch pairing. Each proof
    // attests that a voter correctly encrypted their ballot under the election
    // public key. The batch verification aggregates all proofs into a single
    // multi-pairing check with random linear combination (Fiat-Shamir).
    //
    // This replaces the 3-circuit recursion chain (VoteVerifier → Aggregator →
    // StateTransition) of the Gnark implementation: the zkVM directly verifies
    // up to 128 BN254 ballot proofs in one pass.
    // ═════════════════════════════════════════════════════════════════════════
    let batch_ok = groth16::verify_batch(&parsed, &mut fail_mask);

    // ═════════════════════════════════════════════════════════════════════════
    // PHASE 2: AUTHENTICATION
    //
    // Verify voter identity via cryptographic signatures. Each voter must prove
    // they control the private key corresponding to their registered address.
    // The signature covers the voteID, binding the voter's identity to their
    // specific ballot.
    //
    // Currently supported: secp256k1 ECDSA (Ethereum-compatible).
    // Extensible to: RSA, BLS, EdDSA, or other signature schemes. The
    // authentication method will be determined by a process parameter
    // (similar to how censusOrigin selects the eligibility check).
    // ═════════════════════════════════════════════════════════════════════════
    let auth_ok = ecdsa::verify_batch(&parsed, &mut fail_mask);

    // ═════════════════════════════════════════════════════════════════════════
    // PHASE 3: ELIGIBILITY
    //
    // Verify each voter's right to participate in this election by checking
    // their membership in the census. The verification method depends on the
    // censusOrigin parameter stored in the process configuration.
    //
    // Currently supported: lean-IMT Poseidon Merkle tree proofs.
    //   Each voter proves inclusion of (address, weight) in the census tree.
    //   The circuit enforces: same root for all proofs, no duplicate leaves.
    //
    // Extensible to: CSP blind signatures (authority signs voter's key),
    // ZK-credential proofs, or other census mechanisms. The census proof
    // format and verification logic will be selected by censusOrigin.
    // ═════════════════════════════════════════════════════════════════════════
    let eligibility_ok = census::verify_batch(&parsed, &mut fail_mask);

    // ═════════════════════════════════════════════════════════════════════════
    // PHASE 4: STATE TRANSITION
    //
    // Verify the Sparse Merkle Tree (SMT) state transition that records votes
    // into the election state. This is the core of the DAVINCI protocol,
    // ensuring that each vote is correctly inserted into the state tree and
    // that the election results are properly accumulated.
    //
    // Sub-checks:
    //   4.1 Consistency — namespace validation and proof-to-state binding
    //   4.2 SMT chains  — VoteID insertions, ballot insertions/updates,
    //                      ResultsAdd/Sub transitions, process config reads
    //   4.3 Re-encryption — ElGamal ballot re-encryption correctness,
    //                        ensuring votes are blinded before storage
    // ═════════════════════════════════════════════════════════════════════════

    // 4.1 Consistency: namespace validation and proof-to-state binding.
    //     - VoteID keys fall in [0x8000000000000000, 0xFFFFFFFFFFFFFFFF]
    //     - VoteID keys match the voteID from the ballot proofs
    //     - Ballot keys fall in [0x10, 0x7FFFFFFFFFFFFFFF]
    //     - Ballot keys encode the voter's address (lower 16 bits)
    let consistency_ok = consistency::verify_consistency(&parsed, &mut fail_mask);

    // 4.2 SMT chain verification: the full state-transition integrity check.
    //     Returns the old/new state roots and vote counts.
    let (state_ok, old_root, new_root, voters, overwritten) =
        smt::verify_state(&parsed, &mut fail_mask);

    // 4.3 Re-encryption: verify that each stored ballot is the original
    //     ballot re-encrypted with a deterministic key derived from k_seed.
    //     This ensures votes are blinded (unlinkable to the voter after storage)
    //     while preserving the homomorphic structure for tallying.
    let reenc_ok = babyjubjub::verify_batch_from_parsed(
        &parsed.reenc_pub_key,
        &parsed.reenc_entries,
        &mut fail_mask,
    );

    // 4.4 Result accumulation and ballot leaf hashes:
    //     - Each ballot SMT leaf hash = SHA-256(serialized_ballot_data)
    //     - NewResultsAdd = OldResultsAdd + Σ(all re-encrypted voter ballots)
    //     - NewResultsSub = OldResultsSub + Σ(overwritten ballots)
    //     This ensures the election tally is correctly maintained across batches.
    let results_ok = match &parsed.state {
        Some(state) => results::verify_results(state, &mut fail_mask),
        None => false, // already caught by FAIL_MISSING_BLOCK above
    };

    // ═════════════════════════════════════════════════════════════════════════
    // PHASE 5: DATA AVAILABILITY
    //
    // Verify the EIP-4844 KZG blob commitment. The blob contains the complete
    // vote data (ballots, voteIDs, addresses, results) for on-chain data
    // availability. The circuit verifies the barycentric evaluation Y = P(Z)
    // where Z is derived from the process context (processID, rootHashBefore,
    // commitment) to bind the blob to this specific state transition.
    // ═════════════════════════════════════════════════════════════════════════
    let (kzg_ok, kzg_commitment) = kzg::verify_kzg(&parsed.kzg, &mut fail_mask);

    // ═════════════════════════════════════════════════════════════════════════
    // PHASE 6: CROSS-BLOCK BINDING
    //
    // The input contains independently-parsed binary blocks (STATETX, KZGBLK,
    // REENCBLK). Each block carries its own copy of shared values like
    // processID and rootHashBefore. An attacker could provide a valid KZG
    // evaluation for a *different* election or a *different* state root if
    // these copies are not cross-checked. This phase enforces that all blocks
    // agree on the same process context.
    //
    // Checks:
    //   1. KZG processID     == State processID
    //   2. KZG rootHashBefore == State old_state_root
    //   3. Encryption key hash from re-encryption block matches the value
    //      stored under process config key 0x03 in the state tree.
    // ═════════════════════════════════════════════════════════════════════════
    let mut binding_ok = true;

    // 6.1 KZG ↔ State processID and rootHashBefore
    if let (Some(kzg_block), Some(state)) = (&parsed.kzg, &parsed.state) {
        if kzg_block.process_id != state.process_id {
            fail_mask |= crate::types::FAIL_BINDING;
            binding_ok = false;
        }
        if kzg_block.root_hash_before != state.old_state_root {
            fail_mask |= crate::types::FAIL_BINDING;
            binding_ok = false;
        }
    }

    // 6.2 Re-encryption public key ↔ process config encryption key (key 0x03)
    //
    // The sequencer stores SHA-256(pubKeyX_BE32 || pubKeyY_BE32) as the arbo
    // leaf value for config key 0x03. The circuit recomputes this hash from
    // the re-encryption block's public key and verifies it matches the
    // process proof value, ensuring the re-encryption key is the one
    // authorized by the election configuration.
    if let (Some((pub_x, pub_y)), Some(state)) = (&parsed.reenc_pub_key, &parsed.state) {
        if state.process_proofs.len() == 4 {
            let enc_key_hash = hash_enc_key(pub_x, pub_y);
            if enc_key_hash != state.process_proofs[2].new_value {
                fail_mask |= crate::types::FAIL_BINDING;
                binding_ok = false;
            }
        }
    }

    // 6.3 Census proof count must equal the voter count from STATETX.
    //
    // Without this check, a malicious prover could provide fewer census
    // proofs than voters, allowing non-census-members to submit votes.
    if let Some(state) = &parsed.state {
        if parsed.census_proofs.len() != state.n_voters {
            fail_mask |= crate::types::FAIL_BINDING;
            binding_ok = false;
        }
    }

    // 6.4 Re-encryption entry count must equal the voter count from STATETX.
    //
    // Ensures every voter ballot has a corresponding re-encryption entry,
    // preventing the prover from omitting re-encryption for some ballots.
    if let Some(state) = &parsed.state {
        if parsed.reenc_entries.len() != state.n_voters {
            fail_mask |= crate::types::FAIL_BINDING;
            binding_ok = false;
        }
    }

    // 6.5 Census leaf address must match the ballot proof's address.
    //
    // The census leaf encodes PackAddressWeight(address, weight) = (address << 88) | weight.
    // The ballot proof's public_inputs[0] is the voter's Ethereum address (uint160).
    // This check binds each census membership proof to the specific voter who submitted
    // the corresponding ballot proof, preventing reuse of a single census proof across
    // multiple voters.
    if let Some(state) = &parsed.state {
        let n = state.n_voters.min(parsed.census_proofs.len()).min(parsed.proofs.len());
        if parsed.n_public >= 1 {
            for i in 0..n {
                let leaf_addr = extract_address_from_census_leaf(&parsed.census_proofs[i].leaf);
                let proof_addr = &parsed.proofs[i].public_inputs[0];
                // Compare lower 3 limbs (160 bits); limb[3] must be zero for valid addresses.
                if leaf_addr[0] != proof_addr[0]
                    || leaf_addr[1] != proof_addr[1]
                    || (leaf_addr[2] & 0xFFFFFFFF) != (proof_addr[2] & 0xFFFFFFFF)
                {
                    fail_mask |= crate::types::FAIL_BINDING;
                    binding_ok = false;
                    break;
                }
            }
        }
    }

    // ═════════════════════════════════════════════════════════════════════════
    // FINAL VERDICT
    //
    // Every phase must pass. The fail_mask provides granular diagnostics
    // for debugging when overall_ok is false.
    // ═════════════════════════════════════════════════════════════════════════
    let overall_ok = fail_mask == 0
        && batch_ok
        && auth_ok
        && eligibility_ok
        && consistency_ok
        && state_ok
        && reenc_ok
        && results_ok
        && kzg_ok
        && binding_ok;

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

    // BlobCommitmentLimbs: each 128-bit limb stored as 4 × u32 LE.
    let limb_u32s = kzg::commitment_to_limb_u32s(&kzg_commitment);
    for (l, limb) in limb_u32s.iter().enumerate() {
        for (w, &word) in limb.iter().enumerate() {
            set_output(28 + l * 4 + w, word);
        }
    }

    // ── Diagnostics ─────────────────────────────────────────────────────────
    set_output(40, batch_ok as u32);
    set_output(41, auth_ok as u32);
    set_output(43, parsed.nproofs as u32);
    set_output(44, parsed.n_public as u32);
    set_output(45, parsed.log_n as u32);
}
