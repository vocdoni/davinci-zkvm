//! davinci-stark ballot proof verification inside the zkVM guest.
//!
//! When the service runs Plonky3-recursion aggregation, individual ballot
//! proof bytes are omitted from the guest input (proof_bytes is empty).
//! The aggregated batch-stark proof is verified outside the guest and
//! the outer verifier checks both proofs together.
//!
//! When proof bytes ARE present (standalone mode), the guest verifies each
//! ballot proof individually (legacy path).

use crate::io::ParsedInput;
use crate::types::FAIL_STARK_PROOF;

pub fn verify_batch(parsed: &ParsedInput, fail_mask: &mut u32) -> bool {
    if parsed.stark_proofs.is_empty() {
        *fail_mask |= FAIL_STARK_PROOF;
        return false;
    }

    // Check if any proof has non-empty proof bytes.
    let has_proof_bytes = parsed.stark_proofs.iter().any(|p| !p.proof_bytes.is_empty());

    if !has_proof_bytes {
        // Aggregated mode: proof bytes were stripped by the service.
        // The aggregated batch-stark proof is verified externally.
        // We only need to ensure public values are present (already parsed).
        return true;
    }

    // Legacy standalone mode: verify each ballot proof individually.
    for proof in &parsed.stark_proofs {
        let mut pv = Vec::with_capacity(123);
        pv.extend(proof.public_values.inputs_hash);
        pv.extend(proof.public_values.address);
        pv.push(proof.public_values.vote_id);
        pv.extend(proof.public_values.inputs_preimage);
        if davinci_stark::verify_ballot_wire(&proof.proof_bytes, &pv).is_err() {
            *fail_mask |= FAIL_STARK_PROOF;
            return false;
        }
    }
    true
}
