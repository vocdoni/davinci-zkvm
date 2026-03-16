//! POST /prove => submit a batch of davinci-stark ballot proofs for ZisK proving.

use crate::api::AppState;
use crate::types::{ProveRequest, SmtEntryJson};
use anyhow::{bail, Context};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use davinci_zkvm_input_gen::stark_types::StarkProofBundle;
use davinci_zkvm_input_gen::{
    address_hex_to_fr_le, be_hex32_to_fr_le, census_proof_from_hex, generate_stark_input,
    wrap_for_zisk_vm, write_census_block, write_csp_block, write_kzg_block, write_reenc_block_g5,
    write_state_block, CspBlockData, CspEntryData, Ecgfp5BallotProofData, Ecgfp5CiphertextData,
    Ecgfp5ReencEntryData, KzgData, SmtEntry, StateData,
};
use tracing::{debug, error, info, warn};

fn build_zisk_input_bytes(
    stark_proofs: Vec<crate::types::StarkProofJson>,
    sigs: Vec<davinci_zkvm_input_gen::EcdsaSig>,
    state_json: Option<crate::types::StateTransitionJson>,
    census_json: Vec<crate::types::CensusProofJson>,
    csp_json: Option<crate::types::CspDataJson>,
    reenc_g5_json: Option<crate::types::Ecgfp5ReencryptionDataJson>,
    kzg_json: Option<crate::types::KzgEvalJson>,
) -> anyhow::Result<Vec<u8>> {
    let bundles = stark_proofs
        .iter()
        .map(|p| {
            let proof_hex = p.proof.trim_start_matches("0x");
            let public_hex = p.public_values.trim_start_matches("0x");
            let proof_bytes = hex::decode(proof_hex).with_context(|| "invalid stark proof hex")?;
            let public_bytes =
                hex::decode(public_hex).with_context(|| "invalid stark public values hex")?;
            let mut wire = Vec::with_capacity(4 + proof_bytes.len() + public_bytes.len());
            wire.extend_from_slice(&(proof_bytes.len() as u32).to_le_bytes());
            wire.extend_from_slice(&proof_bytes);
            wire.extend_from_slice(&public_bytes);
            StarkProofBundle::decode_wire(&wire)
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let mut bytes = generate_stark_input(&bundles, &sigs)?;

    if let Some(st) = state_json {
        let sd = StateData {
            n_voters: st.voters_count,
            n_overwritten: st.overwritten_count,
            process_id: davinci_zkvm_input_gen::hex32_to_smt_fr(&st.process_id)?,
            old_state_root: davinci_zkvm_input_gen::hex32_to_smt_fr(&st.old_state_root)?,
            new_state_root: davinci_zkvm_input_gen::hex32_to_smt_fr(&st.new_state_root)?,
            vote_id_chain: smt_entries_from_json(&st.vote_id_smt)?,
            ballot_chain: smt_entries_from_json(&st.ballot_smt)?,
            results_add: st.results_add_smt.as_ref().map(smt_entry_from_json).transpose()?,
            results_sub: st.results_sub_smt.as_ref().map(smt_entry_from_json).transpose()?,
            process_proofs: smt_entries_from_json(&st.process_smt)?,
            ecgfp5_ballot_proof_data: st.ecgfp5_ballot_proofs.as_ref().map(|bp| -> anyhow::Result<Ecgfp5BallotProofData> {
                let parse_ct = |ct: &crate::types::Ecgfp5CiphertextJson| -> anyhow::Result<Ecgfp5CiphertextData> {
                    Ok(Ecgfp5CiphertextData { c1: hex40_to_u64x5(&ct.c1)?, c2: hex40_to_u64x5(&ct.c2)? })
                };
                let old_results_add = bp.old_results_add.each_ref().map(parse_ct).into_iter().collect::<anyhow::Result<Vec<_>>>()?;
                let old_results_sub = bp.old_results_sub.each_ref().map(parse_ct).into_iter().collect::<anyhow::Result<Vec<_>>>()?;
                let voter_ballots = bp.voter_ballots.iter().map(|ballot: &[crate::types::Ecgfp5CiphertextJson; 8]| {
                    ballot.iter().map(parse_ct).collect::<anyhow::Result<Vec<_>>>()
                        .and_then(|v: Vec<Ecgfp5CiphertextData>| v.try_into().map_err(|_| anyhow::anyhow!("expected 8 voter ciphertexts")))
                }).collect::<anyhow::Result<Vec<[Ecgfp5CiphertextData; 8]>>>()?;
                let overwritten_ballots = bp.overwritten_ballots.iter().map(|ballot: &[crate::types::Ecgfp5CiphertextJson; 8]| {
                    ballot.iter().map(parse_ct).collect::<anyhow::Result<Vec<_>>>()
                        .and_then(|v: Vec<Ecgfp5CiphertextData>| v.try_into().map_err(|_| anyhow::anyhow!("expected 8 overwritten ciphertexts")))
                }).collect::<anyhow::Result<Vec<[Ecgfp5CiphertextData; 8]>>>()?;
                Ok(Ecgfp5BallotProofData {
                    old_results_add: old_results_add.try_into().map_err(|_| anyhow::anyhow!("expected 8 old_results_add ciphertexts"))?,
                    old_results_sub: old_results_sub.try_into().map_err(|_| anyhow::anyhow!("expected 8 old_results_sub ciphertexts"))?,
                    voter_ballots,
                    overwritten_ballots,
                })
            }).transpose()?,
        };
        bytes.extend(write_state_block(&sd)?);
    }

    if !census_json.is_empty() {
        let proofs = census_json
            .iter()
            .map(|cp| census_proof_from_hex(&cp.root, &cp.leaf, cp.index, &cp.siblings))
            .collect::<anyhow::Result<Vec<_>>>()?;
        bytes.extend(write_census_block(&proofs)?);
    }

    if let Some(csp) = csp_json {
        let csp_pub_key_x = be_hex32_to_fr_le(&csp.csp_pub_key_x)?;
        let csp_pub_key_y = be_hex32_to_fr_le(&csp.csp_pub_key_y)?;
        let entries = csp
            .proofs
            .iter()
            .map(|p| {
                Ok(CspEntryData {
                    r: be_hex32_to_fr_le(&p.r)?,
                    s: be_hex32_to_fr_le(&p.s)?,
                    voter_address: address_hex_to_fr_le(&p.voter_address)?,
                    weight: be_hex32_to_fr_le(&p.weight)?,
                    index: p.index,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        bytes.extend(write_csp_block(&CspBlockData {
            csp_pub_key_x,
            csp_pub_key_y,
            entries,
        })?);
    }

    if let Some(r) = reenc_g5_json {
        let encryption_key = hex40_to_u64x5(&r.encryption_key)?;
        let parse_ct =
            |ct: &crate::types::Ecgfp5CiphertextJson| -> anyhow::Result<Ecgfp5CiphertextData> {
                Ok(Ecgfp5CiphertextData {
                    c1: hex40_to_u64x5(&ct.c1)?,
                    c2: hex40_to_u64x5(&ct.c2)?,
                })
            };
        let entries = r
            .entries
            .iter()
            .map(|e| {
                let original = e
                    .original
                    .iter()
                    .map(parse_ct)
                    .collect::<anyhow::Result<Vec<_>>>()?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("expected 8 original ciphertexts"))?;
                let reencrypted = e
                    .reencrypted
                    .iter()
                    .map(parse_ct)
                    .collect::<anyhow::Result<Vec<_>>>()?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("expected 8 reencrypted ciphertexts"))?;
                Ok(Ecgfp5ReencEntryData {
                    k: hex40_to_u64x5(&e.k)?,
                    original,
                    reencrypted,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        bytes.extend(write_reenc_block_g5(encryption_key, &entries)?);
    }

    if let Some(k) = kzg_json {
        let commitment_hex = k.commitment.trim_start_matches("0x");
        let commitment_bytes = hex::decode(commitment_hex).with_context(|| "invalid commitment hex")?;
        if commitment_bytes.len() != 48 {
            bail!("commitment must be 48 bytes, got {}", commitment_bytes.len());
        }
        let y_claimed_hex = k.y_claimed.trim_start_matches("0x");
        let y_claimed_bytes = hex::decode(y_claimed_hex).with_context(|| "invalid y_claimed hex")?;
        if y_claimed_bytes.len() != 32 {
            bail!("y_claimed must be 32 bytes, got {}", y_claimed_bytes.len());
        }
        let blob_hex = k.blob.trim_start_matches("0x");
        let blob_bytes = hex::decode(blob_hex).with_context(|| "invalid blob hex")?;

        let mut commitment = [0u8; 48];
        commitment.copy_from_slice(&commitment_bytes);
        let mut y_claimed = [0u8; 32];
        y_claimed.copy_from_slice(&y_claimed_bytes);

        bytes.extend(write_kzg_block(&KzgData {
            process_id: be_hex32_to_fr_le(&k.process_id)?,
            root_hash_before: be_hex32_to_fr_le(&k.root_hash_before)?,
            commitment,
            y_claimed,
            blob: blob_bytes,
        })?);
    }

    Ok(wrap_for_zisk_vm(&bytes))
}

pub async fn submit_prove(
    State(state): State<AppState>,
    Json(req): Json<ProveRequest>,
) -> impl IntoResponse {
    let num_proofs = req.stark_proofs.len();
    if num_proofs == 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "stark_proofs array is empty"})),
        )
            .into_response();
    }

    info!("Received prove request: {} ballot proof(s)", num_proofs);

    if let Some(st) = &req.state {
        info!(
            process_id = %st.process_id,
            old_root   = %st.old_state_root,
            new_root   = %st.new_state_root,
            voters     = st.voters_count,
            overwrites = st.overwritten_count,
            vote_id_smt_entries = st.vote_id_smt.len(),
            ballot_smt_entries  = st.ballot_smt.len(),
            process_smt_entries = st.process_smt.len(),
            has_results_add     = st.results_add_smt.is_some(),
            has_results_sub     = st.results_sub_smt.is_some(),
            "State-transition block"
        );
    } else {
        warn!("No state block in request");
    }

    if !req.census_proofs.is_empty() {
        let root = req
            .census_proofs
            .first()
            .map(|p| p.root.as_str())
            .unwrap_or("?");
        debug!(count = req.census_proofs.len(), census_root = %root, "Census proofs");
    }

    if let Some(k) = &req.kzg {
        debug!(
            process_id       = %k.process_id,
            root_hash_before = %k.root_hash_before,
            commitment       = %k.commitment,
            y_claimed        = %k.y_claimed,
            blob_bytes       = k.blob.len() / 2,
            "KZG barycentric-evaluation block"
        );
    }

    debug!(
        sigs = req.sigs.len(),
        queue_len = state.prover.queue_len(),
        "Request accepted; generating ZisK input"
    );

    let stark_proofs = req.stark_proofs.clone();
    let sigs = req.sigs.clone();
    let state_json = req.state.clone();
    let census_json = req.census_proofs.clone();
    let csp_json = req.csp_data.clone();
    let reenc_g5_json = req.ecgfp5_reencryption.clone();
    let kzg_json = req.kzg.clone();

    let input_bytes = match tokio::task::spawn_blocking(move || {
        build_zisk_input_bytes(
            stark_proofs,
            sigs,
            state_json,
            census_json,
            csp_json,
            reenc_g5_json,
            kzg_json,
        )
    }).await {
        Ok(Ok(bytes)) => { debug!("Input generation succeeded: {} bytes", bytes.len()); bytes }
        Ok(Err(e)) => {
            error!("Input generation failed: {}", e);
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("input generation failed: {}", e)}))).into_response();
        }
        Err(e) => {
            error!("Task panic: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "internal error"}))).into_response();
        }
    };

    let proof_output_dir = state.config.proof_output_dir.clone();
    match state.prover.submit(input_bytes, &proof_output_dir).await {
        Ok(job_id) => {
            info!(
                "Job {} queued: {} ballot proof(s), queue_position={}",
                job_id,
                num_proofs,
                state.prover.queue_len()
            );
            (
                StatusCode::ACCEPTED,
                Json(serde_json::json!({"job_id": job_id, "status": "queued"})),
            )
                .into_response()
        }
        Err(e) => {
            error!("failed to queue prove job: {}", e);
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": format!("failed to queue prove job: {}", e)})),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::build_zisk_input_bytes;
    use crate::types::StarkProofJson;
    use davinci_zkvm_input_gen::stark_types::StarkPublicValues;

    #[test]
    fn zisk_service_input_starts_with_length_prefix_then_guest_magic() {
        let public_values = StarkPublicValues {
            inputs_hash: [0; 4],
            address: [0; 4],
            vote_id: 1,
            inputs_preimage: [0; 114],
        };
        let request_proof = StarkProofJson {
            proof: "0x00".to_string(),
            public_values: format!("0x{}", hex::encode(public_values.encode())),
        };
        let sig = davinci_zkvm_input_gen::EcdsaSig {
            public_key_x: format!("0x{:064x}", 0),
            public_key_y: format!("0x{:064x}", 0),
            signature_r: format!("0x{:064x}", 0),
            signature_s: format!("0x{:064x}", 0),
            vote_id: 1,
            address: "0".to_string(),
            private_key: String::new(),
            signature_v: 0,
        };

        let bytes = build_zisk_input_bytes(
            vec![request_proof.clone(), request_proof],
            vec![sig.clone(), sig],
            None,
            vec![],
            None,
            None,
            None,
        )
        .unwrap();

        // First 8 bytes are the payload length (ZisK framing)
        let payload_len = u64::from_le_bytes(bytes[0..8].try_into().unwrap()) as usize;
        assert!(payload_len > 0);
        assert_eq!(bytes.len(), 8 + ((payload_len + 7) & !7));
        // The guest magic starts at offset 8 (inside the payload)
        assert_eq!(
            u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            u64::from_le_bytes(*b"DSTARKB!")
        );
    }
}

fn smt_entry_from_json(e: &SmtEntryJson) -> anyhow::Result<SmtEntry> {
    Ok(SmtEntry {
        old_root: davinci_zkvm_input_gen::hex32_to_smt_fr(&e.old_root)?,
        new_root: davinci_zkvm_input_gen::hex32_to_smt_fr(&e.new_root)?,
        old_key: davinci_zkvm_input_gen::hex32_to_smt_fr(&e.old_key)?,
        old_value: davinci_zkvm_input_gen::hex32_to_smt_fr(&e.old_value)?,
        is_old0: e.is_old0 != 0,
        new_key: davinci_zkvm_input_gen::hex32_to_smt_fr(&e.new_key)?,
        new_value: davinci_zkvm_input_gen::hex32_to_smt_fr(&e.new_value)?,
        fnc0: e.fnc0 != 0,
        fnc1: e.fnc1 != 0,
        siblings: e
            .siblings
            .iter()
            .map(|s| davinci_zkvm_input_gen::hex32_to_smt_fr(s))
            .collect::<anyhow::Result<Vec<_>>>()?,
    })
}

fn smt_entries_from_json(entries: &[SmtEntryJson]) -> anyhow::Result<Vec<SmtEntry>> {
    entries.iter().map(smt_entry_from_json).collect()
}

fn hex40_to_u64x5(s: &str) -> anyhow::Result<[u64; 5]> {
    let hex = s.trim_start_matches("0x");
    let bytes = hex::decode(hex).with_context(|| format!("invalid 40-byte hex: {s}"))?;
    if bytes.len() != 40 {
        bail!("expected 40 bytes, got {}: {}", bytes.len(), s);
    }
    let mut out = [0u64; 5];
    for i in 0..5 {
        out[i] = u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap());
    }
    Ok(out)
}
