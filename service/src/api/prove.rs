//! POST /prove — submit a batch of Groth16 proofs for ZisK proving

use crate::api::AppState;
use crate::types::{ProveRequest, ProveResponse, SmtEntryJson};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use davinci_zkvm_input_gen::{census_proof_from_hex, generate_input, write_census_block, write_reenc_block, write_smt_block, write_state_block, BjjCiphertextData, ReencEntryData, SmtEntry, StateData};
use tracing::{error, info};

pub async fn submit_prove(
    State(state): State<AppState>,
    Json(req): Json<ProveRequest>,
) -> impl IntoResponse {
    // Validate request
    let num_proofs = req.proofs.len();
    if num_proofs == 0 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "proofs array is empty"}))).into_response();
    }
    if req.public_inputs.len() != num_proofs {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("public_inputs length ({}) must match proofs length ({})", req.public_inputs.len(), num_proofs)})),
        ).into_response();
    }

    // Generate ZisK binary input (CPU-bound — runs in blocking thread pool)
    let vk = req.vk.clone();
    let proofs = req.proofs.clone();
    let public_inputs = req.public_inputs.clone();
    let sigs = req.sigs.clone();
    let smt_json = req.smt.clone();
    let state_json = req.state.clone();
    let census_json = req.census_proofs.clone();
    let reenc_json = req.reencryption.clone();
    let input_bytes = match tokio::task::spawn_blocking(move || {
        let mut bytes = generate_input(&vk, &proofs, &public_inputs, &sigs)?;

        // Append legacy simple SMT block (mutually exclusive with state block).
        if !smt_json.is_empty() && state_json.is_none() {
            let entries = smt_entries_from_json(&smt_json)?;
            bytes.extend(write_smt_block(&entries)?);
        }

        // Append full STATETX state-transition block.
        if let Some(st) = state_json {
            let sd = StateData {
                n_voters: st.voters_count,
                n_overwritten: st.overwritten_count,
                process_id: davinci_zkvm_input_gen::hex32_to_smt_fr(&st.process_id)?,
                old_state_root: davinci_zkvm_input_gen::hex32_to_smt_fr(&st.old_state_root)?,
                new_state_root: davinci_zkvm_input_gen::hex32_to_smt_fr(&st.new_state_root)?,
                vote_id_chain: smt_entries_from_json(&st.vote_id_smt)?,
                ballot_chain: smt_entries_from_json(&st.ballot_smt)?,
                results_add: st.results_add_smt.as_ref().map(|e| smt_entry_from_json(e)).transpose()?,
                results_sub: st.results_sub_smt.as_ref().map(|e| smt_entry_from_json(e)).transpose()?,
                process_proofs: smt_entries_from_json(&st.process_smt)?,
            };
            bytes.extend(write_state_block(&sd)?);
        }

        // Append census block.
        if !census_json.is_empty() {
            let proofs = census_json.iter()
                .map(|cp| census_proof_from_hex(&cp.root, &cp.leaf, cp.index, &cp.siblings))
                .collect::<anyhow::Result<Vec<_>>>()?;
            bytes.extend(write_census_block(&proofs)?);
        }

        // Append re-encryption block.
        if let Some(r) = reenc_json {
            let pub_key_x = davinci_zkvm_input_gen::hex32_to_smt_fr(&r.encryption_key_x)?;
            let pub_key_y = davinci_zkvm_input_gen::hex32_to_smt_fr(&r.encryption_key_y)?;
            let mut entries = Vec::with_capacity(r.entries.len());
            for e in &r.entries {
                let k = davinci_zkvm_input_gen::hex32_to_smt_fr(&e.k)?;
                let parse_ct = |ct: &crate::types::BjjCiphertextJson| -> anyhow::Result<BjjCiphertextData> {
                    Ok(BjjCiphertextData {
                        c1x: davinci_zkvm_input_gen::hex32_to_smt_fr(&ct.c1.x)?,
                        c1y: davinci_zkvm_input_gen::hex32_to_smt_fr(&ct.c1.y)?,
                        c2x: davinci_zkvm_input_gen::hex32_to_smt_fr(&ct.c2.x)?,
                        c2y: davinci_zkvm_input_gen::hex32_to_smt_fr(&ct.c2.y)?,
                    })
                };
                let original: [BjjCiphertextData; 8] = std::array::from_fn(|i| parse_ct(&e.original[i]).unwrap());
                let reencrypted: [BjjCiphertextData; 8] = std::array::from_fn(|i| parse_ct(&e.reencrypted[i]).unwrap());
                entries.push(ReencEntryData { k, original, reencrypted });
            }
            bytes.extend(write_reenc_block(pub_key_x, pub_key_y, &entries)?);
        }

        anyhow::Ok(bytes)
    }).await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(e)) => {
            error!("Input generation failed: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("input generation failed: {}", e)})),
            ).into_response();
        }
        Err(e) => {
            error!("Task panic: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "internal error"}))).into_response();
        }
    };

    // Submit to prover queue
    let proof_output_dir = state.config.proof_output_dir.clone();
    match state.prover.submit(input_bytes, &proof_output_dir).await {
        Ok(job_id) => {
            info!("Job {} queued ({} proofs)", job_id, num_proofs);
            (
                StatusCode::ACCEPTED,
                Json(serde_json::to_value(ProveResponse {
                    job_id,
                    status: crate::types::JobStatus::Queued,
                }).unwrap()),
            ).into_response()
        }
        Err(e) => {
            error!("Failed to queue job: {}", e);
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": format!("failed to queue job: {}", e)})),
            ).into_response()
        }
    }
}

fn smt_entry_from_json(e: &SmtEntryJson) -> anyhow::Result<SmtEntry> {
    let siblings = e.siblings.iter()
        .map(|s| davinci_zkvm_input_gen::hex32_to_smt_fr(s))
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(SmtEntry {
        old_root:  davinci_zkvm_input_gen::hex32_to_smt_fr(&e.old_root)?,
        new_root:  davinci_zkvm_input_gen::hex32_to_smt_fr(&e.new_root)?,
        old_key:   davinci_zkvm_input_gen::hex32_to_smt_fr(&e.old_key)?,
        old_value: davinci_zkvm_input_gen::hex32_to_smt_fr(&e.old_value)?,
        is_old0:   e.is_old0 != 0,
        new_key:   davinci_zkvm_input_gen::hex32_to_smt_fr(&e.new_key)?,
        new_value: davinci_zkvm_input_gen::hex32_to_smt_fr(&e.new_value)?,
        fnc0:      e.fnc0 != 0,
        fnc1:      e.fnc1 != 0,
        siblings,
    })
}

fn smt_entries_from_json(entries: &[SmtEntryJson]) -> anyhow::Result<Vec<SmtEntry>> {
    entries.iter().map(smt_entry_from_json).collect()
}
