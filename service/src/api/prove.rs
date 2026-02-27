//! POST /prove — submit a batch of Groth16 proofs for ZisK proving

use crate::api::AppState;
use crate::types::{ProveRequest, ProveResponse};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use davinci_zkvm_input_gen::{generate_input, write_smt_block, SmtEntry};
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
    let input_bytes = match tokio::task::spawn_blocking(move || {
        let mut bytes = generate_input(&vk, &proofs, &public_inputs, &sigs)?;
        // Append optional SMT block.
        if !smt_json.is_empty() {
            let entries = smt_json.iter()
                .map(|e| -> anyhow::Result<SmtEntry> {
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
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            bytes.extend(write_smt_block(&entries)?);
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
