//! POST /results => prove the single-key tally of one election with the
//! circuit-results guest, PLONK-wrapped (circuit-results/RESULTS.md).
//!
//! The request is only shape-checked here; canonical encodings, the key and
//! accumulator inclusions and the decryption proofs are checked in-guest, and
//! a bad request proves `ok = 0`.

use crate::api::AppState;
use crate::types::{JobKind, ResultsRequest};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use davinci_zkvm_input_gen::results::build_results_input;
use tracing::{error, info};

pub async fn submit_results(
    State(state): State<AppState>,
    Json(req): Json<ResultsRequest>,
) -> impl IntoResponse {
    let input_bytes =
        match tokio::task::spawn_blocking(move || build_results_input(&req)).await {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(e)) => return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("results input assembly failed: {}", e)})),
            )
                .into_response(),
            Err(e) => {
                error!("Task panic: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "internal error"})),
                )
                    .into_response();
            }
        };

    let proof_output_dir = state.config.proof_output_dir.clone();
    let elf = state.config.results_elf_path.clone();
    match state
        .prover
        .submit(
            input_bytes,
            &proof_output_dir,
            JobKind::Results,
            elf,
            Vec::new(),
            0,
        )
        .await
    {
        Ok(job_id) => {
            info!("Results job {} queued", job_id);
            (
                StatusCode::ACCEPTED,
                Json(serde_json::json!({"job_id": job_id, "status": "queued"})),
            )
                .into_response()
        }
        Err(e) => {
            error!("Failed to queue results job: {}", e);
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": format!("failed to queue job: {}", e)})),
            )
                .into_response()
        }
    }
}
