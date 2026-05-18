//! HTTP handlers for inspecting jobs and downloading their artifacts.
//!
//! Endpoints exposed for a completed job:
//!
//! - `GET /jobs/:id`           — JSON status (queued / running / done /
//!                               failed) plus timing metadata.
//! - `GET /jobs/:id/snark`     — JSON payload ready for the on-chain
//!                               verifier:
//!                               `{ program_vk, root_c_vadcop_final,
//!                                  public_values, proof_bytes }`,
//!                               all `0x`-prefixed hex.
//! - `GET /jobs/:id/snark/raw` — raw `proof.bin` (bincode), useful for
//!                               `cargo-zisk verify` and other ZisK-native
//!                               tooling.
//! - `GET /jobs/:id/publics`   — the 256-byte `publicValues` blob on its
//!                               own.
//! - `GET /jobs/:id/inputs`    — the raw `input.bin` the SNARK was
//!                               generated over (audit / re-proving).
//!
//! All artifact endpoints return `429 Too Early` until the job is `done`,
//! `422 Unprocessable Entity` if the job failed, and `404 Not Found` for an
//! unknown job ID.

use crate::api::AppState;
use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};
use std::path::PathBuf;
use tokio::fs::File;
use tokio_util::io::ReaderStream;
use uuid::Uuid;

/// `GET /jobs/:id` — return the typed job status as JSON.
pub async fn get_job_status(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match state.prover.jobs.get(&id) {
        Some(job) => (StatusCode::OK, Json(job.clone())).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "job not found"})),
        )
            .into_response(),
    }
}

/// Resolve `<output_dir>/<job_id>/<filename>` only after confirming the job
/// exists and has completed. Returns a `Response` on any failure so the
/// caller can short-circuit directly.
async fn job_artifact_path(
    state: &AppState,
    id: Uuid,
    filename: &str,
    label: &str,
) -> Result<PathBuf, axum::response::Response> {
    let job = match state.prover.jobs.get(&id) {
        Some(j) => j.clone(),
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "job not found"})),
            )
                .into_response())
        }
    };

    use crate::types::JobStatus;
    match job.status {
        JobStatus::Done => {}
        JobStatus::Failed => {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({
                    "error": format!(
                        "job failed: {}",
                        job.error.as_deref().unwrap_or("unknown error")
                    ),
                })),
            )
                .into_response())
        }
        _ => {
            return Err((
                StatusCode::TOO_EARLY,
                Json(serde_json::json!({
                    "error": format!("{} not ready yet", label),
                    "status": job.status,
                })),
            )
                .into_response())
        }
    }

    let path = state
        .config
        .proof_output_dir
        .join(id.to_string())
        .join(filename);

    if !path.exists() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("{} not found", label)})),
        )
            .into_response());
    }
    Ok(path)
}

/// Stream a file as `application/octet-stream` with a suggested filename.
async fn stream_file(path: PathBuf, download_name: String) -> axum::response::Response {
    let file = match File::open(&path).await {
        Ok(f) => f,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "file not found"})),
            )
                .into_response()
        }
    };
    let body = Body::from_stream(ReaderStream::new(file));
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", download_name),
            ),
        ],
        body,
    )
        .into_response()
}

/// `GET /jobs/:id/snark` — return the Solidity-ready PLONK payload as JSON.
///
/// The four fields can be passed straight to
/// `ZiskVerifier.verifySnarkProof(programVK, rootCVadcopFinal, publicValues,
/// proofBytes)`; no further decoding is required on the consumer side.
pub async fn get_job_snark(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let path = match job_artifact_path(&state, id, "snark.json", "snark").await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    match tokio::fs::read(&path).await {
        Ok(buf) => match serde_json::from_slice::<serde_json::Value>(&buf) {
            Ok(v) => (StatusCode::OK, Json(v)).into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!("malformed snark.json: {}", e),
                })),
            )
                .into_response(),
        },
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("read snark.json: {}", e)})),
        )
            .into_response(),
    }
}

/// `GET /jobs/:id/snark/raw` — download the bincode-encoded `proof.bin`,
/// suitable for `cargo-zisk verify` and other ZisK-native tooling.
pub async fn get_job_snark_raw(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match job_artifact_path(&state, id, "proof.bin", "proof").await {
        Ok(path) => stream_file(path, format!("proof_{}.bin", id)).await,
        Err(resp) => resp,
    }
}

/// `GET /jobs/:id/publics` — download the program's `commit_slice` output as
/// raw bytes (256 B). Same payload as the `public_values` field returned by
/// `/snark`.
pub async fn get_job_publics(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match job_artifact_path(&state, id, "publics.bin", "publics").await {
        Ok(path) => stream_file(path, format!("publics_{}.bin", id)).await,
        Err(resp) => resp,
    }
}

/// `GET /jobs/:id/inputs` — download the raw input that produced the SNARK.
pub async fn get_job_inputs(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match job_artifact_path(&state, id, "input.bin", "inputs").await {
        Ok(path) => stream_file(path, format!("inputs_{}.bin", id)).await,
        Err(resp) => resp,
    }
}
