//! Job status and proof download endpoints

use crate::api::AppState;
use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};
use tokio::fs::File;
use tokio_util::io::ReaderStream;
use uuid::Uuid;

/// GET /jobs/:id: return job status
pub async fn get_job_status(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match state.prover.jobs.get(&id) {
        Some(job) => (StatusCode::OK, Json(job.clone())).into_response(),
        None => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "job not found"}))).into_response(),
    }
}

/// GET /jobs/:id/proof: download the final ZisK proof binary
pub async fn get_job_proof(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let job = match state.prover.jobs.get(&id) {
        Some(j) => j.clone(),
        None => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "job not found"}))).into_response(),
    };

    use crate::types::JobStatus;
    match job.status {
        JobStatus::Done => {}
        JobStatus::Failed => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": format!("job failed: {}", job.error.as_deref().unwrap_or("unknown error"))})),
            ).into_response();
        }
        _ => {
            return (
                StatusCode::TOO_EARLY,
                Json(serde_json::json!({"error": "proof not ready yet", "status": job.status})),
            ).into_response();
        }
    }

    // The proof binary is stored at: <proof_output_dir>/<job_id>/vadcop_final_proof.bin
    let proof_path = state.config.proof_output_dir
        .join(id.to_string())
        .join("vadcop_final_proof.bin");

    let file = match File::open(&proof_path).await {
        Ok(f) => f,
        Err(_) => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "proof file not found"}))).into_response(),
    };

    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream);

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (header::CONTENT_DISPOSITION, &format!("attachment; filename=\"proof_{}.bin\"", id)),
        ],
        body,
    ).into_response()
}
