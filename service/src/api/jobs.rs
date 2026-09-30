//! HTTP handlers for inspecting jobs and downloading their artifacts.
//!
//! Endpoints exposed for a completed job:
//!
//! - `GET /jobs/:id` — JSON status (queued / running / done / failed) plus
//!   timing metadata.
//! - `GET /jobs/:id/snark` — JSON payload ready for the on-chain verifier:
//!   `{ program_vk, root_c_vadcop_final, public_values, proof_bytes }`, all
//!   `0x`-prefixed hex.
//! - `GET /jobs/:id/snark/raw` — raw `proof.bin` (bincode), useful for
//!   `cargo-zisk verify` and other ZisK-native tooling.
//! - `GET /jobs/:id/publics` — the guest's 64 `u32` output registers
//!   (256 bytes).
//! - `GET /jobs/:id/inputs` — the raw `input.bin` the SNARK was generated
//!   over (audit / re-proving).
//!
//! All artifact endpoints return `425 Too Early` until the job is `done`,
//! `422 Unprocessable Entity` if the job failed, and `404 Not Found` for an
//! unknown job ID.

use crate::api::AppState;
use crate::types::{ImportParams, Job, JobStatus};
use axum::{
    body::{Body, Bytes},
    extract::{rejection::QueryRejection, Path, Query, State},
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};
use chrono::Utc;
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

/// `POST /jobs/import[?kind=batch|fold]` — import a raw STARK `proof.bin`
/// proven on another worker, registering it as a completed `BatchStark`
/// (`kind=batch`, the default) or `Fold` (`kind=fold`) job on this instance.
///
/// The chained-fold pipeline pins a fold chain to a single worker (the fold
/// guest loads each STARK's blob from that worker's local filesystem), but
/// batch STARKs can be proved anywhere. To scatter batches across a pool and
/// fold them on one worker, the orchestrator ships each batch's `proof.bin`
/// here and gets back a local job id usable in `/fold`. Importing the last
/// fold proof with `kind=fold` moves a fold chain to another worker: the id
/// is usable as `prev_fold_job` in `/fold` or `fold_job` in `/finalize`.
///
/// Soundness does not depend on trusting the blob: the fold guest re-verifies
/// every STARK in-circuit plus continuity/vk binding (a previous fold proof
/// against the `fold_vk` bound in `config_commitment`), so a forged or corrupt
/// blob simply fails to fold. We still decode it here to reject garbage early
/// and to surface the same `stark.json` / `publics.bin` artifacts a natively
/// proved STARK job exposes.
pub async fn import_stark(
    State(state): State<AppState>,
    params: Result<Query<ImportParams>, QueryRejection>,
    body: Bytes,
) -> impl IntoResponse {
    let kind = match params {
        Ok(Query(p)) => p.kind.job_kind(),
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("kind must be batch or fold: {}", e)})),
            )
                .into_response()
        }
    };
    if body.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "empty proof body"})),
        )
            .into_response();
    }

    let job_id = Uuid::new_v4();
    let job_dir = state.config.proof_output_dir.join(job_id.to_string());
    if let Err(e) = tokio::fs::create_dir_all(&job_dir).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("create job dir: {}", e)})),
        )
            .into_response();
    }
    let proof_path = job_dir.join("proof.bin");
    if let Err(e) = tokio::fs::write(&proof_path, &body).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("write proof.bin: {}", e)})),
        )
            .into_response();
    }

    // Decode the blob to reject non-STARK / corrupt bodies before they can be
    // referenced by a fold, and write stark.json + publics.bin so the imported
    // job is indistinguishable from a natively proved one.
    if let Err(e) = crate::prover::recursion::write_stark_artifacts(&job_dir).await {
        let _ = tokio::fs::remove_dir_all(&job_dir).await;
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": format!("not a valid STARK proof.bin: {}", e)})),
        )
            .into_response();
    }

    let now = Utc::now();
    let mut job = Job::new(job_id, kind, vec![]);
    job.status = JobStatus::Done;
    job.started_at = Some(now);
    job.finished_at = Some(now);
    job.elapsed_ms = Some(0);
    state.prover.jobs.insert(job_id, job);

    (StatusCode::OK, Json(serde_json::json!({"job_id": job_id}))).into_response()
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
/// 64 little-endian `u32` (256 B). The `/snark` `public_values` field carries
/// the same values as 8-byte words.
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
/// The input is the private witness, so it is only kept and served when the
/// service runs with `DAVINCI_KEEP_INPUTS=1`.
pub async fn get_job_inputs(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    if !state.config.keep_inputs {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "inputs are not retained; start the service with DAVINCI_KEEP_INPUTS=1"})),
        )
            .into_response();
    }
    match job_artifact_path(&state, id, "input.bin", "inputs").await {
        Ok(path) => stream_file(path, format!("inputs_{}.bin", id)).await,
        Err(resp) => resp,
    }
}

/// `GET /jobs/:id/stark` — program_vk / zisk_vk of a STARK job as JSON
/// (contents of `stark.json`, written by the worker for non-PLONK jobs).
pub async fn get_job_stark(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let path = match job_artifact_path(&state, id, "stark.json", "stark metadata").await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    match tokio::fs::read(&path).await {
        Ok(buf) => match serde_json::from_slice::<serde_json::Value>(&buf) {
            Ok(v) => (StatusCode::OK, Json(v)).into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("malformed stark.json: {}", e)})),
            )
                .into_response(),
        },
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("read stark.json: {}", e)})),
        )
            .into_response(),
    }
}

/// `GET /jobs/:id/proof/stark` — download the raw vadcop-final STARK blob
/// (the exact byte layout the aggregator guest verifies). Converted lazily
/// from `proof.bin` and cached as `vadcop.bin`.
pub async fn get_job_proof_stark(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let proof_path = match job_artifact_path(&state, id, "proof.bin", "proof").await {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let vadcop_path = proof_path.with_file_name("vadcop.bin");
    if !vadcop_path.exists() {
        let job_dir = proof_path.parent().unwrap().to_path_buf();
        let blob = match tokio::task::spawn_blocking(move || {
            crate::prover::recursion::load_job_blob(&job_dir)
        })
        .await
        {
            Ok(Ok(b)) => b,
            Ok(Err(e)) => {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(serde_json::json!({"error": format!("not a STARK proof: {}", e)})),
                )
                    .into_response()
            }
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "internal error"})),
                )
                    .into_response()
            }
        };
        if let Err(e) = tokio::fs::write(&vadcop_path, &blob.bytes).await {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("write vadcop.bin: {}", e)})),
            )
                .into_response();
        }
    }
    stream_file(vadcop_path, format!("vadcop_{}.bin", id)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::worker::tests::test_config;
    use crate::prover::ProverHandle;
    use crate::types::JobKind;
    use axum::http::Uri;
    use serde::Serialize;
    use std::sync::Arc;

    // Mirror of input-gen's private bincode `proof.bin` layout (Vadcop body).
    #[derive(Serialize)]
    enum ProofBody {
        Vadcop {
            proof: Vec<u64>,
            zisk_vk: Vec<u64>,
            kind: VadcopKind,
            hash: String,
            publics_full: Vec<u64>,
        },
    }
    #[derive(Serialize)]
    enum VadcopKind {
        Final,
    }
    #[derive(Serialize)]
    enum HashMode {
        Poseidon1,
    }
    #[derive(Serialize)]
    struct ProgramVk {
        vk: Vec<u64>,
        hash_mode: HashMode,
    }
    #[derive(Serialize)]
    struct Proof {
        body: ProofBody,
        program_vk: ProgramVk,
    }

    fn stark_proof_bin() -> Vec<u8> {
        let proof = Proof {
            body: ProofBody::Vadcop {
                proof: vec![7; 16],
                zisk_vk: vec![1, 2, 3, 4],
                kind: VadcopKind::Final,
                hash: "Poseidon2".to_string(),
                publics_full: (0..68).collect(),
            },
            program_vk: ProgramVk {
                vk: vec![0, 1, 2, 3],
                hash_mode: HashMode::Poseidon1,
            },
        };
        bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap()
    }

    async fn import(state: &AppState, uri: &str, body: Vec<u8>) -> (StatusCode, serde_json::Value) {
        let params = Query::try_from_uri(&uri.parse::<Uri>().unwrap());
        let resp = import_stark(State(state.clone()), params, Bytes::from(body))
            .await
            .into_response();
        let code = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        (code, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn import_registers_requested_kind() {
        let config = test_config("import");
        let dir = config.proof_output_dir.clone();
        let prover = Arc::new(ProverHandle::new(config.clone()));
        let state = AppState { config, prover };

        for (uri, want) in [
            ("/jobs/import", JobKind::BatchStark),
            ("/jobs/import?kind=batch", JobKind::BatchStark),
            ("/jobs/import?kind=fold", JobKind::Fold),
        ] {
            let (code, body) = import(&state, uri, stark_proof_bin()).await;
            assert_eq!(code, StatusCode::OK, "{uri}: {body}");
            let id: Uuid = body["job_id"].as_str().unwrap().parse().unwrap();
            let job = state.prover.jobs.get(&id).unwrap().clone();
            assert_eq!(job.kind, want, "{uri}");
            assert_eq!(job.status, JobStatus::Done, "{uri}");
            assert!(dir.join(id.to_string()).join("stark.json").exists());
        }
        assert_eq!(state.prover.jobs.len(), 3);

        // An unknown kind is rejected before anything touches the disk.
        let before = std::fs::read_dir(&dir).unwrap().count();
        for uri in [
            "/jobs/import?kind=",
            "/jobs/import?kind=Fold",
            "/jobs/import?kind=finalize",
            "/jobs/import?kind=batchstark",
        ] {
            let (code, body) = import(&state, uri, stark_proof_bin()).await;
            assert_eq!(code, StatusCode::BAD_REQUEST, "{uri}: {body}");
        }
        // A body that is not a STARK is rejected whatever the kind.
        let (code, _) = import(&state, "/jobs/import?kind=fold", vec![1, 2, 3]).await;
        assert_eq!(code, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(state.prover.jobs.len(), 3);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), before);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
