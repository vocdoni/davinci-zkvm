//! POST /fold => fold completed STARK batch jobs (and optionally a previous
//! fold job) into one aggregator STARK proof.
//!
//! The aggregator guest re-verifies every referenced vadcop-final proof,
//! checks state-root continuity from the genesis root derived from the
//! chain config, and commits a digest binding the config, the state root,
//! and both program vks. All proof blobs are read from the referenced jobs'
//! on-disk `proof.bin`; the client only ships job IDs.

use crate::api::AppState;
use crate::prover::recursion;
use crate::types::{FinalizeRequest, FoldRequest, JobKind, JobStatus};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use davinci_zkvm_input_gen::aggregator::{build_finalize_input, build_fold_input, parse_agg_digest};
use tracing::{error, info};
use uuid::Uuid;

fn bad_request(msg: String) -> axum::response::Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"error": msg})),
    )
        .into_response()
}

/// Confirm the referenced job exists, completed, and has the expected kind.
///
/// `Result<(), Response>` is the axum handler-helper pattern: the `Err` side
/// is a ready-made response the caller returns directly. `axum::Response` is
/// ~128 bytes, hence the allow.
#[allow(clippy::result_large_err)]
fn check_parent_job(
    state: &AppState,
    id: Uuid,
    allowed: &[JobKind],
    label: &str,
) -> Result<(), axum::response::Response> {
    let job = match state.prover.jobs.get(&id) {
        Some(j) => j.clone(),
        None => return Err(bad_request(format!("{} job {} not found", label, id))),
    };
    if job.status != JobStatus::Done {
        return Err(bad_request(format!(
            "{} job {} is not done (status: {:?})",
            label, id, job.status
        )));
    }
    if !allowed.contains(&job.kind) {
        return Err(bad_request(format!(
            "{} job {} has kind {:?}, expected one of {:?}",
            label, id, job.kind, allowed
        )));
    }
    Ok(())
}

pub async fn submit_finalize(
    State(state): State<AppState>,
    Json(req): Json<FinalizeRequest>,
) -> impl IntoResponse {
    if let Err(resp) = check_parent_job(&state, req.fold_job, &[JobKind::Fold], "fold") {
        return resp;
    }

    let fold_vk_arg = match req.fold_vk.as_deref().map(recursion::parse_vk_hex) {
        Some(Ok(vk)) => Some(vk),
        Some(Err(e)) => return bad_request(format!("fold_vk: {}", e)),
        None => None,
    };

    let proof_dir = state.config.proof_output_dir.clone();
    let fold_job = req.fold_job;
    let config = req.config.clone();
    let results = req.results;
    let input_bytes = match tokio::task::spawn_blocking(move || {
        let prev = recursion::load_job_blob(&proof_dir.join(fold_job.to_string()))?;
        // batch_vk lives in the fold proof's committed digest.
        let mut pub_bytes = Vec::with_capacity(64 * 4);
        for w in &prev.publics {
            pub_bytes.extend_from_slice(&w.to_le_bytes());
        }
        let digest = parse_agg_digest(&pub_bytes)?;
        let fold_vk = fold_vk_arg.unwrap_or(prev.program_vk);
        build_finalize_input(&config, digest.batch_vk, fold_vk, &prev.bytes, &results)
    })
    .await
    {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(e)) => return bad_request(format!("finalize input assembly failed: {}", e)),
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
    let elf = state.config.aggregator_elf_path.clone();
    match state
        .prover
        .submit(
            input_bytes,
            &proof_output_dir,
            JobKind::Finalize,
            elf,
            vec![req.fold_job],
        )
        .await
    {
        Ok(job_id) => {
            info!("Finalize job {} queued from fold {}", job_id, req.fold_job);
            (
                StatusCode::ACCEPTED,
                Json(serde_json::json!({"job_id": job_id, "status": "queued"})),
            )
                .into_response()
        }
        Err(e) => {
            error!("Failed to queue finalize job: {}", e);
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": format!("failed to queue job: {}", e)})),
            )
                .into_response()
        }
    }
}

pub async fn submit_fold(
    State(state): State<AppState>,
    Json(req): Json<FoldRequest>,
) -> impl IntoResponse {
    if req.batch_jobs.is_empty() {
        return bad_request("batch_jobs is empty".to_string());
    }

    for id in &req.batch_jobs {
        if let Err(resp) = check_parent_job(&state, *id, &[JobKind::BatchStark], "batch") {
            return resp;
        }
    }
    if let Some(prev) = req.prev_fold_job {
        if let Err(resp) = check_parent_job(&state, prev, &[JobKind::Fold], "prev fold") {
            return resp;
        }
    }

    let fold_vk_arg = match req.fold_vk.as_deref().map(recursion::parse_vk_hex) {
        Some(Ok(vk)) => Some(vk),
        Some(Err(e)) => return bad_request(format!("fold_vk: {}", e)),
        None => None,
    };

    // Read and decode all proof blobs off the async runtime.
    let proof_dir = state.config.proof_output_dir.clone();
    let batch_jobs = req.batch_jobs.clone();
    let prev_job = req.prev_fold_job;
    let config = req.config.clone();
    let input_bytes = match tokio::task::spawn_blocking(move || {
        let batches = batch_jobs
            .iter()
            .map(|id| recursion::load_job_blob(&proof_dir.join(id.to_string())))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let batch_vk = batches[0].program_vk;
        for (i, b) in batches.iter().enumerate() {
            anyhow::ensure!(
                b.program_vk == batch_vk,
                "batch job {} program_vk differs from batch 0",
                i
            );
        }

        let prev = prev_job
            .map(|id| recursion::load_job_blob(&proof_dir.join(id.to_string())))
            .transpose()?;
        let fold_vk = match (fold_vk_arg, &prev) {
            (Some(vk), _) => vk,
            (None, Some(p)) => p.program_vk,
            (None, None) => [0u64; 4],
        };

        let batch_blobs: Vec<Vec<u8>> = batches.iter().map(|b| b.bytes.clone()).collect();
        build_fold_input(
            &config,
            batch_vk,
            fold_vk,
            prev.as_ref().map(|p| p.bytes.as_slice()),
            &batch_blobs,
        )
    })
    .await
    {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(e)) => return bad_request(format!("fold input assembly failed: {}", e)),
        Err(e) => {
            error!("Task panic: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal error"})),
            )
                .into_response();
        }
    };

    let mut parents = Vec::new();
    if let Some(prev) = req.prev_fold_job {
        parents.push(prev);
    }
    parents.extend(req.batch_jobs.iter().copied());

    let proof_output_dir = state.config.proof_output_dir.clone();
    let elf = state.config.aggregator_elf_path.clone();
    match state
        .prover
        .submit(input_bytes, &proof_output_dir, JobKind::Fold, elf, parents)
        .await
    {
        Ok(job_id) => {
            info!(
                "Fold job {} queued: {} batch(es), prev={}",
                job_id,
                req.batch_jobs.len(),
                req.prev_fold_job.is_some()
            );
            (
                StatusCode::ACCEPTED,
                Json(serde_json::json!({"job_id": job_id, "status": "queued"})),
            )
                .into_response()
        }
        Err(e) => {
            error!("Failed to queue fold job: {}", e);
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": format!("failed to queue job: {}", e)})),
            )
                .into_response()
        }
    }
}
