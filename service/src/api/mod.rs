//! API router and shared state

pub mod fold;
pub mod jobs;
pub mod prove;
pub mod results;

use crate::config::Config;
use crate::prover::ProverHandle;
use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    routing::get,
    routing::post,
    Json, Router,
};
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

/// Shared application state passed to all handlers
#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub prover: Arc<ProverHandle>,
}

pub fn router(state: AppState) -> Router {
    // 512 MB body limit: a full batch with its SMT siblings, refreshes and
    // ciphertexts is far above the 2 MB axum default.
    const MAX_BODY: usize = 512 * 1024 * 1024;
    Router::new()
        .route("/prove", post(prove::submit_prove))
        .route("/fold", post(fold::submit_fold))
        .route("/finalize", post(fold::submit_finalize))
        .route("/results", post(results::submit_results))
        .route("/jobs/import", post(jobs::import_stark))
        .route("/jobs/:id", get(jobs::get_job_status))
        .route("/jobs/:id/stark", get(jobs::get_job_stark))
        .route("/jobs/:id/proof/stark", get(jobs::get_job_proof_stark))
        .route("/jobs/:id/snark", get(jobs::get_job_snark))
        .route("/jobs/:id/snark/raw", get(jobs::get_job_snark_raw))
        .route("/jobs/:id/publics", get(jobs::get_job_publics))
        .route("/jobs/:id/inputs", get(jobs::get_job_inputs))
        .route("/health", get(health))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state)
}

// 503 once the prover worker has died: the API still answers, but no job will run.
async fn health(State(state): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
    let running = state.prover.worker_running();
    let (code, status, worker) = if running {
        (StatusCode::OK, "ok", "running")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "degraded", "stopped")
    };
    (
        code,
        Json(serde_json::json!({
            "status": status,
            "worker": worker,
            "version": env!("CARGO_PKG_VERSION"),
            "queue_len": state.prover.queue_len(),
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::worker::tests::{stopped_handle, test_config};

    #[tokio::test]
    async fn health_reports_worker_state() {
        let config = test_config("health");
        let prover = Arc::new(ProverHandle::new(config.clone()));
        let (code, Json(body)) = health(State(AppState {
            config: config.clone(),
            prover,
        }))
        .await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body["status"], "ok");
        assert_eq!(body["worker"], "running");
        assert_eq!(body["queue_len"], 0);

        let prover = Arc::new(stopped_handle(config.clone()).await);
        let (code, Json(body)) = health(State(AppState { config, prover })).await;
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["status"], "degraded");
        assert_eq!(body["worker"], "stopped");
        assert_eq!(body["queue_len"], 0);
    }
}
