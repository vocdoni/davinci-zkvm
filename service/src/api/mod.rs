//! API router and shared state

pub mod jobs;
pub mod prove;

use crate::config::Config;
use crate::prover::ProverHandle;
use axum::{extract::State, routing::get, routing::post, Json, Router};
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
    Router::new()
        .route("/prove", post(prove::submit_prove))
        .route("/jobs/:id", get(jobs::get_job_status))
        .route("/jobs/:id/proof", get(jobs::get_job_proof))
        .route("/health", get(health))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn health(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "queue_len": state.prover.queue_len(),
    }))
}
