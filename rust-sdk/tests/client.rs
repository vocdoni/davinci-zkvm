//! ProverClient against a tiny axum mock of the prover service.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use davinci_zkvm_sdk::client::ProverClient;
use davinci_zkvm_sdk::types::{JobId, JobStatus, ProveRequest, ResultsRequest};
use davinci_zkvm_sdk::Error;
use serde_json::{json, Value};

const DONE: &str = "11111111-1111-1111-1111-111111111111";
const FAILED: &str = "22222222-2222-2222-2222-222222222222";
const SLOW: &str = "33333333-3333-3333-3333-333333333333";
const FLAKY: &str = "44444444-4444-4444-4444-444444444444";

#[derive(Default)]
struct Mock {
    polls: AtomicUsize,
    flaky: AtomicUsize,
    submits: AtomicUsize,
}

fn job(id: &str, status: &str) -> Value {
    json!({"job_id": id, "status": status, "kind": "batch", "created_at": "2026-09-26T00:00:00Z"})
}

async fn get_job(State(m): State<Arc<Mock>>, Path(id): Path<String>) -> axum::response::Response {
    match id.as_str() {
        // queued, running, then done
        DONE => {
            let n = m.polls.fetch_add(1, Ordering::SeqCst);
            let st = ["queued", "running", "done"][n.min(2)];
            Json(job(&id, st)).into_response()
        }
        FAILED => {
            let mut j = job(&id, "failed");
            j["error"] = json!("prover exited: SIGKILL");
            Json(j).into_response()
        }
        SLOW => Json(job(&id, "running")).into_response(),
        // Two 502s, then done.
        FLAKY => {
            if m.flaky.fetch_add(1, Ordering::SeqCst) < 2 {
                (StatusCode::BAD_GATEWAY, "upstream").into_response()
            } else {
                Json(job(&id, "done")).into_response()
            }
        }
        _ => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "job not found"})),
        )
            .into_response(),
    }
}

async fn get_snark(Path(id): Path<String>) -> axum::response::Response {
    match id.as_str() {
        DONE => Json(json!({
            "program_vk": format!("0x{}", "ab".repeat(32)),
            "root_c_vadcop_final": format!("0x{}", "cd".repeat(32)),
            "public_values": format!("0x{}", "01".repeat(512)),
            "proof_bytes": format!("0x{}", "02".repeat(768)),
        }))
        .into_response(),
        FAILED => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error": "job failed: boom"})),
        )
            .into_response(),
        SLOW => (
            StatusCode::TOO_EARLY,
            Json(json!({"error": "not ready yet", "status": "running"})),
        )
            .into_response(),
        // Wrong public_values length.
        FLAKY => Json(json!({
            "program_vk": format!("0x{}", "ab".repeat(32)),
            "root_c_vadcop_final": format!("0x{}", "cd".repeat(32)),
            "public_values": "0x01",
            "proof_bytes": format!("0x{}", "02".repeat(768)),
        }))
        .into_response(),
        _ => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "job not found"})),
        )
            .into_response(),
    }
}

async fn get_publics(Path(id): Path<String>) -> axum::response::Response {
    if id == DONE {
        vec![7u8; 256].into_response()
    } else {
        (StatusCode::TOO_EARLY, Json(json!({"error": "not ready"}))).into_response()
    }
}

async fn prove(State(m): State<Arc<Mock>>, Json(body): Json<Value>) -> axum::response::Response {
    // The first submit is accepted, the second hits a full queue, the third a 400.
    match m.submits.fetch_add(1, Ordering::SeqCst) {
        0 => {
            assert!(body.get("vk").is_some());
            (
                StatusCode::ACCEPTED,
                Json(json!({"job_id": DONE, "status": "queued"})),
            )
                .into_response()
        }
        1 => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "queue full"})),
        )
            .into_response(),
        _ => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "single-proof verification failed for proof[0]"})),
        )
            .into_response(),
    }
}

async fn results(Json(body): Json<Value>) -> axum::response::Response {
    assert_eq!(body["results"].as_array().unwrap().len(), 16);
    (
        StatusCode::ACCEPTED,
        Json(json!({"job_id": SLOW, "status": "queued"})),
    )
        .into_response()
}

async fn serve() -> String {
    let app = Router::new()
        .route(
            "/health",
            get(|| async { Json(json!({"status": "ok", "version": "0.1.0", "queue_len": 2})) }),
        )
        .route("/prove", post(prove))
        .route("/results", post(results))
        .route("/jobs/:id", get(get_job))
        .route("/jobs/:id/snark", get(get_snark))
        .route("/jobs/:id/publics", get(get_publics))
        .with_state(Arc::new(Mock::default()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}/")
}

fn id(s: &str) -> JobId {
    JobId::parse(s).unwrap()
}

fn prove_request() -> ProveRequest {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/wire_prove.json"
    ))
    .unwrap();
    serde_json::from_str(&raw).unwrap()
}

fn results_request() -> ResultsRequest {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/results_request.json"
    ))
    .unwrap();
    serde_json::from_str(&raw).unwrap()
}

const MS: Duration = Duration::from_millis(10);

#[tokio::test]
async fn submit_and_status_mapping() {
    let c = ProverClient::new(&serve().await);
    let h = c.health().await.unwrap();
    assert_eq!((h.status.as_str(), h.queue_len), ("ok", 2));

    let req = prove_request();
    assert_eq!(c.prove(&req).await.unwrap(), id(DONE));
    assert!(matches!(c.prove(&req).await, Err(Error::QueueFull)));
    match c.prove(&req).await {
        Err(Error::Status { status: 400, body }) => assert!(body.contains("single-proof")),
        other => panic!("want 400, got {other:?}"),
    }
    assert_eq!(c.results(&results_request()).await.unwrap(), id(SLOW));
}

#[tokio::test]
async fn artifacts_425_422_404() {
    let c = ProverClient::new(&serve().await);
    let s = c.snark(&id(DONE)).await.unwrap();
    assert_eq!(s.program_vk, [0xab; 32]);
    assert_eq!(s.root_c_vadcop_final, [0xcd; 32]);
    assert_eq!((s.public_values.len(), s.proof_bytes.len()), (512, 768));
    assert_eq!(c.publics(&id(DONE)).await.unwrap(), vec![7u8; 256]);

    assert!(matches!(c.snark(&id(SLOW)).await, Err(Error::NotReady)));
    assert!(matches!(c.publics(&id(SLOW)).await, Err(Error::NotReady)));
    match c.snark(&id(FAILED)).await {
        Err(Error::JobFailed(msg)) => assert!(msg.contains("boom")),
        other => panic!("want 422, got {other:?}"),
    }
    assert!(matches!(
        c.snark(&id("deadbeef")).await,
        Err(Error::NotFound(_))
    ));
    assert!(matches!(c.snark(&id(FLAKY)).await, Err(Error::Input(_))));
}

#[tokio::test]
async fn wait_polls_until_done_failed_or_timeout() {
    let c = ProverClient::new(&serve().await);
    let j = c.wait(&id(DONE), MS, Duration::from_secs(5)).await.unwrap();
    assert_eq!(j.status, JobStatus::Done);
    assert_eq!(j.kind.as_deref(), Some("batch"));

    match c.wait(&id(FAILED), MS, Duration::from_secs(5)).await {
        Err(Error::JobFailed(msg)) => assert!(msg.contains("SIGKILL")),
        other => panic!("want failed, got {other:?}"),
    }

    let t0 = std::time::Instant::now();
    assert!(matches!(
        c.wait(&id(SLOW), MS, Duration::from_millis(150)).await,
        Err(Error::Timeout)
    ));
    assert!(t0.elapsed() < Duration::from_secs(2));

    // Transient 5xx while polling is retried; a 404 is not.
    assert_eq!(
        c.wait(&id(FLAKY), MS, Duration::from_secs(5))
            .await
            .unwrap()
            .status,
        JobStatus::Done
    );
    assert!(matches!(
        c.wait(&id("abc"), MS, Duration::from_secs(5)).await,
        Err(Error::NotFound(_))
    ));
}

#[tokio::test]
async fn unreachable_service_is_an_http_error() {
    let c = ProverClient::new("http://127.0.0.1:1");
    assert!(matches!(c.health().await, Err(Error::Http(_))));
}

/// Live check against a running prover: `DAVINCI_ZKVM_URL=http://127.0.0.1:8080
/// cargo test -p davinci-zkvm-sdk --test client -- --ignored`.
#[tokio::test]
#[ignore]
async fn live_health() {
    let url = std::env::var("DAVINCI_ZKVM_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".into());
    let h = ProverClient::new(&url).health().await.unwrap();
    assert_eq!(h.status, "ok");
}
