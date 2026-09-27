//! SDK error type.

/// Every fallible SDK call returns this. Messages never carry secrets.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid field element: {0}")]
    Field(String),
    #[error("invalid point: {0}")]
    Point(&'static str),
    #[error("invalid input: {0}")]
    Input(String),
    #[error("signature: {0}")]
    Signature(&'static str),
    #[error("census: {0}")]
    Census(&'static str),
    #[error("blob: {0}")]
    Blob(String),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("http: {0}")]
    Http(String),
    /// 425: the job is still queued or running.
    #[error("job not ready")]
    NotReady,
    /// 404: unknown job or missing artifact (job state is lost on a service restart).
    #[error("not found: {0}")]
    NotFound(String),
    /// 422 on an artifact route, or a job that ended `failed`.
    #[error("job failed: {0}")]
    JobFailed(String),
    /// 503 on submit: the prover queue is full, retry later.
    #[error("prover queue full")]
    QueueFull,
    /// Any other unexpected status (400 carries the service's reason).
    #[error("prover returned {status}: {body}")]
    Status { status: u16, body: String },
    #[error("timed out waiting for the job")]
    Timeout,
}
