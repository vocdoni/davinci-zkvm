//! Shared types for the davinci-zkvm service.

use chrono::{DateTime, Utc};
use davinci_zkvm_input_gen::{SnarkJsProof, SnarkJsVk};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// HTTP request body for POST /prove
#[derive(Debug, Deserialize)]
pub struct ProveRequest {
    /// snarkjs verification key
    pub vk: SnarkJsVk,
    /// array of snarkjs Groth16 proofs
    pub proofs: Vec<SnarkJsProof>,
    /// public inputs for each proof (same length as proofs)
    pub public_inputs: Vec<Vec<String>>,
}

/// Job status enum
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    Queued,
    Running,
    Done,
    Failed,
}

/// A proof job tracked in the service
#[derive(Debug, Clone, Serialize)]
pub struct Job {
    pub job_id: Uuid,
    pub status: JobStatus,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Job {
    pub fn new(id: Uuid) -> Self {
        Self {
            job_id: id,
            status: JobStatus::Queued,
            created_at: Utc::now(),
            started_at: None,
            finished_at: None,
            elapsed_ms: None,
            error: None,
        }
    }
}

/// HTTP response for POST /prove
#[derive(Serialize)]
pub struct ProveResponse {
    pub job_id: Uuid,
    pub status: JobStatus,
}

/// HTTP error response
#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

impl ErrorResponse {
    pub fn new(msg: impl Into<String>) -> Self {
        Self { error: msg.into() }
    }
}
