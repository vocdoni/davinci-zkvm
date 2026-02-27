//! Shared types for the davinci-zkvm service.

use chrono::{DateTime, Utc};
use davinci_zkvm_input_gen::{EcdsaSig, SnarkJsProof, SnarkJsVk};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// One SMT state-transition entry in JSON format.
///
/// All 32-byte field values are hex-encoded strings (with or without "0x" prefix).
/// `siblings` must all be the same length across all entries in a request.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SmtEntryJson {
    /// 32-byte big-endian hex — old tree root
    pub old_root: String,
    /// 32-byte big-endian hex — new tree root after transition
    pub new_root: String,
    /// 32-byte big-endian hex — key of the old leaf (zero if is_old0=1)
    pub old_key: String,
    /// 32-byte big-endian hex — value of the old leaf (zero if is_old0=1)
    pub old_value: String,
    /// 1 when old leaf slot was empty (pure insert), 0 otherwise
    pub is_old0: u8,
    /// 32-byte big-endian hex — new key being inserted/updated
    pub new_key: String,
    /// 32-byte big-endian hex — new value
    pub new_value: String,
    /// 1 for insert (fnc0=1, fnc1=0) or delete (fnc0=1, fnc1=1)
    pub fnc0: u8,
    /// 1 for update (fnc0=0, fnc1=1) or delete (fnc0=1, fnc1=1)
    pub fnc1: u8,
    /// Merkle siblings root→leaf, padded with "0x00..00" zeros to n_levels length
    pub siblings: Vec<String>,
}

/// HTTP request body for POST /prove
#[derive(Debug, Deserialize)]
pub struct ProveRequest {
    /// snarkjs verification key
    pub vk: SnarkJsVk,
    /// array of snarkjs Groth16 proofs
    pub proofs: Vec<SnarkJsProof>,
    /// public inputs for each proof (same length as proofs)
    pub public_inputs: Vec<Vec<String>>,
    /// ECDSA signatures — one per proof, in same order. Mandatory.
    pub sigs: Vec<EcdsaSig>,
    /// Optional SMT state-transition proofs. When present, the circuit also
    /// verifies each transition and sets output[9]=1 on success.
    #[serde(default)]
    pub smt: Vec<SmtEntryJson>,
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
