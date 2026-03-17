//! Shared types for the davinci-zkvm service.

use chrono::{DateTime, Utc};
use davinci_zkvm_input_gen::EcdsaSig;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SmtEntryJson {
    pub old_root: String,
    pub new_root: String,
    pub old_key: String,
    pub old_value: String,
    pub is_old0: u8,
    pub new_key: String,
    pub new_value: String,
    pub fnc0: u8,
    pub fnc1: u8,
    pub siblings: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StateTransitionJson {
    pub voters_count: u64,
    pub overwritten_count: u64,
    pub process_id: String,
    pub old_state_root: String,
    pub new_state_root: String,
    #[serde(default)]
    pub vote_id_smt: Vec<SmtEntryJson>,
    #[serde(default)]
    pub ballot_smt: Vec<SmtEntryJson>,
    #[serde(default)]
    pub results_add_smt: Option<SmtEntryJson>,
    #[serde(default)]
    pub results_sub_smt: Option<SmtEntryJson>,
    #[serde(default)]
    pub process_smt: Vec<SmtEntryJson>,
    #[serde(default)]
    pub ecgfp5_ballot_proofs: Option<Ecgfp5BallotProofDataJson>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StarkProofJson {
    pub proof: String,
    pub public_values: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CensusProofJson {
    pub root: String,
    pub leaf: String,
    pub index: u64,
    pub siblings: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Ecgfp5CiphertextJson {
    pub c1: String,
    pub c2: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Ecgfp5BallotProofDataJson {
    pub old_results_add: [Ecgfp5CiphertextJson; 8],
    pub old_results_sub: [Ecgfp5CiphertextJson; 8],
    pub voter_ballots: Vec<[Ecgfp5CiphertextJson; 8]>,
    pub overwritten_ballots: Vec<[Ecgfp5CiphertextJson; 8]>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Ecgfp5ReencryptionEntryJson {
    pub k: String,
    pub original: [Ecgfp5CiphertextJson; 8],
    pub reencrypted: [Ecgfp5CiphertextJson; 8],
}

#[derive(Debug, Deserialize, Clone)]
pub struct Ecgfp5ReencryptionDataJson {
    pub encryption_key: String,
    pub entries: Vec<Ecgfp5ReencryptionEntryJson>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct KzgEvalJson {
    pub process_id: String,
    pub root_hash_before: String,
    pub commitment: String,
    pub y_claimed: String,
    pub blob: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CspProofJson {
    pub r: String,
    pub s: String,
    pub voter_address: String,
    pub weight: String,
    pub index: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CspDataJson {
    pub csp_pub_key_x: String,
    pub csp_pub_key_y: String,
    pub proofs: Vec<CspProofJson>,
}

#[derive(Debug, Deserialize)]
pub struct ProveRequest {
    pub stark_proofs: Vec<StarkProofJson>,
    pub sigs: Vec<EcdsaSig>,
    #[serde(default)]
    pub state: Option<StateTransitionJson>,
    #[serde(default)]
    pub census_proofs: Vec<CensusProofJson>,
    #[serde(default)]
    pub csp_data: Option<CspDataJson>,
    #[serde(default)]
    pub ecgfp5_reencryption: Option<Ecgfp5ReencryptionDataJson>,
    #[serde(default)]
    pub kzg: Option<KzgEvalJson>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    Queued,
    Running,
    Done,
    Failed,
}

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

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize)]
pub struct JobResponse {
    pub job_id: Uuid,
    pub status: JobStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize)]
pub struct ProveResponse {
    pub job_id: Uuid,
    pub status: JobStatus,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    pub ok: bool,
    pub queue_len: usize,
}
