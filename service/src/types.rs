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

/// Full state-transition data for the DAVINCI protocol.
/// Mirrors go-sdk/types.go StateTransitionData.
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
}

/// One lean-IMT Poseidon census membership proof in JSON format.
#[derive(Debug, Deserialize, Clone)]
pub struct CensusProofJson {
    /// 32-byte big-endian hex — census tree root
    pub root: String,
    /// 32-byte big-endian hex — leaf = PackAddressWeight(address, weight)
    pub leaf: String,
    /// Packed path bits (bit i = (index >> i) & 1)
    pub index: u64,
    /// Non-empty Merkle siblings (variable length)
    pub siblings: Vec<String>,
}

/// One ElGamal ciphertext point (x, y) on BabyJubJub.
#[derive(Debug, Deserialize, Clone)]
pub struct BjjPointJson {
    pub x: String,
    pub y: String,
}

/// One ElGamal ciphertext (C1, C2) on BabyJubJub.
#[derive(Debug, Deserialize, Clone)]
pub struct BjjCiphertextJson {
    pub c1: BjjPointJson,
    pub c2: BjjPointJson,
}

/// Re-encryption data for one voter.
#[derive(Debug, Deserialize, Clone)]
pub struct ReencryptionEntryJson {
    /// Re-encryption seed (before Poseidon), 32-byte BE hex.
    pub k: String,
    /// 8 original ciphertexts from the ballot proof.
    pub original: [BjjCiphertextJson; 8],
    /// 8 re-encrypted ciphertexts stored in the state tree.
    pub reencrypted: [BjjCiphertextJson; 8],
}

/// Re-encryption verification data for the full batch.
#[derive(Debug, Deserialize, Clone)]
pub struct ReencryptionDataJson {
    pub encryption_key_x: String,
    pub encryption_key_y: String,
    pub entries: Vec<ReencryptionEntryJson>,
}

/// KZG EIP-4844 blob barycentric evaluation data in JSON format.
///
/// All hex strings use the "0x"-prefixed big-endian convention.
#[derive(Debug, Deserialize, Clone)]
pub struct KzgEvalJson {
    /// 32-byte big-endian hex — BN254 Fr process identifier.
    pub process_id: String,
    /// 32-byte big-endian hex — Arbo state root before the batch.
    pub root_hash_before: String,
    /// 48-byte big-endian hex — compressed BLS12-381 G1 KZG commitment.
    pub commitment: String,
    /// 32-byte big-endian hex — claimed evaluation Y = P(Z).
    pub y_claimed: String,
    /// 131072-byte big-endian hex — full EIP-4844 blob (4096 × 32-byte cells).
    pub blob: String,
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
    /// Optional simple SMT proofs (legacy/testing). Use state for full protocol.
    #[serde(default)]
    pub smt: Vec<SmtEntryJson>,
    /// Full state-transition data for the DAVINCI protocol.
    #[serde(default)]
    pub state: Option<StateTransitionJson>,
    /// Census lean-IMT Poseidon membership proofs (one per voter).
    #[serde(default)]
    pub census_proofs: Vec<CensusProofJson>,
    /// ElGamal re-encryption verification data.
    #[serde(default)]
    pub reencryption: Option<ReencryptionDataJson>,
    /// KZG EIP-4844 blob barycentric evaluation data.
    #[serde(default)]
    pub kzg: Option<KzgEvalJson>,
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
