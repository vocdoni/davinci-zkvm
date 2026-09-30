//! Shared types for the davinci-zkvm service.

use chrono::{DateTime, Utc};
use davinci_zkvm_input_gen::{EcdsaSig, SnarkJsProof, SnarkJsVk, NUM_FIELDS};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Accept JSON `null` for an optional list (Go encodes a nil slice as null).
fn null_as_empty<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(d)?.unwrap_or_default())
}

/// One SMT state-transition entry in JSON format.
///
/// Every 32-byte field is arbo little-endian hex (with or without "0x" prefix).
/// `siblings` must all be the same length across all entries in a request.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SmtEntryJson {
    /// Tree root before the transition.
    pub old_root: String,
    /// Tree root after the transition.
    pub new_root: String,
    /// Key of the old leaf (zero if is_old0=1).
    pub old_key: String,
    /// Value of the old leaf (zero if is_old0=1).
    pub old_value: String,
    /// 1 when old leaf slot was empty (pure insert), 0 otherwise
    pub is_old0: u8,
    /// Key being inserted or updated.
    pub new_key: String,
    /// New value.
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
    #[serde(default)]
    pub occupied_before: u64,
    pub process_id: String,
    pub old_state_root: String,
    pub new_state_root: String,
    #[serde(default)]
    pub vote_id_smt: Vec<SmtEntryJson>,
    #[serde(default)]
    pub ballot_smt: Vec<SmtEntryJson>,
    #[serde(default, deserialize_with = "null_as_empty")]
    pub refresh_smt: Vec<SmtEntryJson>,
    #[serde(default)]
    pub results_smt: Option<SmtEntryJson>,
    #[serde(default)]
    pub process_smt: Vec<SmtEntryJson>,
    #[serde(default)]
    pub ballot_proofs: Option<BallotProofsJson>,
}

/// Result accumulator ballot data: old results plus per-voter ballots
/// (64 big-endian hex Fr elements each) for the homomorphic tally check.
#[derive(Debug, Deserialize, Clone)]
pub struct BallotProofsJson {
    pub old_results: Vec<String>,
    pub voter_ballots: Vec<Vec<String>>,
    #[serde(default)]
    pub overwritten_ballots: Vec<Vec<String>>,
    #[serde(default, deserialize_with = "null_as_empty")]
    pub refreshed_ballots: Vec<Vec<String>>,
}

/// One lean-IMT Poseidon census membership proof in JSON format.
#[derive(Debug, Deserialize, Clone)]
pub struct CensusProofJson {
    /// 32-byte big-endian hex: census tree root
    pub root: String,
    /// 32-byte big-endian hex: leaf = PackAddressWeight(address, weight)
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
    /// Original ciphertexts from the ballot proof.
    pub original: [BjjCiphertextJson; NUM_FIELDS],
    /// Re-encrypted ciphertexts stored in the state tree.
    pub reencrypted: [BjjCiphertextJson; NUM_FIELDS],
}

/// Re-encryption verification data for the full batch.
///
/// `seed` is the sequencer-private, batch-scoped chain seed (32-byte
/// big-endian hex). The guest derives every per-ciphertext offset scalar from
/// `(seed, state.old_root)` via a SHA-256 chain, so no per-voter secret is
/// carried in the payload.
#[derive(Debug, Deserialize, Clone)]
pub struct ReencryptionDataJson {
    pub encryption_key_x: String,
    pub encryption_key_y: String,
    pub seed: String,
    pub entries: Vec<ReencryptionEntryJson>,
}

/// KZG commitment data in JSON format.
///
/// All hex strings use the "0x"-prefixed big-endian convention.
#[derive(Debug, Deserialize, Clone)]
pub struct KzgEvalJson {
    /// 32-byte big-endian hex: BN254 Fr process identifier.
    pub process_id: String,
    /// 32-byte big-endian hex: Arbo state root before the batch.
    pub root_hash_before: String,
    /// 1..=MAX_BLOBS compressed BLS12-381 G1 KZG commitments (0x-prefixed 96-hex-char each).
    pub commitments: Vec<String>,
}

/// One CSP ECDSA attestation for a voter in JSON format.
#[derive(Debug, Deserialize, Clone)]
pub struct CspProofJson {
    /// ECDSA signature R component, 32-byte big-endian hex.
    pub r: String,
    /// ECDSA signature S component, 32-byte big-endian hex.
    pub s: String,
    /// y-coordinate parity bit (0 or 1) used by `ecdsa_recover_secp256k1`.
    pub recid: u8,
    /// Voter's Ethereum address, 20-byte hex (0x-prefixed).
    pub voter_address: String,
    /// Voter's census weight, 32-byte big-endian hex.
    pub weight: String,
    /// CSP-assigned auto-increment ballot index.
    pub index: u64,
}

/// CSP ECDSA census data for the full batch in JSON format. The CSP public key
/// is not part of the payload; the guest recovers it per-entry via
/// `ecdsa_recover_secp256k1`.
#[derive(Debug, Deserialize, Clone)]
pub struct CspDataJson {
    /// Per-voter CSP ECDSA attestations.
    pub proofs: Vec<CspProofJson>,
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
    /// ECDSA signatures: one per proof, in same order. Mandatory.
    pub sigs: Vec<EcdsaSig>,
    /// Full state-transition data for the DAVINCI protocol.
    #[serde(default)]
    pub state: Option<StateTransitionJson>,
    /// Census lean-IMT Poseidon membership proofs (one per voter).
    #[serde(default)]
    pub census_proofs: Vec<CensusProofJson>,
    /// CSP ECDSA census data (used when censusOrigin == 4).
    /// Mutually exclusive with census_proofs.
    #[serde(default)]
    pub csp_data: Option<CspDataJson>,
    /// ElGamal re-encryption verification data.
    #[serde(default)]
    pub reencryption: Option<ReencryptionDataJson>,
    /// KZG EIP-4844 blob barycentric evaluation data.
    #[serde(default)]
    pub kzg: Option<KzgEvalJson>,
    /// Proof output kind: "plonk" (default, on-chain SNARK) or "stark"
    /// (vadcop-final STARK only, foldable by the aggregator).
    #[serde(default)]
    pub output: Option<String>,
}

/// HTTP request body for POST /fold.
///
/// Folds one or more completed STARK batch jobs (and optionally a previous
/// fold job) into a single aggregator STARK proof. All proof blobs are read
/// from the referenced jobs' on-disk artifacts; nothing is shipped by the
/// client.
#[derive(Debug, Deserialize)]
pub struct FoldRequest {
    /// Immutable election chain config (all 32-byte fields LE hex).
    pub config: davinci_zkvm_input_gen::aggregator::ChainConfig,
    /// Previous fold job to chain from. None = genesis fold.
    #[serde(default)]
    pub prev_fold_job: Option<Uuid>,
    /// Completed batch jobs (proven with output=stark), in chain order.
    pub batch_jobs: Vec<Uuid>,
    /// Aggregator program_vk to bind (0x-prefixed BE hex, 32 bytes).
    /// Defaults to the previous fold proof's program_vk, or zero for the
    /// genesis bootstrap pass.
    #[serde(default)]
    pub fold_vk: Option<String>,
}

/// HTTP request body for POST /finalize.
///
/// Verifies the last fold proof, the Results-leaf inclusions, and the
/// trustees' decryption proofs, then wraps everything in one PLONK.
#[derive(Debug, Deserialize)]
pub struct FinalizeRequest {
    /// Immutable election chain config (all 32-byte fields LE hex).
    pub config: davinci_zkvm_input_gen::aggregator::ChainConfig,
    /// Completed fold job whose proof to finalize.
    pub fold_job: Uuid,
    /// Aggregator program_vk to bind (0x-prefixed BE hex, 32 bytes).
    /// Defaults to the fold proof's own program_vk.
    #[serde(default)]
    pub fold_vk: Option<String>,
    /// Decrypted results payload: accumulator ballots, plaintext results,
    /// Chaum-Pedersen proofs and SMT siblings.
    pub results: davinci_zkvm_input_gen::aggregator::ResultsPayload,
}

/// Query parameters of POST /jobs/import.
#[derive(Debug, Default, Deserialize)]
pub struct ImportParams {
    #[serde(default)]
    pub kind: ImportKind,
}

/// Job kind an imported STARK is registered as.
#[derive(Debug, Default, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ImportKind {
    /// A vote batch STARK, referenced by `/fold` in `batch_jobs`.
    #[default]
    Batch,
    /// A fold STARK, referenced by `/fold` in `prev_fold_job` or by `/finalize`.
    Fold,
}

impl ImportKind {
    pub fn job_kind(self) -> JobKind {
        match self {
            ImportKind::Batch => JobKind::BatchStark,
            ImportKind::Fold => JobKind::Fold,
        }
    }
}

/// HTTP request body for POST /results: the single-key tally of one election
/// (circuit-results/RESULTS.md). 32-byte values are arbo-LE hex.
pub type ResultsRequest = davinci_zkvm_input_gen::results::ResultsJson;

/// Job status enum
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    Queued,
    Running,
    Done,
    Failed,
}

/// What a job proves and which ELF/pipeline it uses.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum JobKind {
    /// Vote batch, PLONK wrap (on-chain SNARK).
    Batch,
    /// Vote batch, vadcop-final STARK only (foldable).
    BatchStark,
    /// Aggregator fold step, STARK only.
    Fold,
    /// Aggregator finalize step, PLONK wrap.
    Finalize,
    /// Single-key tally (circuit-results), PLONK wrap.
    Results,
}

impl JobKind {
    pub fn is_plonk(self) -> bool {
        matches!(self, JobKind::Batch | JobKind::Finalize | JobKind::Results)
    }
}

/// A proof job tracked in the service
#[derive(Debug, Clone, Serialize)]
pub struct Job {
    pub job_id: Uuid,
    pub status: JobStatus,
    pub kind: JobKind,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub parent_job_ids: Vec<Uuid>,
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
    pub fn new(id: Uuid, kind: JobKind, parent_job_ids: Vec<Uuid>) -> Self {
        Self {
            job_id: id,
            status: JobStatus::Queued,
            kind,
            parent_job_ids,
            created_at: Utc::now(),
            started_at: None,
            finished_at: None,
            elapsed_ms: None,
            error: None,
        }
    }
}
