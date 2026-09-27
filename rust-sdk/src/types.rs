//! Serde mirrors of the prover service JSON (`service/src/types.rs`,
//! `input-gen/src/lib.rs`, go-sdk `types.go`). Field names are the wire names;
//! optional parts are omitted when empty, as the Go SDK does (the service
//! rejects `null` for some lists).
//!
//! Byte orders are easy to mix up; build strings with [`enc`].

use serde::{Deserialize, Serialize};

use crate::limits::NUM_FIELDS;

fn bn128() -> String {
    "bn128".into()
}

fn groth16() -> String {
    "groth16".into()
}

fn is_empty<T>(v: &[T]) -> bool {
    v.is_empty()
}

// Go encodes a nil slice as `null`.
fn null_as_empty<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(d)?.unwrap_or_default())
}

/// snarkjs Groth16 proof. `curve` and `protocol` default on input (rapidsnark
/// omits `curve`) and are always emitted, since the service requires both.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SnarkJsProof {
    pub pi_a: [String; 3],
    pub pi_b: [[String; 2]; 3],
    pub pi_c: [String; 3],
    #[serde(default = "groth16")]
    pub protocol: String,
    #[serde(default = "bn128")]
    pub curve: String,
}

/// snarkjs verification key (`verification_key.json`).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SnarkJsVk {
    #[serde(default = "groth16")]
    pub protocol: String,
    #[serde(default = "bn128")]
    pub curve: String,
    #[serde(rename = "nPublic", default, skip_serializing_if = "Option::is_none")]
    pub n_public: Option<u64>,
    pub vk_alpha_1: [String; 3],
    pub vk_beta_2: [[String; 2]; 3],
    pub vk_gamma_2: [[String; 2]; 3],
    pub vk_delta_2: [[String; 2]; 3],
    /// Precomputed pairing snarkjs emits; carried through, never used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vk_alphabeta_12: Option<serde_json::Value>,
    #[serde(rename = "IC")]
    pub ic: Vec<[String; 3]>,
}

/// Voter ECDSA signature over its vote id. Only `signature_r/s/v` reach the
/// guest; the service still requires the other fields.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct EcdsaSigJson {
    /// `0x` + 64 hex (BE); unused by the guest.
    pub public_key_x: String,
    pub public_key_y: String,
    /// `0x` + exactly 64 hex, BE.
    pub signature_r: String,
    pub signature_s: String,
    /// Recovery id 0 or 1 (the service defaults a missing value to 0).
    pub signature_v: u8,
    pub vote_id: u64,
    /// Decimal uint160.
    pub address: String,
}

/// One SMT transition. Every 32-byte field is arbo-LE hex (exactly 32 bytes).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
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
    /// Root to leaf, zero-padded to `SMT_LEVELS`.
    pub siblings: Vec<String>,
}

/// Ballot data for the accumulator check. Every coordinate is BE hex.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BallotProofsJson {
    pub old_results: Vec<String>,
    pub voter_ballots: Vec<Vec<String>>,
    #[serde(default, deserialize_with = "null_as_empty")]
    pub overwritten_ballots: Vec<Vec<String>>,
    #[serde(
        default,
        deserialize_with = "null_as_empty",
        skip_serializing_if = "is_empty"
    )]
    pub refreshed_ballots: Vec<Vec<String>>,
}

/// STATETX block. `process_id` and the roots are arbo-LE hex.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct StateTransitionJson {
    pub voters_count: u64,
    pub overwritten_count: u64,
    pub occupied_before: u64,
    pub process_id: String,
    pub old_state_root: String,
    pub new_state_root: String,
    pub vote_id_smt: Vec<SmtEntryJson>,
    pub ballot_smt: Vec<SmtEntryJson>,
    #[serde(
        default,
        deserialize_with = "null_as_empty",
        skip_serializing_if = "is_empty"
    )]
    pub refresh_smt: Vec<SmtEntryJson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub results_smt: Option<SmtEntryJson>,
    pub process_smt: Vec<SmtEntryJson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ballot_proofs: Option<BallotProofsJson>,
}

/// lean-IMT census proof, BE hex; `index` is the path bits.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CensusProofJson {
    pub root: String,
    pub leaf: String,
    pub index: u64,
    pub siblings: Vec<String>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CspProofJson {
    pub r: String,
    pub s: String,
    pub recid: u8,
    /// `0x` + 40 hex.
    pub voter_address: String,
    /// BE hex.
    pub weight: String,
    pub index: u64,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CspDataJson {
    pub proofs: Vec<CspProofJson>,
}

/// TE point, BE hex.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BjjPointJson {
    pub x: String,
    pub y: String,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BjjCiphertextJson {
    pub c1: BjjPointJson,
    pub c2: BjjPointJson,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ReencryptionEntryJson {
    pub original: [BjjCiphertextJson; NUM_FIELDS],
    pub reencrypted: [BjjCiphertextJson; NUM_FIELDS],
}

/// REENCBLK: election key and seed as BE hex. `Debug` redacts the seed (the
/// batch secret).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReencryptionJson {
    pub encryption_key_x: String,
    pub encryption_key_y: String,
    pub seed: String,
    pub entries: Vec<ReencryptionEntryJson>,
}

impl std::fmt::Debug for ReencryptionJson {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReencryptionJson")
            .field("encryption_key_x", &self.encryption_key_x)
            .field("encryption_key_y", &self.encryption_key_y)
            .field("seed", &"<redacted>")
            .field("entries", &self.entries)
            .finish()
    }
}

/// KZGBLK: `process_id` and `root_hash_before` BE hex, commitments `0x` + 96 hex.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct KzgJson {
    pub process_id: String,
    pub root_hash_before: String,
    pub commitments: Vec<String>,
}

/// `POST /prove` body.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ProveRequest {
    pub vk: SnarkJsVk,
    pub proofs: Vec<SnarkJsProof>,
    pub public_inputs: Vec<[String; 3]>,
    pub sigs: Vec<EcdsaSigJson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<StateTransitionJson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub census_proofs: Option<Vec<CensusProofJson>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub csp_data: Option<CspDataJson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reencryption: Option<ReencryptionJson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kzg: Option<KzgJson>,
    /// `"plonk"` (default) or `"stark"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
}

/// One decryption proof, arbo-LE hex (TE coords, `z` reduced mod l).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CpProofJson {
    pub a1x: String,
    pub a1y: String,
    pub a2x: String,
    pub a2y: String,
    pub z: String,
}

/// `POST /results` body for circuit-results (`input-gen/src/results.rs`
/// `ResultsJson`). 32-byte values are arbo-LE hex; `state_root` is the raw
/// root bytes.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ResultsRequest {
    pub state_root: String,
    pub enc_key_x: String,
    pub enc_key_y: String,
    pub key_siblings: Vec<String>,
    pub accumulator: Vec<String>,
    pub acc_siblings: Vec<String>,
    pub results: Vec<u64>,
    pub cp_proofs: Vec<CpProofJson>,
}

/// Service job id (a UUID). Only `[0-9A-Za-z-]` is accepted, so it is safe in
/// a URL path.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct JobId(String);

impl JobId {
    pub fn parse(s: &str) -> Result<Self, crate::Error> {
        if s.is_empty()
            || s.len() > 64
            || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(crate::Error::Input("bad job id".into()));
        }
        Ok(JobId(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for JobId {
    type Error = crate::Error;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        JobId::parse(&s)
    }
}

impl From<JobId> for String {
    fn from(j: JobId) -> String {
        j.0
    }
}

impl std::fmt::Display for JobId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    Queued,
    Running,
    Done,
    Failed,
}

/// `GET /jobs/{id}`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Job {
    pub job_id: JobId,
    pub status: JobStatus,
    /// `batch`, `batchstark`, `fold`, `finalize`, `results`.
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub parent_job_ids: Vec<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub started_at: Option<String>,
    #[serde(default)]
    pub finished_at: Option<String>,
    #[serde(default)]
    pub elapsed_ms: Option<u64>,
    #[serde(default)]
    pub error: Option<String>,
}

/// `GET /health`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Health {
    pub status: String,
    pub version: String,
    pub queue_len: u64,
}

/// Wire encodings. Every helper returns `0x`-prefixed hex.
pub mod enc {
    use crate::ballot::Ballot;
    use crate::crypto::babyjubjub::Point;
    use crate::crypto::elgamal::Ciphertext;
    use crate::crypto::field::{fr_to_be, fr_to_le, Fr};

    use super::{BjjCiphertextJson, BjjPointJson};

    /// Bytes already in arbo little-endian order (roots, siblings, LE32 values).
    pub fn le_hex(b: &[u8; 32]) -> String {
        format!("0x{}", hex::encode(b))
    }

    /// Bytes already big-endian (coordinates, census values, seed).
    pub fn be_hex(b: &[u8; 32]) -> String {
        format!("0x{}", hex::encode(b))
    }

    /// Leaf value of a digest-valued leaf: `reverse(digest)` as LE hex.
    pub fn leaf_value_hex(digest: &[u8; 32]) -> String {
        let mut b = *digest;
        b.reverse();
        le_hex(&b)
    }

    /// SMT key `k` as arbo-LE hex (`k_le8 || 24 zero bytes`).
    pub fn key_hex(k: u64) -> String {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&k.to_le_bytes());
        le_hex(&b)
    }

    /// Field element as an arbo leaf value / LE hex.
    pub fn fr_le_hex(x: &Fr) -> String {
        le_hex(&fr_to_le(x))
    }

    /// Field element as BE hex (coordinates, census, KZG pid).
    pub fn fr_be_hex(x: &Fr) -> String {
        be_hex(&fr_to_be(x))
    }

    /// Root/digest bytes as the BE hex of their little-endian integer
    /// (`kzg.root_hash_before`).
    pub fn root_be_hex(root: &[u8; 32]) -> String {
        let mut b = *root;
        b.reverse();
        be_hex(&b)
    }

    pub fn point_json(p: &Point) -> BjjPointJson {
        BjjPointJson {
            x: fr_be_hex(&p.x),
            y: fr_be_hex(&p.y),
        }
    }

    pub fn ciphertext_json(c: &Ciphertext) -> BjjCiphertextJson {
        BjjCiphertextJson {
            c1: point_json(&c.c1),
            c2: point_json(&c.c2),
        }
    }

    /// 64 BE hex coordinates.
    pub fn ballot_be_hex(b: &Ballot) -> Vec<String> {
        b.coords().iter().map(fr_be_hex).collect()
    }

    /// 64 LE hex coordinates (results request accumulator).
    pub fn ballot_le_hex(b: &Ballot) -> Vec<String> {
        b.coords().iter().map(fr_le_hex).collect()
    }
}
