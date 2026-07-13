//! Aggregator guest input assembly: chained-mode election config, vadcop
//! proof blobs, and the framed input stream for `circuit-aggregator/`.
//!
//! Input frames (each framed for `read_input_slice`: u64 LE length prefix,
//! data padded to 8 bytes):
//!   1. header: 12 u64 LE = [magic, mode, has_prev, n_batch, batch_vk[4], fold_vk[4]]
//!   2. config: 200 bytes (see [`ChainConfig::encode`])
//!   3. (if has_prev) previous fold proof blob
//!   4. n_batch vote-batch proof blobs
//!
//! Proof blobs use the `get_proof_bytes()` layout consumed by
//! `ziskos::zisklib::verify_zisk_proof_c` (ZisK v0.18.0):
//!   words = [minimal][n_publics=68][program_vk(4)][publics(64)][proof][zisk_vk(4)]

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

pub const AGG_MAGIC: u64 = u64::from_le_bytes(*b"DAVAGGR!");
pub const MODE_FOLD: u64 = 1;
pub const MODE_FINALIZE: u64 = 2;

const ZISK_PUBLICS: usize = 64;
const PROGRAM_VK_LEN: usize = 4;

/// Immutable election config for the chained mode. All 32-byte fields are
/// little-endian (arbo/FrRaw convention). The guest recomputes the genesis
/// state root from these values and commits sha256 of the encoded frame
/// concatenated with batch_vk ‖ fold_vk (the circuit-release identity).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    /// ProcessID (state tree key 0x00), 32 bytes LE, hex-encoded.
    pub process_id: String,
    /// BallotMode (key 0x02), 32 bytes LE, hex.
    pub ballot_mode: String,
    /// Encryption pubkey X (Twisted Edwards), 32 bytes LE, hex.
    pub enc_x: String,
    /// Encryption pubkey Y (Twisted Edwards), 32 bytes LE, hex.
    pub enc_y: String,
    /// CensusOrigin (key 0x06): 1-3 = lean-IMT Merkle, 4 = CSP.
    pub census_origin: u64,
    /// Census root every batch must use, 32 bytes LE, hex.
    pub census_root: String,
    /// sha256 of the ballot Groth16 VK wire bytes (key 0x07), 32 bytes LE, hex.
    pub ballot_vk_hash: String,
}

fn hex32_le(field: &str, s: &str) -> Result<[u8; 32]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).with_context(|| format!("config field {}: bad hex", field))?;
    if bytes.len() != 32 {
        bail!("config field {}: expected 32 bytes, got {}", field, bytes.len());
    }
    Ok(bytes.try_into().unwrap())
}

impl ChainConfig {
    /// Encode to the 200-byte guest config frame.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(200);
        out.extend_from_slice(&hex32_le("process_id", &self.process_id)?);
        out.extend_from_slice(&hex32_le("ballot_mode", &self.ballot_mode)?);
        out.extend_from_slice(&hex32_le("enc_x", &self.enc_x)?);
        out.extend_from_slice(&hex32_le("enc_y", &self.enc_y)?);
        out.extend_from_slice(&self.census_origin.to_le_bytes());
        out.extend_from_slice(&hex32_le("census_root", &self.census_root)?);
        out.extend_from_slice(&hex32_le("ballot_vk_hash", &self.ballot_vk_hash)?);
        Ok(out)
    }
}

// Minimal bincode mirrors of ZisK's `common::proof::Proof`. Only the layout
// matters; see upstream `common/src/proof.rs` (v0.18.0).

#[derive(Debug, Serialize, Deserialize)]
struct ProgramVK {
    vk: Vec<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PublicValues {
    data: Vec<u8>,
    #[serde(skip)]
    _cursor: (),
}

#[derive(Debug, Serialize, Deserialize)]
struct PlonkVkey {
    protocol: String,
    curve: String,
    #[serde(rename = "nPublic")]
    n_public: u32,
    power: u32,
    k1: String,
    k2: String,
    #[serde(rename = "Qm")] qm: [String; 3],
    #[serde(rename = "Ql")] ql: [String; 3],
    #[serde(rename = "Qr")] qr: [String; 3],
    #[serde(rename = "Qo")] qo: [String; 3],
    #[serde(rename = "Qc")] qc: [String; 3],
    #[serde(rename = "S1")] s1: [String; 3],
    #[serde(rename = "S2")] s2: [String; 3],
    #[serde(rename = "S3")] s3: [String; 3],
    #[serde(rename = "X_2")] x_2: [[String; 2]; 3],
    w: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PlonkVkBlob {
    vadcop_vk: Vec<u64>,
    plonk_vkey: PlonkVkey,
}

#[derive(Debug, Serialize, Deserialize)]
enum ProofBody {
    Vadcop {
        proof: Vec<u64>,
        zisk_vk: Vec<u64>,
        minimal: bool,
    },
    Plonk {
        proof_bytes: Vec<u8>,
        plonk_vk: Box<PlonkVkBlob>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct Proof {
    body: ProofBody,
    publics: PublicValues,
    program_vk: ProgramVK,
}

/// A vadcop proof blob ready for in-guest verification, plus the metadata
/// the aggregator's caller needs for vk binding.
#[derive(Debug, Clone)]
pub struct VadcopBlob {
    /// Raw blob bytes in the `get_proof_bytes()` word layout.
    pub bytes: Vec<u8>,
    pub program_vk: [u64; 4],
    pub zisk_vk: [u64; 4],
    /// The inner guest's 64 u32 output registers.
    pub publics: [u32; 64],
}

/// Convert a bincode `proof.bin` (Vadcop STARK body) into a [`VadcopBlob`].
pub fn vadcop_blob_from_proof_bin(bytes: &[u8]) -> Result<VadcopBlob> {
    let (proof, _): (Proof, _) =
        bincode::serde::decode_from_slice(bytes, bincode::config::standard())
            .map_err(|e| anyhow::anyhow!("bincode-decode proof.bin: {}", e))?;

    let (proof_words, zisk_vk, minimal) = match proof.body {
        ProofBody::Vadcop { proof, zisk_vk, minimal } => (proof, zisk_vk, minimal),
        ProofBody::Plonk { .. } => bail!("proof.bin holds a PLONK proof; need a Vadcop STARK"),
    };

    if proof.program_vk.vk.len() != PROGRAM_VK_LEN {
        bail!("bad program_vk len {}", proof.program_vk.vk.len());
    }
    if zisk_vk.len() != PROGRAM_VK_LEN {
        bail!("bad zisk_vk len {}", zisk_vk.len());
    }
    if proof.publics.data.len() != ZISK_PUBLICS * 4 {
        bail!("bad publics len {}", proof.publics.data.len());
    }

    let mut publics = [0u32; ZISK_PUBLICS];
    for (i, c) in proof.publics.data.chunks_exact(4).enumerate() {
        publics[i] = u32::from_le_bytes(c.try_into().unwrap());
    }

    let n_publics = PROGRAM_VK_LEN + ZISK_PUBLICS;
    let mut words: Vec<u64> =
        Vec::with_capacity(2 + n_publics + proof_words.len() + zisk_vk.len());
    words.push(minimal as u64);
    words.push(n_publics as u64);
    words.extend_from_slice(&proof.program_vk.vk);
    words.extend(publics.iter().map(|&p| p as u64));
    words.extend_from_slice(&proof_words);
    words.extend_from_slice(&zisk_vk);

    let mut out = Vec::with_capacity(words.len() * 8);
    for w in &words {
        out.extend_from_slice(&w.to_le_bytes());
    }

    Ok(VadcopBlob {
        bytes: out,
        program_vk: proof.program_vk.vk.try_into().unwrap(),
        zisk_vk: zisk_vk.try_into().unwrap(),
        publics,
    })
}

/// `read_input_slice` framing: u64 LE length prefix + data padded to 8 bytes.
fn frame(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    out.extend_from_slice(data);
    while !out.len().is_multiple_of(8) {
        out.push(0);
    }
}

/// Assemble the full aggregator guest input for one fold step.
/// `prev_blob` is `None` for the genesis fold (step 0).
pub fn build_fold_input(
    config: &ChainConfig,
    batch_vk: [u64; 4],
    fold_vk: [u64; 4],
    prev_blob: Option<&[u8]>,
    batch_blobs: &[Vec<u8>],
) -> Result<Vec<u8>> {
    let mut header = Vec::with_capacity(12 * 8);
    for w in [
        AGG_MAGIC,
        MODE_FOLD,
        prev_blob.is_some() as u64,
        batch_blobs.len() as u64,
    ] {
        header.extend_from_slice(&w.to_le_bytes());
    }
    for w in batch_vk.iter().chain(fold_vk.iter()) {
        header.extend_from_slice(&w.to_le_bytes());
    }

    let mut out = Vec::new();
    frame(&mut out, &header);
    frame(&mut out, &config.encode()?);
    if let Some(p) = prev_blob {
        frame(&mut out, p);
    }
    for b in batch_blobs {
        frame(&mut out, b);
    }
    Ok(out)
}

/// Decrypted-results payload for the finalize step. All 32-byte fields are
/// little-endian hex (arbo/FrRaw convention, same as [`ChainConfig`]). Ballot
/// coordinates are Twisted Edwards, ciphertext order
/// `[c1x, c1y, c2x, c2y] x 16`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultsPayload {
    /// Net Results accumulator (state key 0x04): 64 TE coordinates.
    pub ballot: Vec<String>,
    /// Claimed plaintexts of the net accumulator.
    pub results: Vec<u64>,
    /// 16 Chaum-Pedersen proofs, one per ciphertext.
    pub cp_proofs: Vec<CpProofJson>,
    /// Inclusion siblings for the Results leaf, root→leaf, zero-padded.
    pub siblings: Vec<String>,
}

/// One Chaum-Pedersen decryption proof (TE coordinates, LE hex).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpProofJson {
    pub a1x: String,
    pub a1y: String,
    pub a2x: String,
    pub a2y: String,
    pub z: String,
}

impl ResultsPayload {
    /// Encode to the guest results frame (see circuit-aggregator main.rs).
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.ballot.len() != 64 {
            bail!("ballot must have 64 coordinates");
        }
        if self.results.len() != 16 {
            bail!("results must have 16 values");
        }
        if self.cp_proofs.len() != 16 {
            bail!("expected 16 CP proofs, got {}", self.cp_proofs.len());
        }
        if self.siblings.is_empty() {
            bail!("sibling list must be non-empty");
        }
        let n_levels = self.siblings.len();
        let mut out = Vec::with_capacity(2048 + 128 + 16 * 160 + 8 + n_levels * 32);
        for (i, c) in self.ballot.iter().enumerate() {
            out.extend_from_slice(&hex32_le(&format!("ballot[{}]", i), c)?);
        }
        for r in self.results.iter() {
            out.extend_from_slice(&r.to_le_bytes());
        }
        for (i, p) in self.cp_proofs.iter().enumerate() {
            for (f, v) in [("a1x", &p.a1x), ("a1y", &p.a1y), ("a2x", &p.a2x), ("a2y", &p.a2y), ("z", &p.z)] {
                out.extend_from_slice(&hex32_le(&format!("cp[{}].{}", i, f), v)?);
            }
        }
        out.extend_from_slice(&(n_levels as u64).to_le_bytes());
        for (i, s) in self.siblings.iter().enumerate() {
            out.extend_from_slice(&hex32_le(&format!("siblings[{}]", i), s)?);
        }
        Ok(out)
    }
}

/// Assemble the full aggregator guest input for the finalize step.
pub fn build_finalize_input(
    config: &ChainConfig,
    batch_vk: [u64; 4],
    fold_vk: [u64; 4],
    prev_blob: &[u8],
    results: &ResultsPayload,
) -> Result<Vec<u8>> {
    let mut header = Vec::with_capacity(12 * 8);
    for w in [AGG_MAGIC, MODE_FINALIZE, 1u64, 0u64] {
        header.extend_from_slice(&w.to_le_bytes());
    }
    for w in batch_vk.iter().chain(fold_vk.iter()) {
        header.extend_from_slice(&w.to_le_bytes());
    }

    let mut out = Vec::new();
    frame(&mut out, &header);
    frame(&mut out, &config.encode()?);
    frame(&mut out, prev_blob);
    frame(&mut out, &results.encode()?);
    Ok(out)
}

/// Parse a committed 53-word aggregator digest (212 bytes LE).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggDigest {
    pub mode: u32,
    pub step_count: u32,
    pub total_voters: u32,
    pub total_overwrites: u32,
    pub config_commitment: [u32; 8],
    pub state_root: [u32; 8],
    pub batch_vk: [u64; 4],
    pub fold_vk: [u64; 4],
    pub results: [u32; 16],
}

pub fn parse_agg_digest(bytes: &[u8]) -> Result<AggDigest> {
    if bytes.len() < 53 * 4 {
        bail!("digest too short: {} bytes", bytes.len());
    }
    let w: Vec<u32> = bytes[..53 * 4]
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
        .collect();
    if w[0] != u32::from_le_bytes(*b"DAG1") {
        bail!("bad digest magic {:#x}", w[0]);
    }
    let u32x8 = |off: usize| -> [u32; 8] { w[off..off + 8].try_into().unwrap() };
    let u64x4 = |off: usize| -> [u64; 4] {
        let mut v = [0u64; 4];
        for i in 0..4 {
            v[i] = w[off + i * 2] as u64 | ((w[off + i * 2 + 1] as u64) << 32);
        }
        v
    };
    let mut results = [0u32; 16];
    for i in 0..16 {
        results[i] = w[37 + i];
    }
    Ok(AggDigest {
        mode: w[1],
        step_count: w[2],
        total_voters: w[3],
        total_overwrites: w[4],
        config_commitment: u32x8(5),
        state_root: u32x8(13),
        batch_vk: u64x4(21),
        fold_vk: u64x4(29),
        results,
    })
}
