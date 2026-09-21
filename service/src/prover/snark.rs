//! Decode the bincode-encoded `proof.bin` produced by ZisK into the four
//! byte strings the on-chain `ZiskVerifier.verifySnarkProof` consumes:
//!
//! ```solidity
//! function verifySnarkProof(
//!     bytes32 programVK,
//!     bytes32 rootCVadcopFinal,
//!     bytes  publicValues,
//!     bytes  proofBytes
//! ) external view;
//! ```
//!
//! The on-chain verifier hashes `programVK || publicValues ||
//! rootCVadcopFinal` with SHA-256, reduces the digest modulo the BN254
//! scalar field, and feeds the resulting scalar to the bare PLONK verifier
//! together with `abi.decode(proofBytes, (uint256[24]))`. All four values
//! are present in `proof.bin`; this module pulls them out with `bincode`
//! and serde so no ZisK tooling is needed at consumption time.
//!
//! `publicValues` is NOT the guest's raw u32 output. Since ZisK 1.3 the final
//! circom circuit hashes each of the 64 publics as a 64-bit little-endian
//! word (`snark_inputs_bytes` in upstream `common/src/proof.rs`), so the byte
//! string the contract must hash is 512 bytes. The 256-byte u32 view is kept
//! separately for `publics.bin` and the digest parsers.
//!
//! ## Wire format
//!
//! `proof.bin` is the `bincode::serde::encode` output of ZisK's
//! `common::proof::Proof { body: ProofBody::Plonk { proof_bytes, plonk_vk },
//! publics, program_vk }`. We mirror only the subset of those types needed
//! to deserialize the PLONK variant; the file format is documented in
//! upstream's `common/src/proof.rs`.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Number of publics ZisK reserves for the program's `commit_slice` output.
const ZISK_PUBLICS: usize = 64;
/// Length of the program (ROM) verification key in `u64` words.
const PROGRAM_VK_LEN: usize = 4;
/// Size of the on-chain `publicValues` string: each public as 8 LE bytes.
const PUBLIC_VALUES_LEN: usize = ZISK_PUBLICS * 8;
/// Size of the ABI-encoded `uint256[24]` PLONK proof payload, in bytes.
const PROOF_BYTES_LEN: usize = 24 * 32;

/// Mirror of upstream `HashMode`. Variant order fixes the bincode tag.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
enum HashMode {
    Poseidon1,
    Poseidon2,
    Blake3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProgramVK {
    vk: Vec<u64>,
    hash_mode: HashMode,
}

/// Mirror of upstream `VadcopKind`. Variant order fixes the bincode tag.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
enum VadcopKind {
    Final,
    Recurser,
    Minimal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PublicValues {
    data: Vec<u8>,
    // The upstream struct stores an AtomicUsize cursor here; we deserialize
    // it as `()` because bincode treats serde-skipped fields as zero-sized.
    #[serde(skip)]
    _cursor: (),
}

/// Mirror of upstream's snarkjs PLONK vkey JSON, present in `proof.bin` so a
/// consumer can verify off-chain without external files. We do not touch
/// any field; bincode just needs the layout to walk past it.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PlonkVkBlob {
    vadcop_vk: Vec<u64>,
    plonk_vkey: PlonkVkey,
}

/// Variants must match the upstream `ProofBody` enum in the same order so
/// that bincode's tag discriminants line up.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum ProofBody {
    Vadcop {
        proof: Vec<u64>,
        zisk_vk: Vec<u64>,
        kind: VadcopKind,
        hash: String,
        publics_full: Vec<u64>,
    },
    Plonk {
        proof_bytes: Vec<u8>,
        plonk_vk: Box<PlonkVkBlob>,
        publics: PublicValues,
        publics_full: Vec<u64>,
        rootc: Vec<u64>,
    },
}

/// ZisK 1.3 moved `publics` out of `Proof` and into the body variants.
#[derive(Debug, Serialize, Deserialize)]
struct Proof {
    body: ProofBody,
    program_vk: ProgramVK,
}

/// On-chain-ready PLONK SNARK payload extracted from `proof.bin`. All four
/// fields are `0x`-prefixed hex strings so they drop straight into a
/// `cast call …` invocation or an ABI packer without further conversion.
#[derive(Debug, Clone, Serialize)]
pub struct SnarkArtifact {
    /// `bytes32 programVK` — the program (ROM) verification key.
    pub program_vk: String,
    /// `bytes32 rootCVadcopFinal` — the VADCOP-final commitment root for
    /// the current ZisK setup. Equal to the constant returned by
    /// `ZiskVerifier.getRootCVadcopFinal()`; we include it here so the
    /// SNARK payload is fully self-contained.
    pub root_c_vadcop_final: String,
    /// `bytes publicValues` — the 64 publics as 8-byte little-endian words
    /// (512 bytes), the exact string the on-chain verifier hashes.
    pub public_values: String,
    /// `bytes proofBytes` — the PLONK proof, already ABI-encoded as
    /// `uint256[24]` (768 bytes), exactly what `verifySnarkProof` expects.
    pub proof_bytes: String,
    /// The guest's `commit_slice` output as 64 LE `u32`s (256 bytes). Not
    /// part of the on-chain payload; the worker persists it as `publics.bin`
    /// for `GET /jobs/{id}/publics` and the chained-mode digest parsers.
    #[serde(skip)]
    pub program_publics: Vec<u8>,
}

/// Decode `<job_dir>/proof.bin` from disk into a [`SnarkArtifact`].
pub fn parse_proof_bin(path: &Path) -> Result<SnarkArtifact> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("read proof file at {}", path.display()))?;
    parse_proof_bytes(&bytes)
}

/// Decode a raw `proof.bin` byte buffer into a [`SnarkArtifact`].
pub fn parse_proof_bytes(bytes: &[u8]) -> Result<SnarkArtifact> {
    let (proof, _): (Proof, _) =
        bincode::serde::decode_from_slice(bytes, bincode::config::standard())
            .map_err(|e| anyhow!("bincode-decode proof.bin: {}", e))?;

    // ZisK 1.3 stamps the rootCVadcopFinal that went into `publicsHash` in the
    // body (the vadcop_final verkey for a plain proof, the recurser verkey for
    // an aggregated one). Use it rather than plonk_vk.vadcop_vk, which is only
    // the same value in the plain case.
    let (proof_bytes, vadcop_vk, publics, publics_full) = match proof.body {
        ProofBody::Plonk { proof_bytes, publics, rootc, publics_full, .. } => {
            (proof_bytes, rootc, publics, publics_full)
        }
        ProofBody::Vadcop { .. } => bail!(
            "proof.bin is a Vadcop STARK proof, not a PLONK SNARK; the service must run \
             cargo-zisk prove with --plonk"
        ),
    };

    if proof.program_vk.vk.len() != PROGRAM_VK_LEN {
        bail!(
            "program_vk: expected {} u64 words, got {}",
            PROGRAM_VK_LEN,
            proof.program_vk.vk.len()
        );
    }
    if vadcop_vk.len() != PROGRAM_VK_LEN {
        bail!(
            "vadcop_vk: expected {} u64 words, got {}",
            PROGRAM_VK_LEN,
            vadcop_vk.len()
        );
    }
    if publics.data.len() != ZISK_PUBLICS * 4 {
        bail!(
            "publics: expected {} bytes, got {}",
            ZISK_PUBLICS * 4,
            publics.data.len()
        );
    }
    if proof_bytes.len() != PROOF_BYTES_LEN {
        bail!(
            "proof_bytes: expected {} bytes (uint256[24]), got {}",
            PROOF_BYTES_LEN,
            proof_bytes.len()
        );
    }
    let public_values = snark_public_values(&publics_full, &proof.program_vk.vk)?;

    Ok(SnarkArtifact {
        program_vk: encode_u64_be_hex(&proof.program_vk.vk),
        root_c_vadcop_final: encode_u64_be_hex(&vadcop_vk),
        public_values: format!("0x{}", hex::encode(&public_values)),
        proof_bytes: format!("0x{}", hex::encode(&proof_bytes)),
        program_publics: publics.data,
    })
}

/// The on-chain `publicValues` string: `publics_full` is `[program_vk(4) |
/// publics(64)]`, optionally led by the recursion-layer flag word, and the
/// circuit hashes each public as 8 little-endian bytes. Mirrors upstream
/// `snark_inputs_bytes`; the vk prefix is checked against `program_vk` so a
/// layout drift fails here rather than on-chain.
fn snark_public_values(publics_full: &[u64], program_vk: &[u64]) -> Result<Vec<u8>> {
    let words = match publics_full.len() {
        n if n == PROGRAM_VK_LEN + ZISK_PUBLICS => publics_full,
        n if n == PROGRAM_VK_LEN + ZISK_PUBLICS + 1 => &publics_full[1..],
        n => bail!(
            "publics_full: expected {} or {} u64 words, got {}",
            PROGRAM_VK_LEN + ZISK_PUBLICS,
            PROGRAM_VK_LEN + ZISK_PUBLICS + 1,
            n
        ),
    };
    if &words[..PROGRAM_VK_LEN] != program_vk {
        bail!("publics_full does not start with program_vk");
    }
    let mut out = Vec::with_capacity(PUBLIC_VALUES_LEN);
    for w in &words[PROGRAM_VK_LEN..] {
        out.extend_from_slice(&w.to_le_bytes());
    }
    Ok(out)
}

/// Pack a slice of `u64` words as a contiguous big-endian byte string and
/// emit it as `0x`-prefixed hex. This is the layout `bytes32` uses on
/// Ethereum.
fn encode_u64_be_hex(words: &[u64]) -> String {
    let mut out = Vec::with_capacity(words.len() * 8);
    for w in words {
        out.extend_from_slice(&w.to_be_bytes());
    }
    format!("0x{}", hex::encode(out))
}
