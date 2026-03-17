//! Input generation for davinci-zkvm.
//!
//! This crate encodes the active davinci-stark ballot proof path plus the
//! ecgfp5-native state-transition and re-encryption payloads into the binary
//! format expected by the `davinci-zkvm-circuit` guest program.

pub mod stark_types;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::stark_types::{StarkProofBundle, STARK_PUBLIC_VALUE_COUNT};

const STARK_MAGIC: u64 = u64::from_le_bytes(*b"DSTARKB!");
const STATE_G5_MAGIC: u64 = u64::from_le_bytes(*b"STAG5TX!");
const REENC_G5_MAGIC: u64 = u64::from_le_bytes(*b"REG5BLK!");
const CENSUS_MAGIC: u64 = u64::from_le_bytes(*b"CENSUS!!");
const KZG_MAGIC: u64 = u64::from_le_bytes(*b"KZGBLK!!");
const CSP_MAGIC: u64 = u64::from_le_bytes(*b"CSPBLK!!");

pub const DEFAULT_MAX_BATCH_SIZE: usize = 128;

const fn parse_max_batch_size_ascii(raw: &str) -> Option<usize> {
    let bytes = raw.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let mut value = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if b < b'0' || b > b'9' {
            return None;
        }
        value = value.saturating_mul(10).saturating_add((b - b'0') as usize);
        i += 1;
    }
    if value >= 2 && value.is_power_of_two() {
        Some(value)
    } else {
        None
    }
}

const fn configured_max_batch_size(raw: Option<&str>) -> usize {
    match raw {
        Some(s) => match parse_max_batch_size_ascii(s) {
            Some(v) => v,
            None => DEFAULT_MAX_BATCH_SIZE,
        },
        None => DEFAULT_MAX_BATCH_SIZE,
    }
}

pub const MAX_BATCH_SIZE: usize = configured_max_batch_size(option_env!("DAVINCI_MAX_BATCH_SIZE"));

#[derive(Debug, Clone)]
pub struct SmtEntry {
    pub old_root: [u64; 4],
    pub new_root: [u64; 4],
    pub old_key: [u64; 4],
    pub old_value: [u64; 4],
    pub is_old0: bool,
    pub new_key: [u64; 4],
    pub new_value: [u64; 4],
    pub fnc0: bool,
    pub fnc1: bool,
    pub siblings: Vec<[u64; 4]>,
}

pub fn hex32_to_smt_fr(s: &str) -> Result<[u64; 4]> {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(hex).with_context(|| format!("invalid hex: {}", s))?;
    if bytes.len() != 32 {
        bail!("expected 32-byte hex, got {} bytes: {}", bytes.len(), s);
    }
    let mut out = [0u64; 4];
    for i in 0..4 {
        out[i] = u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap());
    }
    Ok(out)
}

#[derive(Debug, Clone, Default)]
pub struct StateData {
    pub n_voters: u64,
    pub n_overwritten: u64,
    pub process_id: [u64; 4],
    pub old_state_root: [u64; 4],
    pub new_state_root: [u64; 4],
    pub vote_id_chain: Vec<SmtEntry>,
    pub ballot_chain: Vec<SmtEntry>,
    pub results_add: Option<SmtEntry>,
    pub results_sub: Option<SmtEntry>,
    pub process_proofs: Vec<SmtEntry>,
    pub ecgfp5_ballot_proof_data: Option<Ecgfp5BallotProofData>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Ecgfp5CiphertextData {
    pub c1: [u64; 5],
    pub c2: [u64; 5],
}

#[derive(Debug, Clone)]
pub struct Ecgfp5BallotProofData {
    pub old_results_add: [Ecgfp5CiphertextData; 8],
    pub old_results_sub: [Ecgfp5CiphertextData; 8],
    pub voter_ballots: Vec<[Ecgfp5CiphertextData; 8]>,
    pub overwritten_ballots: Vec<[Ecgfp5CiphertextData; 8]>,
}

pub fn write_state_block(sd: &StateData) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&STATE_G5_MAGIC.to_le_bytes());
    buf.extend_from_slice(&sd.n_voters.to_le_bytes());
    buf.extend_from_slice(&sd.n_overwritten.to_le_bytes());
    write_u64_slice(&mut buf, &sd.process_id);
    write_u64_slice(&mut buf, &sd.old_state_root);
    write_u64_slice(&mut buf, &sd.new_state_root);

    write_smt_chain(&mut buf, &sd.vote_id_chain)?;
    write_smt_chain(&mut buf, &sd.ballot_chain)?;
    write_optional_smt(&mut buf, sd.results_add.as_ref())?;

    let results_n_levels = sd
        .results_add
        .as_ref()
        .map(|r| r.siblings.len())
        .or_else(|| sd.results_sub.as_ref().map(|r| r.siblings.len()))
        .unwrap_or(0);
    buf.extend_from_slice(&(sd.results_sub.is_some() as u64).to_le_bytes());
    if let Some(r) = &sd.results_sub {
        if r.siblings.len() != results_n_levels && results_n_levels > 0 {
            bail!(
                "results_sub sibling count {} != results_add {}",
                r.siblings.len(),
                results_n_levels
            );
        }
        write_smt_entry_body(&mut buf, r);
    }

    if !sd.process_proofs.is_empty() && sd.process_proofs.len() != 4 {
        bail!(
            "process_proofs must have exactly 4 entries, got {}",
            sd.process_proofs.len()
        );
    }
    buf.extend_from_slice(&(sd.process_proofs.len() as u64).to_le_bytes());
    if !sd.process_proofs.is_empty() {
        let proc_n_levels = sd.process_proofs[0].siblings.len();
        buf.extend_from_slice(&(proc_n_levels as u64).to_le_bytes());
        for p in &sd.process_proofs {
            if p.siblings.len() != proc_n_levels {
                bail!("process proof sibling count mismatch");
            }
            write_smt_entry_body(&mut buf, p);
        }
    }

    if let Some(bp) = &sd.ecgfp5_ballot_proof_data {
        buf.extend_from_slice(&1u64.to_le_bytes());
        for ct in &bp.old_results_add {
            write_u64_slice(&mut buf, &ct.c1);
            write_u64_slice(&mut buf, &ct.c2);
        }
        for ct in &bp.old_results_sub {
            write_u64_slice(&mut buf, &ct.c1);
            write_u64_slice(&mut buf, &ct.c2);
        }
        buf.extend_from_slice(&(bp.voter_ballots.len() as u64).to_le_bytes());
        for ballot in &bp.voter_ballots {
            for ct in ballot {
                write_u64_slice(&mut buf, &ct.c1);
                write_u64_slice(&mut buf, &ct.c2);
            }
        }
        buf.extend_from_slice(&(bp.overwritten_ballots.len() as u64).to_le_bytes());
        for ballot in &bp.overwritten_ballots {
            for ct in ballot {
                write_u64_slice(&mut buf, &ct.c1);
                write_u64_slice(&mut buf, &ct.c2);
            }
        }
    } else {
        buf.extend_from_slice(&0u64.to_le_bytes());
    }

    Ok(buf)
}

fn write_smt_chain(buf: &mut Vec<u8>, entries: &[SmtEntry]) -> Result<()> {
    let n = entries.len() as u64;
    let n_levels = entries.first().map(|e| e.siblings.len()).unwrap_or(0);
    for (i, e) in entries.iter().enumerate() {
        if e.siblings.len() != n_levels {
            bail!(
                "chain entry {} has {} siblings, expected {}",
                i,
                e.siblings.len(),
                n_levels
            );
        }
    }
    buf.extend_from_slice(&n.to_le_bytes());
    buf.extend_from_slice(&(n_levels as u64).to_le_bytes());
    for e in entries {
        write_smt_entry_body(buf, e);
    }
    Ok(())
}

fn write_optional_smt(buf: &mut Vec<u8>, entry: Option<&SmtEntry>) -> Result<()> {
    let has = entry.is_some();
    let n_levels = entry.map(|e| e.siblings.len()).unwrap_or(0);
    buf.extend_from_slice(&(has as u64).to_le_bytes());
    buf.extend_from_slice(&(n_levels as u64).to_le_bytes());
    if let Some(e) = entry {
        write_smt_entry_body(buf, e);
    }
    Ok(())
}

fn write_smt_entry_body(buf: &mut Vec<u8>, e: &SmtEntry) {
    write_u64_slice(buf, &e.old_root);
    write_u64_slice(buf, &e.new_root);
    write_u64_slice(buf, &e.old_key);
    write_u64_slice(buf, &e.old_value);
    buf.extend_from_slice(&(e.is_old0 as u64).to_le_bytes());
    write_u64_slice(buf, &e.new_key);
    write_u64_slice(buf, &e.new_value);
    buf.extend_from_slice(&(e.fnc0 as u64).to_le_bytes());
    buf.extend_from_slice(&(e.fnc1 as u64).to_le_bytes());
    for sib in &e.siblings {
        write_u64_slice(buf, sib);
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct EcdsaSig {
    pub public_key_x: String,
    pub public_key_y: String,
    pub signature_r: String,
    pub signature_s: String,
    pub vote_id: u64,
    pub address: String,
    #[serde(default)]
    pub private_key: String,
    #[serde(default)]
    pub signature_v: u8,
}

fn write_u64_slice(buf: &mut Vec<u8>, words: &[u64]) {
    for w in words {
        buf.extend_from_slice(&w.to_le_bytes());
    }
}

fn pad_to_u64_boundary(buf: &mut Vec<u8>) {
    let rem = buf.len() % 8;
    if rem != 0 {
        buf.resize(buf.len() + (8 - rem), 0);
    }
}

/// Wrap a raw guest payload into the outer ZisK input framing expected by
/// `ziskos::io::read_input_slice()`:
/// `[payload_len(u64) | payload_bytes | zero padding to 8-byte boundary]`.
pub fn wrap_for_zisk_vm(payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + payload.len() + 7);
    buf.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    buf.extend_from_slice(payload);
    pad_to_u64_boundary(&mut buf);
    buf
}

fn hex32_to_u64x4(s: &str) -> Result<[u64; 4]> {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(hex).with_context(|| format!("invalid hex: {}", s))?;
    if bytes.len() != 32 {
        bail!("expected 32-byte hex, got {} bytes: {}", bytes.len(), s);
    }
    let mut out = [0u64; 4];
    for i in 0..4 {
        let start = 24 - i * 8;
        out[i] = u64::from_be_bytes(bytes[start..start + 8].try_into().unwrap());
    }
    Ok(out)
}

pub fn generate_stark_input(bundles: &[StarkProofBundle], sigs: &[EcdsaSig]) -> Result<Vec<u8>> {
    generate_stark_input_inner(bundles, sigs, false)
}

/// Generate input with proof bytes stripped (aggregated mode).
///
/// When the service uses Plonky3-recursion to aggregate ballot proofs,
/// the individual proof bytes are omitted from the guest input. The guest
/// skips STARK verification and only processes public values + other checks.
/// The aggregated batch-stark proof is verified externally.
pub fn generate_stark_input_aggregated(
    bundles: &[StarkProofBundle],
    sigs: &[EcdsaSig],
) -> Result<Vec<u8>> {
    generate_stark_input_inner(bundles, sigs, true)
}

fn generate_stark_input_inner(
    bundles: &[StarkProofBundle],
    sigs: &[EcdsaSig],
    strip_proof_bytes: bool,
) -> Result<Vec<u8>> {
    let num_proofs = bundles.len();
    if num_proofs < 2 || !num_proofs.is_power_of_two() || num_proofs > MAX_BATCH_SIZE {
        bail!(
            "num_proofs ({}) must be a power of two between 2 and {} (MAX_BATCH_SIZE)",
            num_proofs,
            MAX_BATCH_SIZE
        );
    }
    if sigs.len() != num_proofs {
        bail!(
            "sigs length ({}) must equal num_proofs ({})",
            sigs.len(),
            num_proofs
        );
    }
    let log_n = (num_proofs as f64).log2() as u64;
    let mut buf = Vec::new();
    write_u64_slice(
        &mut buf,
        &[
            STARK_MAGIC,
            log_n,
            num_proofs as u64,
            STARK_PUBLIC_VALUE_COUNT as u64,
        ],
    );
    for bundle in bundles {
        if strip_proof_bytes {
            // Zero-length proof block: the guest will skip STARK verification.
            write_u64_slice(&mut buf, &[0u64]);
        } else {
            write_u64_slice(&mut buf, &[bundle.proof_bytes.len() as u64]);
            buf.extend_from_slice(&bundle.proof_bytes);
            pad_to_u64_boundary(&mut buf);
        }
        for limb in bundle.public_values.as_u64_vec() {
            write_u64_slice(&mut buf, &[limb]);
        }
    }
    for sig in sigs {
        write_u64_slice(&mut buf, &hex32_to_u64x4(&sig.signature_r)?);
        write_u64_slice(&mut buf, &hex32_to_u64x4(&sig.signature_s)?);
        write_u64_slice(&mut buf, &hex32_to_u64x4(&sig.public_key_x)?);
        write_u64_slice(&mut buf, &hex32_to_u64x4(&sig.public_key_y)?);
    }
    Ok(buf)
}

pub struct CensusProofData {
    pub root: [u64; 4],
    pub leaf: [u64; 4],
    pub index: u64,
    pub siblings: Vec<[u64; 4]>,
}

pub fn write_census_block(proofs: &[CensusProofData]) -> Result<Vec<u8>> {
    if proofs.is_empty() {
        return Ok(Vec::new());
    }
    let mut buf = Vec::with_capacity(8 + 8 + proofs.len() * (32 + 32 + 8 + 8));
    buf.extend_from_slice(&CENSUS_MAGIC.to_le_bytes());
    buf.extend_from_slice(&(proofs.len() as u64).to_le_bytes());
    for p in proofs {
        write_u64_slice(&mut buf, &p.root);
        write_u64_slice(&mut buf, &p.leaf);
        buf.extend_from_slice(&p.index.to_le_bytes());
        buf.extend_from_slice(&(p.siblings.len() as u64).to_le_bytes());
        for s in &p.siblings {
            write_u64_slice(&mut buf, s);
        }
    }
    Ok(buf)
}

pub fn census_proof_from_hex(
    root: &str,
    leaf: &str,
    index: u64,
    siblings: &[String],
) -> Result<CensusProofData> {
    let root = hex32_to_u64x4(root)?;
    let leaf = hex32_to_u64x4(leaf)?;
    let mut sibs = Vec::with_capacity(siblings.len());
    for s in siblings {
        sibs.push(hex32_to_u64x4(s)?);
    }
    Ok(CensusProofData {
        root,
        leaf,
        index,
        siblings: sibs,
    })
}

pub struct Ecgfp5ReencEntryData {
    pub k: [u64; 5],
    pub original: [Ecgfp5CiphertextData; 8],
    pub reencrypted: [Ecgfp5CiphertextData; 8],
}

pub fn write_reenc_block_g5(
    encryption_key: [u64; 5],
    entries: &[Ecgfp5ReencEntryData],
) -> Result<Vec<u8>> {
    if entries.is_empty() {
        return Ok(Vec::new());
    }
    let mut buf = Vec::new();
    buf.extend_from_slice(&REENC_G5_MAGIC.to_le_bytes());
    buf.extend_from_slice(&(entries.len() as u64).to_le_bytes());
    write_u64_slice(&mut buf, &encryption_key);
    for e in entries {
        write_u64_slice(&mut buf, &e.k);
        for ct in &e.original {
            write_u64_slice(&mut buf, &ct.c1);
            write_u64_slice(&mut buf, &ct.c2);
        }
        for ct in &e.reencrypted {
            write_u64_slice(&mut buf, &ct.c1);
            write_u64_slice(&mut buf, &ct.c2);
        }
    }
    Ok(buf)
}

pub struct KzgData {
    pub process_id: [u64; 4],
    pub root_hash_before: [u64; 4],
    pub commitment: [u8; 48],
    pub y_claimed: [u8; 32],
    pub blob: Vec<u8>,
}

pub fn write_kzg_block(d: &KzgData) -> Result<Vec<u8>> {
    if d.blob.len() != 4096 * 32 {
        bail!("blob must be exactly 131072 bytes, got {}", d.blob.len());
    }
    let mut buf = Vec::with_capacity(8 + 32 + 32 + 48 + 32 + 4096 * 32);
    buf.extend_from_slice(&KZG_MAGIC.to_le_bytes());
    write_u64_slice(&mut buf, &d.process_id);
    write_u64_slice(&mut buf, &d.root_hash_before);
    buf.extend_from_slice(&d.commitment);
    buf.extend_from_slice(&d.y_claimed);
    buf.extend_from_slice(&d.blob);
    Ok(buf)
}

pub fn be_hex32_to_fr_le(s: &str) -> Result<[u64; 4]> {
    let hex = s.trim_start_matches("0x");
    let bytes = hex::decode(hex).with_context(|| format!("invalid hex: {s}"))?;
    if bytes.len() > 32 {
        bail!("value too large: {} bytes (max 32)", bytes.len());
    }
    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok([
        u64::from_be_bytes(padded[24..32].try_into().unwrap()),
        u64::from_be_bytes(padded[16..24].try_into().unwrap()),
        u64::from_be_bytes(padded[8..16].try_into().unwrap()),
        u64::from_be_bytes(padded[0..8].try_into().unwrap()),
    ])
}

#[derive(Debug, Clone)]
pub struct CspEntryData {
    pub r: [u64; 4],
    pub s: [u64; 4],
    pub voter_address: [u64; 4],
    pub weight: [u64; 4],
    pub index: u64,
}

#[derive(Debug, Clone)]
pub struct CspBlockData {
    pub csp_pub_key_x: [u64; 4],
    pub csp_pub_key_y: [u64; 4],
    pub entries: Vec<CspEntryData>,
}

pub fn write_csp_block(data: &CspBlockData) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&CSP_MAGIC.to_le_bytes());
    buf.extend_from_slice(&(data.entries.len() as u64).to_le_bytes());
    write_u64_slice(&mut buf, &data.csp_pub_key_x);
    write_u64_slice(&mut buf, &data.csp_pub_key_y);
    for entry in &data.entries {
        write_u64_slice(&mut buf, &entry.r);
        write_u64_slice(&mut buf, &entry.s);
        write_u64_slice(&mut buf, &entry.voter_address);
        write_u64_slice(&mut buf, &entry.weight);
        buf.extend_from_slice(&entry.index.to_le_bytes());
    }
    Ok(buf)
}

pub fn address_hex_to_fr_le(s: &str) -> Result<[u64; 4]> {
    let hex = s.trim_start_matches("0x");
    let bytes = hex::decode(hex).with_context(|| format!("invalid address hex: {s}"))?;
    if bytes.len() != 20 {
        bail!("expected 20 bytes for address, got {}: {}", bytes.len(), s);
    }
    let mut padded = [0u8; 32];
    padded[12..].copy_from_slice(&bytes);
    Ok([
        u64::from_be_bytes(padded[24..32].try_into().unwrap()),
        u64::from_be_bytes(padded[16..24].try_into().unwrap()),
        u64::from_be_bytes(padded[8..16].try_into().unwrap()),
        u64::from_be_bytes(padded[0..8].try_into().unwrap()),
    ])
}

#[cfg(test)]
mod tests {
    use super::{
        configured_max_batch_size, generate_stark_input, parse_max_batch_size_ascii,
        wrap_for_zisk_vm,
        stark_types::{StarkProofBundle, StarkPublicValues},
        EcdsaSig, DEFAULT_MAX_BATCH_SIZE,
    };

    #[test]
    fn parse_max_batch_size_accepts_power_of_two() {
        assert_eq!(parse_max_batch_size_ascii("256"), Some(256));
    }

    #[test]
    fn parse_max_batch_size_rejects_non_power_of_two() {
        assert_eq!(parse_max_batch_size_ascii("192"), None);
    }

    #[test]
    fn configured_max_batch_size_falls_back_to_default() {
        assert_eq!(configured_max_batch_size(Some("bad")), DEFAULT_MAX_BATCH_SIZE);
    }

    #[test]
    fn generated_stark_input_is_u64_aligned() {
        let bundle = StarkProofBundle {
            proof_bytes: vec![1, 2, 3, 4, 5],
            public_values: StarkPublicValues {
                inputs_hash: [11, 12, 13, 14],
                address: [15, 16, 17, 18],
                vote_id: 19,
                inputs_preimage: [20; 114],
            },
        };
        let sig = EcdsaSig {
            public_key_x: format!("0x{:064x}", 0),
            public_key_y: format!("0x{:064x}", 0),
            signature_r: format!("0x{:064x}", 0),
            signature_s: format!("0x{:064x}", 0),
            vote_id: 19,
            address: "0".to_string(),
            private_key: String::new(),
            signature_v: 0,
        };
        let input = generate_stark_input(&[bundle.clone(), bundle], &[sig.clone(), sig]).unwrap();
        assert_eq!(input.len() % 8, 0);
    }

    #[test]
    fn wrapped_zisk_input_has_outer_length_prefix() {
        let payload = b"DSTARKB!";
        let framed = wrap_for_zisk_vm(payload);
        assert_eq!(framed.len() % 8, 0);
        assert_eq!(u64::from_le_bytes(framed[0..8].try_into().unwrap()), payload.len() as u64);
        assert_eq!(&framed[8..16], payload);
    }
}
