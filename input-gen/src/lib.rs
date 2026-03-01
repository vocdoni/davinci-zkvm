//! Input generation for davinci-zkvm: Groth16 BN254 proofs → ZisK binary input.
//!
//! This library converts snarkjs-format Groth16 proofs and verification keys
//! into the binary format expected by the `davinci-zkvm-circuit` guest program.

use anyhow::{anyhow, bail, Context, Result};
use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInt as ArkBigInt, Field, PrimeField};
use ark_groth16::{prepare_verifying_key, Groth16, Proof, VerifyingKey};
use ark_snark::SNARK;
use num_bigint::BigUint;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::fs;
use std::path::{Path, PathBuf};

// "GROTH16B" in little-endian ASCII — matches guest magic constant
const MAGIC: u64 = 0x423631484f545247u64;
// "SMTBLK!!" in little-endian ASCII — matches circuit SMT_MAGIC constant
const SMT_MAGIC: u64 = u64::from_le_bytes(*b"SMTBLK!!");
const STATE_MAGIC: u64 = u64::from_le_bytes(*b"STATETX!");

/// One Arbo-compatible SMT state-transition entry for binary encoding.
///
/// All `[u64; 4]` fields use little-endian word order (word[0] = least-significant 64 bits),
/// matching the circuit's `FrRaw` convention.  The values are big-endian 32-byte numbers
/// as understood by Arbo; the circuit converts them internally for SHA-256 hashing.
#[derive(Debug, Clone)]
pub struct SmtEntry {
    pub old_root:  [u64; 4],
    pub new_root:  [u64; 4],
    pub old_key:   [u64; 4],
    pub old_value: [u64; 4],
    /// `true` when the old leaf slot was empty (pure insert into unoccupied position).
    pub is_old0:   bool,
    pub new_key:   [u64; 4],
    pub new_value: [u64; 4],
    /// `true` for insert (or delete when also `fnc1=true`).
    pub fnc0: bool,
    /// `true` for update (or delete when also `fnc0=true`).
    pub fnc1: bool,
    /// Merkle siblings root→leaf, padded to `n_levels` with zeros.
    pub siblings: Vec<[u64; 4]>,
}

/// Encode a slice of SMT transitions into the optional SMT binary block.
///
/// Returns an empty `Vec` if `entries` is empty (no block written).
/// Returns an error if entries have inconsistent sibling counts.
///
/// The returned bytes should be appended to the output of `generate_input`.
pub fn write_smt_block(entries: &[SmtEntry]) -> Result<Vec<u8>> {
    if entries.is_empty() {
        return Ok(Vec::new());
    }
    let n_levels = entries[0].siblings.len();
    for (i, e) in entries.iter().enumerate() {
        if e.siblings.len() != n_levels {
            bail!("SMT entry {} has {} siblings, expected {}", i, e.siblings.len(), n_levels);
        }
    }
    let n_transitions = entries.len();
    // Header: magic(u64) + n_transitions(u64) + n_levels(u64) = 24 bytes
    // Per transition: 4+4+4+4 FrRaw + 1+4+4+1+1 u64 scalars + n_levels FrRaw
    //   = (4*4 + 1+1+1 + n_levels*4) × 8 bytes
    let entry_bytes = (4 * 4 + 5 + n_levels * 4) * 8;
    let mut buf = Vec::with_capacity(24 + n_transitions * entry_bytes);

    buf.extend_from_slice(&SMT_MAGIC.to_le_bytes());
    buf.extend_from_slice(&(n_transitions as u64).to_le_bytes());
    buf.extend_from_slice(&(n_levels as u64).to_le_bytes());

    for e in entries {
        write_smt_entry_body(&mut buf, e);
    }
    Ok(buf)
}

/// Parse a 0x-prefixed 32-byte big-endian hex string into `[u64; 4]` (LE word order).
///
/// Convert a 0x-prefixed **little-endian** hex string to `[u64; 4]` LE words.
/// Arbo stores all values (keys, values, roots, siblings) in little-endian byte
/// order (`BigIntToBytes` = LE), so the hex bytes map directly to LE words.
pub fn hex32_to_smt_fr(s: &str) -> Result<[u64; 4]> {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(hex)
        .with_context(|| format!("invalid hex: {}", s))?;
    if bytes.len() != 32 {
        bail!("expected 32-byte hex, got {} bytes: {}", bytes.len(), s);
    }
    // Input is little-endian (arbo format); words map directly to bytes.
    let mut out = [0u64; 4];
    for i in 0..4 {
        out[i] = u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap());
    }
    Ok(out)
}



/// Full DAVINCI state-transition data for binary serialization.
///
/// Matches the `StateTransitionData` JSON type in go-sdk/types.go.
/// All `[u64;4]` fields use little-endian word order (arbo convention).
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
    /// Exactly 4 read-proofs: processID(0x0), ballotMode(0x2), encKey(0x3), censusOrigin(0x6).
    pub process_proofs: Vec<SmtEntry>,
}

/// Serialize a `StateData` into the STATETX binary block.
///
/// Returns an empty `Vec` if not needed (n_voters==0 and no transitions).
/// All SMT chains are serialized with their own n_levels (inferred from the first entry's siblings).
pub fn write_state_block(sd: &StateData) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&STATE_MAGIC.to_le_bytes());
    buf.extend_from_slice(&sd.n_voters.to_le_bytes());
    buf.extend_from_slice(&sd.n_overwritten.to_le_bytes());
    write_u64_slice(&mut buf, &sd.process_id);
    write_u64_slice(&mut buf, &sd.old_state_root);
    write_u64_slice(&mut buf, &sd.new_state_root);

    // VoteID chain
    write_smt_chain(&mut buf, &sd.vote_id_chain)?;

    // Ballot chain
    write_smt_chain(&mut buf, &sd.ballot_chain)?;

    // ResultsAdd (0 or 1)
    write_optional_smt(&mut buf, sd.results_add.as_ref())?;

    // ResultsSub (0 or 1, same n_levels as resultsAdd)
    let results_n_levels = sd.results_add.as_ref()
        .map(|r| r.siblings.len())
        .or_else(|| sd.results_sub.as_ref().map(|r| r.siblings.len()))
        .unwrap_or(0);
    let has_sub = sd.results_sub.is_some();
    buf.extend_from_slice(&(has_sub as u64).to_le_bytes());
    if let Some(r) = &sd.results_sub {
        if r.siblings.len() != results_n_levels && results_n_levels > 0 {
            bail!("results_sub sibling count {} != results_add {}", r.siblings.len(), results_n_levels);
        }
        write_smt_entry_body(&mut buf, r);
    }

    // Process read-proofs: write n (0 or 4), then n_levels + entries only when n>0.
    if !sd.process_proofs.is_empty() && sd.process_proofs.len() != 4 {
        bail!("process_proofs must have exactly 4 entries, got {}", sd.process_proofs.len());
    }
    buf.extend_from_slice(&(sd.process_proofs.len() as u64).to_le_bytes()); // 0 or 4
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

    Ok(buf)
}

/// Serialize a chain of SMT entries: u64 len + u64 n_levels + entries.
fn write_smt_chain(buf: &mut Vec<u8>, entries: &[SmtEntry]) -> Result<()> {
    let n = entries.len() as u64;
    let n_levels = entries.first().map(|e| e.siblings.len()).unwrap_or(0);
    for (i, e) in entries.iter().enumerate() {
        if e.siblings.len() != n_levels {
            bail!("chain entry {} has {} siblings, expected {}", i, e.siblings.len(), n_levels);
        }
    }
    buf.extend_from_slice(&n.to_le_bytes());
    buf.extend_from_slice(&(n_levels as u64).to_le_bytes());
    for e in entries {
        write_smt_entry_body(buf, e);
    }
    Ok(())
}

/// Serialize has_results + n_levels + optional entry body.
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

/// Serialize a single SMT entry body (no length prefix).
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

/// Write a zero-filled SMT entry (for padding).
fn write_zero_smt_entry(buf: &mut Vec<u8>, n_levels: usize) {
    let zero = [0u64; 4];
    for _ in 0..4 { write_u64_slice(buf, &zero); } // old_root, new_root, old_key, old_value
    buf.extend_from_slice(&0u64.to_le_bytes()); // is_old0
    for _ in 0..2 { write_u64_slice(buf, &zero); } // new_key, new_value
    buf.extend_from_slice(&0u64.to_le_bytes()); // fnc0
    buf.extend_from_slice(&0u64.to_le_bytes()); // fnc1
    for _ in 0..n_levels { write_u64_slice(buf, &zero); }
}


#[derive(Debug, Deserialize, Clone)]
pub struct EcdsaSig {
    pub public_key_x: String,  // 0x-prefixed 32-byte big-endian hex
    pub public_key_y: String,  // 0x-prefixed 32-byte big-endian hex
    pub signature_r: String,   // 0x-prefixed 32-byte big-endian hex
    pub signature_s: String,   // 0x-prefixed 32-byte big-endian hex
    pub vote_id: u64,
    pub address: String,       // decimal uint160
    // private_key and signature_v are not used by the circuit; present for debugging
    #[serde(default)]
    pub private_key: String,
    #[serde(default)]
    pub signature_v: u8,
}

/// snarkjs Groth16 proof JSON format
#[derive(Debug, Deserialize, Clone)]
pub struct SnarkJsProof {
    pub curve: String,
    pub protocol: String,
    pub pi_a: [String; 3],
    pub pi_b: [[String; 2]; 3],
    pub pi_c: [String; 3],
}

/// snarkjs verification key JSON format
#[derive(Debug, Deserialize, Clone)]
pub struct SnarkJsVk {
    pub curve: String,
    pub protocol: String,
    pub vk_alpha_1: [String; 3],
    pub vk_beta_2: [[String; 2]; 3],
    pub vk_gamma_2: [[String; 2]; 3],
    pub vk_delta_2: [[String; 2]; 3],
    #[serde(rename = "IC")]
    pub ic: Vec<[String; 3]>,
}

#[derive(Clone, Copy, Debug)]
enum G2Mode {
    C0C1, C1C0, C0C1YSwap, C1C0YSwap,
    XYSwapC0C1, XYSwapC1C0, XYSwapC0C1YSwap, XYSwapC1C0YSwap,
}

impl G2Mode {
    fn all() -> [G2Mode; 8] {
        [G2Mode::C0C1, G2Mode::C1C0, G2Mode::C0C1YSwap, G2Mode::C1C0YSwap,
         G2Mode::XYSwapC0C1, G2Mode::XYSwapC1C0, G2Mode::XYSwapC0C1YSwap, G2Mode::XYSwapC1C0YSwap]
    }
}

fn parse_big_decimal(s: &str) -> Result<BigUint> {
    BigUint::parse_bytes(s.as_bytes(), 10).ok_or_else(|| anyhow!("invalid decimal integer: {s}"))
}

fn big_to_u64x4_le(x: &BigUint) -> Result<[u64; 4]> {
    let bytes = x.to_bytes_le();
    if bytes.len() > 32 { bail!("integer does not fit in 32 bytes"); }
    let mut out = [0u8; 32];
    out[..bytes.len()].copy_from_slice(&bytes);
    let mut limbs = [0u64; 4];
    for i in 0..4 { limbs[i] = u64::from_le_bytes(out[i * 8..(i + 1) * 8].try_into().unwrap()); }
    Ok(limbs)
}

fn fq_from_dec(s: &str) -> Result<Fq> {
    let limbs = big_to_u64x4_le(&parse_big_decimal(s)?)?;
    Fq::from_bigint(ArkBigInt::<4>(limbs)).ok_or_else(|| anyhow!("invalid Fq element"))
}

fn fr_from_dec(s: &str) -> Result<Fr> {
    let limbs = big_to_u64x4_le(&parse_big_decimal(s)?)?;
    Fr::from_bigint(ArkBigInt::<4>(limbs)).ok_or_else(|| anyhow!("invalid Fr element"))
}

fn parse_g1(v: &[String; 3]) -> Result<G1Affine> {
    if v[2] == "0" { return Ok(G1Affine::identity()); }
    let x = fq_from_dec(&v[0])?;
    let y = fq_from_dec(&v[1])?;
    let p = G1Affine::new_unchecked(x, y);
    if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() { bail!("invalid G1 point"); }
    Ok(p)
}

fn parse_g2(v: &[[String; 2]; 3], mode: G2Mode) -> Result<G2Affine> {
    if v[2][0] == "0" && v[2][1] == "0" { return Ok(G2Affine::identity()); }

    let (x_pair, y_pair) = match mode {
        G2Mode::XYSwapC0C1 | G2Mode::XYSwapC1C0 | G2Mode::XYSwapC0C1YSwap | G2Mode::XYSwapC1C0YSwap => (&v[1], &v[0]),
        _ => (&v[0], &v[1]),
    };

    let x0 = fq_from_dec(&x_pair[0])?;
    let x1 = fq_from_dec(&x_pair[1])?;
    let y0 = fq_from_dec(&y_pair[0])?;
    let y1 = fq_from_dec(&y_pair[1])?;

    let (x_c0, x_c1, y_c0, y_c1) = match mode {
        G2Mode::C0C1 | G2Mode::XYSwapC0C1 => (x0, x1, y0, y1),
        G2Mode::C1C0 | G2Mode::XYSwapC1C0 => (x1, x0, y1, y0),
        G2Mode::C0C1YSwap | G2Mode::XYSwapC0C1YSwap => (x0, x1, y1, y0),
        G2Mode::C1C0YSwap | G2Mode::XYSwapC1C0YSwap => (x1, x0, y0, y1),
    };

    let p = G2Affine::new_unchecked(Fq2::new(x_c0, x_c1), Fq2::new(y_c0, y_c1));
    if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() { bail!("invalid G2 point"); }
    Ok(p)
}

fn build_vk(vk: &SnarkJsVk, mode: G2Mode) -> Result<VerifyingKey<Bn254>> {
    let alpha = parse_g1(&vk.vk_alpha_1)?;
    let beta2 = parse_g2(&vk.vk_beta_2, mode)?;
    let gamma2 = parse_g2(&vk.vk_gamma_2, mode)?;
    let delta2 = parse_g2(&vk.vk_delta_2, mode)?;
    let ic = vk.ic.iter().map(parse_g1).collect::<Result<Vec<_>>>().context("failed to parse IC points")?;
    if ic.is_empty() { bail!("vk IC must not be empty"); }
    Ok(VerifyingKey { alpha_g1: alpha, beta_g2: beta2, gamma_g2: gamma2, delta_g2: delta2, gamma_abc_g1: ic })
}

fn build_proof(p: &SnarkJsProof, mode: G2Mode) -> Result<Proof<Bn254>> {
    Ok(Proof { a: parse_g1(&p.pi_a)?, b: parse_g2(&p.pi_b, mode)?, c: parse_g1(&p.pi_c)? })
}

fn detect_mode(vk: &SnarkJsVk, first_proof: &SnarkJsProof, first_public: &[String]) -> Result<G2Mode> {
    for mode in G2Mode::all() {
        let try_vk = match build_vk(vk, mode) { Ok(v) => v, Err(_) => continue };
        let try_proof = match build_proof(first_proof, mode) { Ok(p) => p, Err(_) => continue };
        let pubs = match first_public.iter().map(|s| fr_from_dec(s)).collect::<Result<Vec<_>>>() {
            Ok(v) => v, Err(_) => continue,
        };
        let pvk = prepare_verifying_key(&try_vk);
        if Groth16::<Bn254>::verify_with_processed_vk(&pvk, &pubs, &try_proof).unwrap_or(false) {
            return Ok(mode);
        }
    }
    bail!("could not detect G2 coordinate ordering mode")
}

fn parse_index(name: &str, prefix: &str) -> Option<usize> {
    if !name.starts_with(prefix) || !name.ends_with(".json") { return None; }
    name.strip_prefix(prefix)?.strip_suffix(".json")?.parse::<usize>().ok()
}

fn collect_paths(dir: &Path, prefix: &str) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if parse_index(&name, prefix).is_some() { out.push(entry.path()); }
    }
    out.sort_by(|a, b| {
        let an = a.file_name().and_then(|n| n.to_str()).and_then(|n| parse_index(n, prefix)).unwrap_or(usize::MAX);
        let bn = b.file_name().and_then(|n| n.to_str()).and_then(|n| parse_index(n, prefix)).unwrap_or(usize::MAX);
        if an == bn { a.cmp(b) } else if an < bn { Ordering::Less } else { Ordering::Greater }
    });
    Ok(out)
}

fn fq_to_u64x4(x: &Fq) -> [u64; 4] { x.into_bigint().0 }
fn fr_to_u64x4(x: &Fr) -> [u64; 4] { x.into_bigint().0 }

fn g1_to_raw(p: &G1Affine) -> [u64; 8] {
    if p.is_zero() { let mut id = [0u64; 8]; id[4] = 1; return id; }
    let x = fq_to_u64x4(&p.x);
    let y = fq_to_u64x4(&p.y);
    [x[0], x[1], x[2], x[3], y[0], y[1], y[2], y[3]]
}

fn g2_to_raw(p: &G2Affine) -> [u64; 16] {
    if p.is_zero() { let mut id = [0u64; 16]; id[8] = 1; return id; }
    let xc0 = fq_to_u64x4(&p.x.c0);
    let xc1 = fq_to_u64x4(&p.x.c1);
    let yc0 = fq_to_u64x4(&p.y.c0);
    let yc1 = fq_to_u64x4(&p.y.c1);
    [xc0[0], xc0[1], xc0[2], xc0[3], xc1[0], xc1[1], xc1[2], xc1[3],
     yc0[0], yc0[1], yc0[2], yc0[3], yc1[0], yc1[1], yc1[2], yc1[3]]
}

fn write_u64_slice(buf: &mut Vec<u8>, words: &[u64]) {
    for w in words { buf.extend_from_slice(&w.to_le_bytes()); }
}

/// Compute Fiat-Shamir challenge r_shift from all proof data (must match guest's transcript).
///
/// Scheme (must stay in sync with circuit/src/main.rs):
///   digest  = SHA256("groth16-batch-v1" || A_0||B_0||C_0||pub_0 || ... )
///   d0      = SHA256(digest || counter(8B) || 0x00)
///   d1      = SHA256(digest || counter(8B) || 0x01)
///   r_shift = Fr::from_random_bytes(d0 || d1)   (retry with counter++ if not invertible)
///
/// Pre-hashing the 36KB transcript to 32 bytes before the retry loop avoids re-hashing
/// the full transcript on each retry attempt.
fn compute_r_shift(proofs: &[Proof<Bn254>], public_inputs: &[Vec<Fr>]) -> Fr {
    let mut data = Vec::<u8>::new();
    data.extend_from_slice(b"groth16-batch-v1");
    for (proof, pubs) in proofs.iter().zip(public_inputs.iter()) {
        for w in g1_to_raw(&proof.a) { data.extend_from_slice(&w.to_le_bytes()); }
        for w in g2_to_raw(&proof.b) { data.extend_from_slice(&w.to_le_bytes()); }
        for w in g1_to_raw(&proof.c) { data.extend_from_slice(&w.to_le_bytes()); }
        for pub_val in pubs {
            for w in fr_to_u64x4(pub_val) { data.extend_from_slice(&w.to_le_bytes()); }
        }
    }
    // Pre-hash full transcript to 32 bytes to avoid re-hashing on retries.
    let digest: [u8; 32] = Sha256::digest(&data).into();
    let mut counter = 0u64;
    loop {
        let d0: [u8; 32] = {
            let mut h = [0u8; 41];
            h[..32].copy_from_slice(&digest);
            h[32..40].copy_from_slice(&counter.to_be_bytes());
            h[40] = 0u8;
            Sha256::digest(&h).into()
        };
        let d1: [u8; 32] = {
            let mut h = [0u8; 41];
            h[..32].copy_from_slice(&digest);
            h[32..40].copy_from_slice(&counter.to_be_bytes());
            h[40] = 1u8;
            Sha256::digest(&h).into()
        };
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&d0);
        wide[32..].copy_from_slice(&d1);
        if let Some(v) = Fr::from_random_bytes(&wide) {
            if v.inverse().is_some() { return v; }
        }
        counter += 1;
    }
}

/// Generate ZisK binary input from a snarkjs VK and an array of proofs + public inputs.
///
/// The `proofs` and `public_inputs` arrays must have the same length, which must be a
/// power of two >= 2 and match the circuit's expected batch size (typically 128).
///
/// Returns raw bytes suitable for writing to disk and passing to `cargo-zisk prove --input`.
pub fn generate_input(vk: &SnarkJsVk, proofs_json: &[SnarkJsProof], public_inputs_json: &[Vec<String>], sigs: &[EcdsaSig]) -> Result<Vec<u8>> {
    let num_proofs = proofs_json.len();
    if num_proofs < 2 || !num_proofs.is_power_of_two() {
        bail!("num_proofs ({}) must be a power of two >= 2", num_proofs);
    }
    if proofs_json.len() != public_inputs_json.len() {
        bail!("proofs and public_inputs must have the same length");
    }
    if sigs.len() != num_proofs {
        bail!("sigs length ({}) must equal num_proofs ({}); ECDSA signatures are mandatory", sigs.len(), num_proofs);
    }

    // Detect G2 encoding mode from the first proof
    let first_public_str: Vec<String> = public_inputs_json[0].clone();
    let mode = detect_mode(vk, &proofs_json[0], &first_public_str)?;

    let ark_vk = build_vk(vk, mode)?;
    let pvk = prepare_verifying_key(&ark_vk);
    let n_public = ark_vk.gamma_abc_g1.len() - 1;

    // Parse and verify each proof
    let mut ark_proofs = Vec::with_capacity(num_proofs);
    let mut ark_public_inputs = Vec::with_capacity(num_proofs);
    for (i, (proof_json, pubs_json)) in proofs_json.iter().zip(public_inputs_json.iter()).enumerate() {
        let proof = build_proof(proof_json, mode).with_context(|| format!("proof[{}] parse failed", i))?;
        let pubs = pubs_json.iter().map(|s| fr_from_dec(s)).collect::<Result<Vec<_>>>()
            .with_context(|| format!("public[{}] parse failed", i))?;
        if !Groth16::<Bn254>::verify_with_processed_vk(&pvk, &pubs, &proof)? {
            bail!("single-proof verification failed for proof[{}]", i);
        }
        ark_proofs.push(proof);
        ark_public_inputs.push(pubs);
    }

    // Compute Fiat-Shamir challenge
    let r_shift = compute_r_shift(&ark_proofs, &ark_public_inputs);
    let mut r_powers: Vec<Fr> = Vec::with_capacity(num_proofs);
    r_powers.push(Fr::ONE);
    for i in 1..num_proofs { r_powers.push(r_powers[i - 1] * r_shift); }

    // Precompute hints
    let scaled_a: Vec<G1Affine> = ark_proofs.iter().zip(r_powers.iter())
        .map(|(p, r)| p.a.mul_bigint(r.into_bigint()).into_affine())
        .collect();
    let r_sum: Fr = r_powers.iter().sum();
    let neg_alpha_rsum = (ark_vk.alpha_g1.mul_bigint((-r_sum).into_bigint())).into_affine();
    let mut g_ic = ark_vk.gamma_abc_g1[0].mul_bigint(r_sum.into_bigint());
    for j in 0..n_public {
        let coeff: Fr = ark_public_inputs.iter().zip(r_powers.iter())
            .map(|(pubs, r)| pubs[j] * r)
            .sum();
        g_ic += ark_vk.gamma_abc_g1[j + 1].mul_bigint(coeff.into_bigint());
    }
    let neg_g_ic = (-g_ic).into_affine();
    let acc_c_proj: ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config> = ark_proofs.iter().zip(r_powers.iter())
        .map(|(p, r)| p.c.mul_bigint(r.into_bigint()))
        .sum();
    let neg_acc_c = (-acc_c_proj).into_affine();

    // Serialize to binary
    let log_n = (num_proofs as f64).log2() as u64;
    let mut buf: Vec<u8> = Vec::new();
    // Header
    write_u64_slice(&mut buf, &[MAGIC, log_n, num_proofs as u64, n_public as u64]);
    // VK
    write_u64_slice(&mut buf, &g1_to_raw(&ark_vk.alpha_g1));
    write_u64_slice(&mut buf, &g2_to_raw(&ark_vk.beta_g2));
    write_u64_slice(&mut buf, &g2_to_raw(&ark_vk.gamma_g2));
    write_u64_slice(&mut buf, &g2_to_raw(&ark_vk.delta_g2));
    write_u64_slice(&mut buf, &[ark_vk.gamma_abc_g1.len() as u64]);
    for p in &ark_vk.gamma_abc_g1 { write_u64_slice(&mut buf, &g1_to_raw(p)); }
    // Proofs
    write_u64_slice(&mut buf, &[num_proofs as u64]);
    for (proof, pubs) in ark_proofs.iter().zip(ark_public_inputs.iter()) {
        write_u64_slice(&mut buf, &g1_to_raw(&proof.a));
        write_u64_slice(&mut buf, &g2_to_raw(&proof.b));
        write_u64_slice(&mut buf, &g1_to_raw(&proof.c));
        for x in pubs { write_u64_slice(&mut buf, &fr_to_u64x4(x)); }
    }
    // Precomputed hints
    for p in &scaled_a { write_u64_slice(&mut buf, &g1_to_raw(p)); }
    write_u64_slice(&mut buf, &g1_to_raw(&neg_alpha_rsum));
    write_u64_slice(&mut buf, &g1_to_raw(&neg_g_ic));
    write_u64_slice(&mut buf, &g1_to_raw(&neg_acc_c));

    // ECDSA signatures (one entry per proof): r[4] || s[4] || px[4] || py[4] (all [u64;4] LE)
    for sig in sigs {
        write_u64_slice(&mut buf, &hex32_to_u64x4(&sig.signature_r)?);
        write_u64_slice(&mut buf, &hex32_to_u64x4(&sig.signature_s)?);
        write_u64_slice(&mut buf, &hex32_to_u64x4(&sig.public_key_x)?);
        write_u64_slice(&mut buf, &hex32_to_u64x4(&sig.public_key_y)?);
    }

    Ok(buf)
}

/// Load proofs from a directory following snarkjs naming convention.
/// Reads `proof_1.json..proof_N.json` and `public_1.json..public_N.json`.
pub fn load_proofs_from_dir(dir: &Path, num_proofs: usize) -> Result<(Vec<SnarkJsProof>, Vec<Vec<String>>)> {
    let mut proof_paths = collect_paths(dir, "proof_")?;
    let mut public_paths = collect_paths(dir, "public_")?;
    if proof_paths.len() < num_proofs || public_paths.len() < num_proofs {
        bail!("not enough proofs/publics in {} (need {})", dir.display(), num_proofs);
    }
    proof_paths.truncate(num_proofs);
    public_paths.truncate(num_proofs);

    let proofs = proof_paths.iter()
        .map(|p| read_json(p))
        .collect::<Result<Vec<SnarkJsProof>>>()?;
    let publics = public_paths.iter()
        .map(|p| read_json::<Vec<String>>(p))
        .collect::<Result<Vec<_>>>()?;
    Ok((proofs, publics))
}

fn read_json<T: for<'de> serde::Deserialize<'de>>(path: &Path) -> Result<T> {
    let raw = fs::read(path).with_context(|| format!("failed reading {}", path.display()))?;
    serde_json::from_slice(&raw).with_context(|| format!("invalid JSON: {}", path.display()))
}

/// Load ECDSA signatures from a directory.
/// Reads `sig_1.json..sig_N.json` (produced by davinci-circom generate-proofs.sh).
/// Fails if no sig files are found — ECDSA signatures are mandatory.
pub fn load_signatures_from_dir(dir: &Path, num_proofs: usize) -> Result<Vec<EcdsaSig>> {
    let mut sig_paths = collect_paths(dir, "sig_")?;
    if sig_paths.is_empty() {
        bail!("no sig_*.json files found in {}; ECDSA signatures are mandatory", dir.display());
    }
    if sig_paths.len() < num_proofs {
        bail!("not enough sig files in {} (need {}, found {})", dir.display(), num_proofs, sig_paths.len());
    }
    sig_paths.truncate(num_proofs);
    sig_paths.iter().map(|p| read_json(p)).collect()
}

/// Parse a 0x-prefixed 32-byte big-endian hex string into [u64; 4] little-endian.
/// The circuit reads these words as little-endian 64-bit integers.
fn hex32_to_u64x4(s: &str) -> Result<[u64; 4]> {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(hex)
        .with_context(|| format!("invalid hex: {}", s))?;
    if bytes.len() != 32 {
        bail!("expected 32-byte hex, got {} bytes: {}", bytes.len(), s);
    }
    // Input is big-endian; convert to little-endian u64 words (lowest word = bytes[24..32])
    let mut out = [0u64; 4];
    for i in 0..4 {
        let start = 24 - i * 8; // big-endian: word 0 = bytes[24..32]
        out[i] = u64::from_be_bytes(bytes[start..start + 8].try_into().unwrap());
    }
    Ok(out)
}

/// Census proof data for one voter in lean-IMT format.
pub struct CensusProofData {
    /// Census tree root as [u64; 4] LE.
    pub root: [u64; 4],
    /// Leaf = PackAddressWeight(address, weight) as [u64; 4] LE.
    pub leaf: [u64; 4],
    /// Packed path bits (bit i = (index >> i) & 1).
    pub index: u64,
    /// Non-empty Merkle siblings (variable length).
    pub siblings: Vec<[u64; 4]>,
}

/// Serialize census membership proofs into the CENSUS binary block.
///
/// Format:
/// ```
/// magic:    u64 = "CENSUS!!"
/// n_proofs: u64
/// Per proof:
///   root:       [u64; 4]
///   leaf:       [u64; 4]
///   index:      u64
///   n_siblings: u64
///   siblings:   [[u64; 4]; n_siblings]
/// ```
pub fn write_census_block(proofs: &[CensusProofData]) -> Result<Vec<u8>> {
    if proofs.is_empty() {
        return Ok(Vec::new());
    }
    let magic: u64 = u64::from_le_bytes(*b"CENSUS!!");
    let mut buf = Vec::with_capacity(8 + 8 + proofs.len() * (32 + 32 + 8 + 8));
    buf.extend_from_slice(&magic.to_le_bytes());
    buf.extend_from_slice(&(proofs.len() as u64).to_le_bytes());
    for p in proofs {
        for w in &p.root     { buf.extend_from_slice(&w.to_le_bytes()); }
        for w in &p.leaf     { buf.extend_from_slice(&w.to_le_bytes()); }
        buf.extend_from_slice(&p.index.to_le_bytes());
        buf.extend_from_slice(&(p.siblings.len() as u64).to_le_bytes());
        for s in &p.siblings {
            for w in s { buf.extend_from_slice(&w.to_le_bytes()); }
        }
    }
    Ok(buf)
}

/// Parse a 0x-prefixed hex big-endian string into CensusProofData.
pub fn census_proof_from_hex(
    root: &str, leaf: &str, index: u64, siblings: &[String],
) -> Result<CensusProofData> {
    let root = hex32_to_u64x4(root)?;
    let leaf = hex32_to_u64x4(leaf)?;
    let mut sibs = Vec::with_capacity(siblings.len());
    for s in siblings {
        sibs.push(hex32_to_u64x4(s)?);
    }
    Ok(CensusProofData { root, leaf, index, siblings: sibs })
}

/// One ElGamal ciphertext (C1.x, C1.y, C2.x, C2.y) in BN254 Fr as LE u64 limbs.
pub struct BjjCiphertextData {
    pub c1x: [u64; 4],
    pub c1y: [u64; 4],
    pub c2x: [u64; 4],
    pub c2y: [u64; 4],
}

/// Re-encryption data for one voter: seed k, 8 original ciphertexts, 8 re-encrypted ciphertexts.
pub struct ReencEntryData {
    pub k: [u64; 4],
    pub original: [BjjCiphertextData; 8],
    pub reencrypted: [BjjCiphertextData; 8],
}

/// Serialize re-encryption entries into the REENCBLK binary block.
///
/// Format:
/// ```
/// magic:     u64 = "REENCBLK"
/// n_voters:  u64
/// pub_key_x: [u64; 4]
/// pub_key_y: [u64; 4]
/// Per voter:
///   k:             [u64; 4]
///   original[8]:   8 × (c1x, c1y, c2x, c2y)  each [u64; 4]
///   reencrypted[8]: 8 × (c1x, c1y, c2x, c2y)  each [u64; 4]
/// ```
pub fn write_reenc_block(
    pub_key_x: [u64; 4],
    pub_key_y: [u64; 4],
    entries: &[ReencEntryData],
) -> Result<Vec<u8>> {
    if entries.is_empty() {
        return Ok(Vec::new());
    }
    let magic: u64 = u64::from_le_bytes(*b"REENCBLK");
    let mut buf = Vec::new();
    buf.extend_from_slice(&magic.to_le_bytes());
    buf.extend_from_slice(&(entries.len() as u64).to_le_bytes());
    for w in &pub_key_x { buf.extend_from_slice(&w.to_le_bytes()); }
    for w in &pub_key_y { buf.extend_from_slice(&w.to_le_bytes()); }
    for e in entries {
        for w in &e.k { buf.extend_from_slice(&w.to_le_bytes()); }
        for ct in &e.original {
            for w in &ct.c1x { buf.extend_from_slice(&w.to_le_bytes()); }
            for w in &ct.c1y { buf.extend_from_slice(&w.to_le_bytes()); }
            for w in &ct.c2x { buf.extend_from_slice(&w.to_le_bytes()); }
            for w in &ct.c2y { buf.extend_from_slice(&w.to_le_bytes()); }
        }
        for ct in &e.reencrypted {
            for w in &ct.c1x { buf.extend_from_slice(&w.to_le_bytes()); }
            for w in &ct.c1y { buf.extend_from_slice(&w.to_le_bytes()); }
            for w in &ct.c2x { buf.extend_from_slice(&w.to_le_bytes()); }
            for w in &ct.c2y { buf.extend_from_slice(&w.to_le_bytes()); }
        }
    }
    Ok(buf)
}
