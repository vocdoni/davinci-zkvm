//! circuit-results guest input: the single-key tally frame.
//!
//! Frame layout, all LE (see circuit-results/RESULTS.md §1):
//! ```text
//! magic "DAVRSLT1" u64
//! state_root   32B  raw arbo root digest
//! pk_x, pk_y   2 x 32B  TE coords
//! n_key u64 (= 64), key_siblings 64 x 32B
//! accumulator  64 x 32B  [c1x, c1y, c2x, c2y] x 16
//! n_acc u64 (= 64), acc_siblings 64 x 32B
//! results      16 x u64
//! cp           16 x 160B  a1x a1y a2x a2y z
//! ```
//! The builder only checks shape; canonical encodings, curve membership,
//! inclusions and the proofs are checked by the guest.

use crate::aggregator::CpProofJson;
use crate::{BALLOT_FIELDS, NUM_FIELDS};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

pub const RESULTS_MAGIC: u64 = u64::from_le_bytes(*b"DAVRSLT1");
/// Sibling count the guest accepts (state tree depth, `SMT_LEVELS`).
pub const RESULTS_LEVELS: usize = 64;
/// Exact guest frame length.
pub const RESULTS_FRAME_LEN: usize = 8
    + 32
    + 64
    + 8
    + RESULTS_LEVELS * 32
    + BALLOT_FIELDS * 32
    + 8
    + RESULTS_LEVELS * 32
    + NUM_FIELDS * 8
    + NUM_FIELDS * 160;

/// `POST /results` body. 32-byte values are arbo-LE hex (`0x` optional).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultsJson {
    /// Final state root: hex of the raw arbo root bytes.
    pub state_root: String,
    /// Election key, TE coordinates.
    pub enc_key_x: String,
    pub enc_key_y: String,
    /// Inclusion siblings of key 0x03, root→leaf, at most 64 (zero-padded here).
    pub key_siblings: Vec<String>,
    /// Net results accumulator (key 0x04): 64 TE coordinates.
    pub accumulator: Vec<String>,
    /// Inclusion siblings of key 0x04, root→leaf, at most 64.
    pub acc_siblings: Vec<String>,
    /// Claimed plaintext per ciphertext.
    pub results: Vec<u64>,
    /// One Chaum-Pedersen decryption proof per ciphertext; `z` reduced mod l.
    pub cp_proofs: Vec<CpProofJson>,
}

fn hex32(field: &str, s: &str) -> Result<[u8; 32]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).with_context(|| format!("{}: bad hex", field))?;
    bytes
        .try_into()
        .map_err(|b: Vec<u8>| anyhow::anyhow!("{}: expected 32 bytes, got {}", field, b.len()))
}

fn push_siblings(out: &mut Vec<u8>, field: &str, sibs: &[String]) -> Result<()> {
    if sibs.is_empty() || sibs.len() > RESULTS_LEVELS {
        bail!(
            "{}: expected 1..={} siblings, got {}",
            field,
            RESULTS_LEVELS,
            sibs.len()
        );
    }
    out.extend_from_slice(&(RESULTS_LEVELS as u64).to_le_bytes());
    for (i, s) in sibs.iter().enumerate() {
        out.extend_from_slice(&hex32(&format!("{}[{}]", field, i), s)?);
    }
    // Trailing zero siblings leave an inclusion proof unchanged.
    out.resize(out.len() + (RESULTS_LEVELS - sibs.len()) * 32, 0);
    Ok(())
}

/// Encode a results request into the raw guest frame (no `read_slice` length
/// prefix; the service and ziskemu add it).
pub fn build_results_input(req: &ResultsJson) -> Result<Vec<u8>> {
    if req.accumulator.len() != BALLOT_FIELDS {
        bail!(
            "accumulator: expected {} coordinates, got {}",
            BALLOT_FIELDS,
            req.accumulator.len()
        );
    }
    if req.results.len() != NUM_FIELDS {
        bail!(
            "results: expected {} values, got {}",
            NUM_FIELDS,
            req.results.len()
        );
    }
    if req.cp_proofs.len() != NUM_FIELDS {
        bail!(
            "cp_proofs: expected {} proofs, got {}",
            NUM_FIELDS,
            req.cp_proofs.len()
        );
    }

    let mut out = Vec::with_capacity(RESULTS_FRAME_LEN);
    out.extend_from_slice(&RESULTS_MAGIC.to_le_bytes());
    out.extend_from_slice(&hex32("state_root", &req.state_root)?);
    out.extend_from_slice(&hex32("enc_key_x", &req.enc_key_x)?);
    out.extend_from_slice(&hex32("enc_key_y", &req.enc_key_y)?);
    push_siblings(&mut out, "key_siblings", &req.key_siblings)?;
    for (i, c) in req.accumulator.iter().enumerate() {
        out.extend_from_slice(&hex32(&format!("accumulator[{}]", i), c)?);
    }
    push_siblings(&mut out, "acc_siblings", &req.acc_siblings)?;
    for r in &req.results {
        out.extend_from_slice(&r.to_le_bytes());
    }
    for (i, p) in req.cp_proofs.iter().enumerate() {
        for (f, v) in [
            ("a1x", &p.a1x),
            ("a1y", &p.a1y),
            ("a2x", &p.a2x),
            ("a2y", &p.a2y),
            ("z", &p.z),
        ] {
            out.extend_from_slice(&hex32(&format!("cp_proofs[{}].{}", i, f), v)?);
        }
    }
    debug_assert_eq!(out.len(), RESULTS_FRAME_LEN);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(b: u8) -> String {
        hex::encode([b; 32])
    }

    fn request() -> ResultsJson {
        ResultsJson {
            state_root: h(0x11),
            enc_key_x: h(0x22),
            enc_key_y: format!("0x{}", h(0x33)),
            key_siblings: vec![h(0x44); 3],
            accumulator: (0..BALLOT_FIELDS).map(|i| h(i as u8)).collect(),
            acc_siblings: vec![h(0x55); RESULTS_LEVELS],
            results: (0..NUM_FIELDS as u64).map(|i| i << 32 | 7).collect(),
            cp_proofs: (0..NUM_FIELDS)
                .map(|i| CpProofJson {
                    a1x: h(0xA0 + i as u8),
                    a1y: h(0xA1),
                    a2x: h(0xA2),
                    a2y: h(0xA3),
                    z: h(0xB0 + i as u8),
                })
                .collect(),
        }
    }

    #[test]
    fn frame_layout() {
        let f = build_results_input(&request()).unwrap();
        assert_eq!(f.len(), RESULTS_FRAME_LEN);
        assert_eq!(RESULTS_FRAME_LEN, 8952);
        assert_eq!(&f[0..8], b"DAVRSLT1");
        assert_eq!(f[8..40], [0x11; 32]);
        assert_eq!(f[40..72], [0x22; 32]);
        assert_eq!(f[72..104], [0x33; 32]);
        assert_eq!(u64::from_le_bytes(f[104..112].try_into().unwrap()), 64);
        // Three siblings, then zero padding.
        assert_eq!(f[112 + 2 * 32..112 + 3 * 32], [0x44; 32]);
        assert!(f[112 + 3 * 32..2160].iter().all(|&b| b == 0));
        assert_eq!(f[2160 + 5 * 32..2160 + 6 * 32], [5u8; 32]);
        assert_eq!(u64::from_le_bytes(f[4208..4216].try_into().unwrap()), 64);
        assert_eq!(f[4216..4248], [0x55; 32]);
        assert_eq!(
            u64::from_le_bytes(f[6264 + 3 * 8..6264 + 4 * 8].try_into().unwrap()),
            3 << 32 | 7
        );
        let cp2 = 6392 + 2 * 160;
        assert_eq!(f[cp2..cp2 + 32], [0xA2; 32]);
        assert_eq!(f[cp2 + 128..cp2 + 160], [0xB2; 32]);
    }

    #[test]
    fn rejects_bad_shapes() {
        let mut r = request();
        r.key_siblings = vec![h(1); RESULTS_LEVELS + 1];
        assert!(build_results_input(&r).is_err());

        let mut r = request();
        r.acc_siblings.clear();
        assert!(build_results_input(&r).is_err());

        let mut r = request();
        r.accumulator.pop();
        assert!(build_results_input(&r).is_err());

        let mut r = request();
        r.results.push(0);
        assert!(build_results_input(&r).is_err());

        let mut r = request();
        r.cp_proofs.pop();
        assert!(build_results_input(&r).is_err());

        let mut r = request();
        r.state_root = hex::encode([0u8; 31]);
        assert!(build_results_input(&r).is_err());

        let mut r = request();
        r.cp_proofs[4].z = "zz".repeat(32);
        assert!(build_results_input(&r).is_err());
    }
}
