//! Binary input parsing for the davinci-zkvm circuit.
//!
//! # Binary format
//!
//! All integers are little-endian; field/curve elements are stored as `[u64; N]`.
//!
//! ```text
//! Header : magic(u64) log_n(u64) nproofs(u64) n_public(u64)
//! VK     : alpha_g1(G1) beta_g2(G2) gamma_g2(G2) delta_g2(G2)
//!          gamma_abc_len(u64) gamma_abc[..](G1 each)
//! Proofs : nproofs(u64) [a(G1) b(G2) c(G1) pubs[..](FrRaw each)] × nproofs
//! Hints  : scaled_a[..](G1 each) neg_alpha_rsum(G1) neg_g_ic(G1) neg_acc_c(G1)
//! ECDSA  : [r s px py](FrRaw each) × nproofs  (mandatory)
//! ```
//!
//! The ECDSA block must be present; its expected size is `nproofs × 4 × 32` bytes.

use crate::bn254::{g1_identity, g2_identity};
use crate::types::*;

/// Read `N` little-endian `u64` words from `input` at `*offset`, advancing `*offset`.
/// Returns `None` — without moving `*offset` — if insufficient bytes remain.
pub fn read_words_le<const N: usize>(input: &[u8], offset: &mut usize) -> Option<[u64; N]> {
    let bytes = N * 8;
    if *offset + bytes > input.len() {
        return None;
    }
    let mut out = [0u64; N];
    for i in 0..N {
        let start = *offset + i * 8;
        out[i] = u64::from_le_bytes(input[start..start + 8].try_into().unwrap());
    }
    *offset += bytes;
    Some(out)
}

/// All data parsed from a single ZisK binary input blob.
pub struct ParsedInput {
    pub log_n: usize,
    pub nproofs: usize,
    pub n_public: usize,
    pub vk_alpha_g1: G1,
    pub vk_beta_g2: G2,
    pub vk_gamma_g2: G2,
    pub vk_delta_g2: G2,
    pub vk_gamma_abc: Vec<G1>,
    pub proofs: Vec<ProofRaw>,
    pub scaled_a: Vec<G1>,
    pub neg_alpha_rsum: G1,
    pub neg_g_ic: G1,
    pub neg_acc_c: G1,
    /// ECDSA entries; one per proof (mandatory).
    pub ecdsa: Vec<EcdsaEntry>,
    /// Number of bytes consumed (equals `input.len()` on success).
    pub bytes_consumed: usize,
}

/// Parse the binary input blob, setting bits in `fail_mask` on any error.
///
/// This function is **infallible** — it always returns a `ParsedInput`, using
/// identity/zero fallbacks for unreadable fields.  Callers must check `fail_mask`
/// (particularly bit 31 = parse error) before trusting the returned data.
///
/// # Fail-mask bits
/// - Bit 31 — format/parse error (magic mismatch, truncated data, counter mismatch)
pub fn parse_input(input: &[u8], fail_mask: &mut u32) -> ParsedInput {
    // Convenience macros to read fields and record failures without early-return.
    macro_rules! read1 {
        ($off:expr, $default:expr) => {
            read_words_le::<1>(input, $off)
                .map(|x| x[0])
                .unwrap_or_else(|| { *fail_mask |= 1 << 31; $default })
        };
    }
    macro_rules! read_g1 { ($off:expr) => {
        read_words_le::<8>(input, $off).unwrap_or_else(|| { *fail_mask |= 1 << 31; g1_identity() })
    };}
    macro_rules! read_g2 { ($off:expr) => {
        read_words_le::<16>(input, $off).unwrap_or_else(|| { *fail_mask |= 1 << 31; g2_identity() })
    };}
    macro_rules! read_fr { ($off:expr) => {
        read_words_le::<4>(input, $off).unwrap_or_else(|| { *fail_mask |= 1 << 31; ZERO_FR })
    };}

    let mut off = 0usize;

    // --- Header ---
    let magic    = read1!(&mut off, 0);
    let log_n    = read1!(&mut off, 0) as usize;
    let nproofs  = read1!(&mut off, 0) as usize;
    let n_public = read1!(&mut off, 0) as usize;

    if magic != MAGIC              { *fail_mask |= 1 << 31; }
    if nproofs == 0 || nproofs > 4096 { *fail_mask |= 1 << 31; }
    if n_public > 256              { *fail_mask |= 1 << 31; }

    // --- Verification key ---
    let vk_alpha_g1 = read_g1!(&mut off);
    let vk_beta_g2  = read_g2!(&mut off);
    let vk_gamma_g2 = read_g2!(&mut off);
    let vk_delta_g2 = read_g2!(&mut off);

    let gamma_abc_len = read1!(&mut off, 0) as usize;
    if gamma_abc_len != n_public + 1 { *fail_mask |= 1 << 31; }

    let mut vk_gamma_abc = Vec::with_capacity(gamma_abc_len);
    for _ in 0..gamma_abc_len {
        vk_gamma_abc.push(read_g1!(&mut off));
    }

    // --- Proofs ---
    let nproofs_check = read1!(&mut off, 0) as usize;
    if nproofs_check != nproofs { *fail_mask |= 1 << 31; }

    let mut proofs = Vec::with_capacity(nproofs);
    for _ in 0..nproofs {
        let a = read_g1!(&mut off);
        let b = read_g2!(&mut off);
        let c = read_g1!(&mut off);
        let mut public_inputs = Vec::with_capacity(n_public);
        for _ in 0..n_public {
            public_inputs.push(read_fr!(&mut off));
        }
        proofs.push(ProofRaw { a, b, c, public_inputs });
    }

    // --- Precomputed hints (validated by the pairing equation) ---
    let mut scaled_a = Vec::with_capacity(nproofs);
    for _ in 0..nproofs {
        scaled_a.push(read_g1!(&mut off));
    }
    let neg_alpha_rsum = read_g1!(&mut off);
    let neg_g_ic       = read_g1!(&mut off);
    let neg_acc_c      = read_g1!(&mut off);

    // --- ECDSA block (mandatory) ---
    // Must be present: exactly nproofs × (r + s + px + py) × 32 bytes remaining.
    let ecdsa_block_size = nproofs * 4 * 32;
    if *fail_mask == 0 && off + ecdsa_block_size != input.len() {
        *fail_mask |= 1 << 31;
    }

    let mut ecdsa = Vec::with_capacity(nproofs);
    for _ in 0..nproofs {
        let r  = read_fr!(&mut off);
        let s  = read_fr!(&mut off);
        let px = read_fr!(&mut off);
        let py = read_fr!(&mut off);
        ecdsa.push(EcdsaEntry { r, s, px, py });
    }

    ParsedInput {
        log_n, nproofs, n_public,
        vk_alpha_g1, vk_beta_g2, vk_gamma_g2, vk_delta_g2, vk_gamma_abc,
        proofs, scaled_a, neg_alpha_rsum, neg_g_ic, neg_acc_c,
        ecdsa,
        bytes_consumed: off,
    }
}
