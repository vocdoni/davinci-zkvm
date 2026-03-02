//! CSP (Credential Service Provider) ECDSA census verification.
//!
//! In CSP census mode (censusOrigin == 4), an authority (the CSP) signs each voter's
//! eligibility using secp256k1 ECDSA. The census root is the CSP's Ethereum address.
//!
//! # Message format (Ethereum personal-sign)
//!
//! ```text
//! payload  = processID_BE32 || address_BE20 || weight_BE32 || index_BE8
//! envelope = "\x19Ethereum Signed Message:\n92" || payload   (120 bytes)
//! z        = keccak256(envelope)
//! ```
//!
//! # Verification per voter
//!
//! 1. Reconstruct `z` from (processID, voter_address, weight, index)
//! 2. `secp256k1_ecdsa_verify(csp_pk, z, r, s)` — CSP signed this voter
//! 3. `eth_address_from_pk(csp_pk) == censusRoot` — CSP is the authorized authority
//!
//! # Security invariants
//!
//! - All entries share the same CSP public key (stored once in the block header)
//! - No duplicate (voter_address, index) pairs
//! - CSP address == census root from process config
//! - voter_address in each CSP entry must match the ballot proof's address (pub_inputs[0])

use crate::hash::keccak256_short;
use crate::types::{CspBlock, FrRaw, FAIL_CSP, ZERO_FR};
use ziskos::syscalls::SyscallPoint256;
use ziskos::zisklib::secp256k1_ecdsa_verify;

/// Compute the Ethereum signed-message hash for a CSP attestation.
///
/// `z = keccak256("\x19Ethereum Signed Message:\n92" || processID_BE32 || address_BE20 || weight_BE32 || index_BE8)`
fn csp_message_hash(process_id: &FrRaw, voter_address: &FrRaw, weight: &FrRaw, index: u64) -> [u64; 4] {
    // Prefix: "\x19Ethereum Signed Message:\n92" = 28 bytes
    const PREFIX: &[u8] = b"\x19Ethereum Signed Message:\n92";
    let mut envelope = [0u8; 120]; // 28 + 32 + 20 + 32 + 8

    // Copy prefix
    envelope[..28].copy_from_slice(PREFIX);

    // processID: FrRaw [u64;4] LE → 32-byte big-endian
    for i in 0..4 {
        let bytes = process_id[3 - i].to_be_bytes();
        envelope[28 + i * 8..28 + i * 8 + 8].copy_from_slice(&bytes);
    }

    // voter_address: uint160 in FrRaw LE → 20-byte big-endian
    // addr is packed as: limb[0] = bits 0-63, limb[1] = bits 64-127, limb[2] = bits 128-159
    let addr_bytes = fr_to_address(voter_address);
    envelope[60..80].copy_from_slice(&addr_bytes);

    // weight: FrRaw [u64;4] LE → 32-byte big-endian
    for i in 0..4 {
        let bytes = weight[3 - i].to_be_bytes();
        envelope[80 + i * 8..80 + i * 8 + 8].copy_from_slice(&bytes);
    }

    // index: u64 → 8-byte big-endian
    envelope[112..120].copy_from_slice(&index.to_be_bytes());

    let h = keccak256_short(&envelope);
    // Big-endian hash → [u64;4] LE scalar
    [
        u64::from_be_bytes(h[24..32].try_into().unwrap()),
        u64::from_be_bytes(h[16..24].try_into().unwrap()),
        u64::from_be_bytes(h[8..16].try_into().unwrap()),
        u64::from_be_bytes(h[0..8].try_into().unwrap()),
    ]
}

/// Convert a uint160 stored as FrRaw LE limbs to a 20-byte big-endian Ethereum address.
fn fr_to_address(fr: &FrRaw) -> [u8; 20] {
    // fr[0] = bits 0..63, fr[1] = bits 64..127, fr[2] = bits 128..159 (upper 32 bits only)
    let mut addr = [0u8; 20];
    // Lower 32 bits of fr[2] → first 4 bytes (big-endian)
    addr[0..4].copy_from_slice(&(fr[2] as u32).to_be_bytes());
    // fr[1] → next 8 bytes (big-endian)
    addr[4..12].copy_from_slice(&fr[1].to_be_bytes());
    // fr[0] → last 8 bytes (big-endian)
    addr[12..20].copy_from_slice(&fr[0].to_be_bytes());
    addr
}

/// Derive the 20-byte Ethereum address from a secp256k1 public key.
fn eth_address_from_pk(px: &FrRaw, py: &FrRaw) -> [u8; 20] {
    let mut pubkey = [0u8; 64];
    for i in 0..4 {
        pubkey[i * 8..i * 8 + 8].copy_from_slice(&px[3 - i].to_be_bytes());
        pubkey[32 + i * 8..32 + i * 8 + 8].copy_from_slice(&py[3 - i].to_be_bytes());
    }
    let hash = keccak256_short(&pubkey);
    hash[12..].try_into().unwrap()
}

/// Pack a 20-byte big-endian Ethereum address into an FrRaw (uint160 LE limbs).
fn address_to_fr(addr: &[u8; 20]) -> FrRaw {
    [
        u64::from_be_bytes([addr[12], addr[13], addr[14], addr[15], addr[16], addr[17], addr[18], addr[19]]),
        u64::from_be_bytes([addr[4], addr[5], addr[6], addr[7], addr[8], addr[9], addr[10], addr[11]]),
        u32::from_be_bytes([addr[0], addr[1], addr[2], addr[3]]) as u64,
        0,
    ]
}

/// Verify CSP ECDSA proofs for all voters.
///
/// Returns `(ok, census_root_fr)` where `census_root_fr` is the CSP's Ethereum address
/// as an FrRaw (used as the census root output).
///
/// # Fail-mask bits
/// - `FAIL_CSP` (bit 23) — CSP signature verification or address check failed
pub fn verify_csp(
    csp: &CspBlock,
    process_id: &FrRaw,
    fail_mask: &mut u32,
) -> (bool, FrRaw) {
    if csp.entries.is_empty() {
        *fail_mask |= FAIL_CSP;
        return (false, ZERO_FR);
    }

    // Derive the CSP's Ethereum address (this IS the census root).
    let csp_addr = eth_address_from_pk(&csp.csp_pub_key_x, &csp.csp_pub_key_y);
    let census_root = address_to_fr(&csp_addr);

    let pk = SyscallPoint256 { x: csp.csp_pub_key_x, y: csp.csp_pub_key_y };

    // ── Invariant 1: no duplicate (voter_address, index) pairs ──────────────
    let n = csp.entries.len();
    for i in 0..n {
        for j in (i + 1)..n {
            if csp.entries[i].voter_address == csp.entries[j].voter_address
                && csp.entries[i].index == csp.entries[j].index
            {
                *fail_mask |= FAIL_CSP;
                return (false, census_root);
            }
        }
    }

    // ── Invariant 2: each CSP signature is valid ────────────────────────────
    for entry in &csp.entries {
        let z = csp_message_hash(process_id, &entry.voter_address, &entry.weight, entry.index);
        if !secp256k1_ecdsa_verify(&pk, &z, &entry.r, &entry.s) {
            *fail_mask |= FAIL_CSP;
            return (false, census_root);
        }
    }

    (true, census_root)
}
