//! CSP (Credential Service Provider) ECDSA census verification via key recovery.
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
//! 1. Reconstruct `z` from (processID, voter_address, weight, index).
//! 2. `pk_i = ecdsa_recover_secp256k1(r, s, z, recid)` — recovers the signer.
//! 3. First entry: `census_root = eth_address(pk_0)`.
//! 4. Subsequent entries: assert `pk_i == pk_0` (8×u64 equality, no keccak needed).
//!
//! Saves N−1 keccak256 calls vs deriving address each entry, and removes the
//! CSP pk from the witness entirely.
//!
//! # Security invariants
//!
//! - All entries recover to the same secp256k1 public key (single authorised CSP)
//! - No duplicate (voter_address, index) pairs
//! - The recovered CSP address is exported as the census root; the caller binds
//!   it to the process-config census-root key.

use crate::hash::keccak256_short;
use crate::types::{CspBlock, FrRaw, FAIL_CSP, ZERO_FR};
use ziskos::zisklib::ecdsa_recover_secp256k1;

/// Compute the Ethereum signed-message hash for a CSP attestation.
fn csp_message_hash(process_id: &FrRaw, voter_address: &FrRaw, weight: &FrRaw, index: u64) -> [u64; 4] {
    // Prefix: "\x19Ethereum Signed Message:\n92" = 28 bytes
    const PREFIX: &[u8] = b"\x19Ethereum Signed Message:\n92";
    let mut envelope = [0u8; 120]; // 28 + 32 + 20 + 32 + 8

    envelope[..28].copy_from_slice(PREFIX);

    // processID: FrRaw [u64;4] LE → 32-byte big-endian
    for i in 0..4 {
        let bytes = process_id[3 - i].to_be_bytes();
        envelope[28 + i * 8..28 + i * 8 + 8].copy_from_slice(&bytes);
    }

    // voter_address: uint160 in FrRaw LE → 20-byte big-endian
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
    [
        u64::from_be_bytes(h[24..32].try_into().unwrap()),
        u64::from_be_bytes(h[16..24].try_into().unwrap()),
        u64::from_be_bytes(h[8..16].try_into().unwrap()),
        u64::from_be_bytes(h[0..8].try_into().unwrap()),
    ]
}

/// Convert a uint160 stored as FrRaw LE limbs to a 20-byte big-endian Ethereum address.
fn fr_to_address(fr: &FrRaw) -> [u8; 20] {
    let mut addr = [0u8; 20];
    addr[0..4].copy_from_slice(&(fr[2] as u32).to_be_bytes());
    addr[4..12].copy_from_slice(&fr[1].to_be_bytes());
    addr[12..20].copy_from_slice(&fr[0].to_be_bytes());
    addr
}

/// Derive the 20-byte Ethereum address from a recovered secp256k1 public key
/// stored as `[u64; 8]` (px LE limbs, then py LE limbs).
fn eth_address_from_recovered_pk(pk_le: &[u64; 8]) -> [u8; 20] {
    let mut pubkey = [0u8; 64];
    for i in 0..4 {
        pubkey[i * 8..i * 8 + 8].copy_from_slice(&pk_le[3 - i].to_be_bytes());
        pubkey[32 + i * 8..32 + i * 8 + 8].copy_from_slice(&pk_le[4 + 3 - i].to_be_bytes());
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

/// Verify CSP ECDSA proofs for all voters via public-key recovery.
/// Returns `(ok, census_root_fr)` where `census_root_fr` is the recovered CSP's
/// Ethereum address as an FrRaw (used as the census root output).
///
/// # Fail-mask bits
/// - `FAIL_CSP` (bit 23): signature recovery, key-mismatch, or duplicate check failed
pub fn verify_csp(
    csp: &CspBlock,
    process_id: &FrRaw,
    fail_mask: &mut u32,
) -> (bool, FrRaw) {
    if csp.entries.is_empty() {
        *fail_mask |= FAIL_CSP;
        return (false, ZERO_FR);
    }

    let n = csp.entries.len();

    // Invariant 1: no duplicate (voter_address, index) pairs.
    for i in 0..n {
        for j in (i + 1)..n {
            if csp.entries[i].voter_address == csp.entries[j].voter_address
                && csp.entries[i].index == csp.entries[j].index
            {
                *fail_mask |= FAIL_CSP;
                return (false, ZERO_FR);
            }
        }
    }

    // Recover pk from the first entry → census_root = eth_address(pk_0).
    let first = &csp.entries[0];
    let z0 = csp_message_hash(process_id, &first.voter_address, &first.weight, first.index);
    let pk0 = match ecdsa_recover_secp256k1(&first.r, &first.s, &z0, first.recid) {
        Ok(pk) => pk,
        Err(_) => {
            *fail_mask |= FAIL_CSP;
            return (false, ZERO_FR);
        }
    };
    let census_root = address_to_fr(&eth_address_from_recovered_pk(&pk0));

    // Invariant 2: every remaining entry recovers to the same public key.
    for entry in &csp.entries[1..] {
        let z = csp_message_hash(process_id, &entry.voter_address, &entry.weight, entry.index);
        match ecdsa_recover_secp256k1(&entry.r, &entry.s, &z, entry.recid) {
            Ok(pk) if pk == pk0 => {}
            _ => {
                *fail_mask |= FAIL_CSP;
                return (false, census_root);
            }
        }
    }

    (true, census_root)
}
