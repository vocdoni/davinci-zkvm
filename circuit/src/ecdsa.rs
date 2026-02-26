//! Ethereum secp256k1 ECDSA signature batch verification.
//!
//! Each ballot carries an ECDSA signature over its `vote_id`, produced with the
//! standard Ethereum personal-sign scheme (matching `davinci-node/crypto/signatures/ethereum`):
//!
//! ```text
//! message  = PadToSign(vote_id_BE8)            // 32 bytes: 24 zero prefix + 8-byte BE vote_id
//! envelope = "\x19Ethereum Signed Message:\n32" || message   // 60 bytes total
//! z        = keccak256(envelope)               // as big-endian 256-bit integer → [u64;4] LE
//! sig      = secp256k1.Sign(z, privKey)        // R[32] || S[32] || V[1]
//! ```
//!
//! In addition to the signature check, we verify that the public key hashes to the
//! Ethereum address declared as the first public input of the matching ballot proof:
//!
//! ```text
//! address = keccak256(pk.x_BE32 || pk.y_BE32)[12..]   // 20-byte Ethereum address
//! assert address == pubs[0]
//! ```

use crate::hash::keccak256_short;
use crate::io::ParsedInput;
use crate::types::FrRaw;
use ziskos::syscalls::SyscallPoint256;
use ziskos::zisklib::secp256k1_ecdsa_verify;

/// Compute the Ethereum signed-message hash of `vote_id` as a `[u64; 4]` LE scalar.
///
/// The result is used as `z` in `secp256k1_ecdsa_verify(pk, z, r, s)`.
fn eth_message_hash(vote_id: u64) -> [u64; 4] {
    // Prefix: "\x19Ethereum Signed Message:\n32" = 28 bytes
    const PREFIX: &[u8] = b"\x19Ethereum Signed Message:\n32";
    let mut envelope = [0u8; 60];
    envelope[..28].copy_from_slice(PREFIX);
    // PadToSign: 24 zero bytes (already zeroed) followed by 8-byte big-endian vote_id
    envelope[52..].copy_from_slice(&vote_id.to_be_bytes());
    let h = keccak256_short(&envelope);
    // Interpret the 32-byte hash as a big-endian 256-bit integer, store as [u64; 4] LE.
    [
        u64::from_be_bytes(h[24..32].try_into().unwrap()),
        u64::from_be_bytes(h[16..24].try_into().unwrap()),
        u64::from_be_bytes(h[8..16].try_into().unwrap()),
        u64::from_be_bytes(h[0..8].try_into().unwrap()),
    ]
}

/// Derive the 20-byte big-endian Ethereum address from a secp256k1 public key.
///
/// `address = keccak256(px_BE32 || py_BE32)[12..]`
///
/// Inputs `px`/`py` are `[u64; 4]` little-endian (standard ZisK representation).
fn eth_address_from_pk(px: &FrRaw, py: &FrRaw) -> [u8; 20] {
    let mut pubkey = [0u8; 64];
    for i in 0..4 {
        pubkey[i * 8..i * 8 + 8].copy_from_slice(&px[3 - i].to_be_bytes());
        pubkey[32 + i * 8..32 + i * 8 + 8].copy_from_slice(&py[3 - i].to_be_bytes());
    }
    keccak256_short(&pubkey)[12..].try_into().unwrap()
}

/// Compare a 20-byte big-endian Ethereum address against a BN254 Fr element (uint160).
///
/// The Fr element stores the uint160 as `[u64; 4]` LE: `fr[0]` = lower 64 bits, etc.
fn address_matches(addr_bytes: &[u8; 20], pubs_addr: &FrRaw) -> bool {
    let mut expected = [0u8; 20];
    expected[0..4].copy_from_slice(&(pubs_addr[2] as u32).to_be_bytes());
    expected[4..12].copy_from_slice(&pubs_addr[1].to_be_bytes());
    expected[12..20].copy_from_slice(&pubs_addr[0].to_be_bytes());
    addr_bytes == &expected
}

/// Verify all ECDSA signatures in `parsed.ecdsa`.
///
/// Returns `ecdsa_ok = false` when any signature or address binding check fails.
///
/// # Fail-mask bits
/// - Bit 3 — ECDSA signature or address-binding check failed (or ECDSA block missing)
pub fn verify_batch(parsed: &ParsedInput, fail_mask: &mut u32) -> bool {
    if parsed.ecdsa.is_empty() {
        // ECDSA block is mandatory; treat absence as failure
        *fail_mask |= 1 << 3;
        return false;
    }
    // Public input layout: pubs[0] = address (uint160), pubs[1] = vote_id (uint64)
    if parsed.n_public < 2 {
        *fail_mask |= 1 << 3;
        return false;
    }
    for (i, sig) in parsed.ecdsa.iter().enumerate() {
        let pubs    = &parsed.proofs[i].public_inputs;
        let vote_id = pubs[1][0]; // vote_id fits in u64; upper limbs are 0
        let pk      = SyscallPoint256 { x: sig.px, y: sig.py };
        let z       = eth_message_hash(vote_id);

        if !secp256k1_ecdsa_verify(&pk, &z, &sig.r, &sig.s) {
            *fail_mask |= 1 << 3;
            return false;
        }
        let addr = eth_address_from_pk(&sig.px, &sig.py);
        if !address_matches(&addr, &pubs[0]) {
            *fail_mask |= 1 << 3;
            return false;
        }
    }
    true
}
