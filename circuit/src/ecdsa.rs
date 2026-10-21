//! Ethereum secp256k1 ECDSA signature batch verification via public-key recovery.
//!
//! Each ballot carries an ECDSA signature over its vote envelope, produced with the
//! standard Ethereum personal-sign scheme over a 32-byte digest:
//!
//! ```text
//! ballot   = sha256(c1x ‖ c1y ‖ c2x ‖ c2y of the 16 original fields, BE32 each)  // 2048 B
//! digest   = keccak256("davinci-vote-v1" ‖ process_id_BE32 ‖ vote_id_BE8 ‖ ballot)  // 87 B
//! z        = keccak256("\x19Ethereum Signed Message:\n32" ‖ digest)   // as a big-endian integer
//! sig      = secp256k1.Sign(z, privKey)        // R[32] || S[32] || V[1]
//! ```
//!
//! The ballot is the one proof `i` was verified against: public inputs 7..70,
//! the original ciphertexts with the identity above `num_fields`. A signature
//! therefore binds one process, one vote id and one set of ciphertexts.
//!
//! Rather than carrying the public key in the witness and running
//! `ecdsa_verify_secp256k1(pk, z, r, s)`, we use the recovery form
//! `ecdsa_recover_secp256k1(r, s, z, recid) -> pk`. The recovered point is
//! guaranteed on-curve by the precompile; we then derive the Ethereum
//! address and bind it to the matching ballot proof's public input 0 (the
//! census address, see `publics.rs`):
//!
//! ```text
//! address = keccak256(pk.x_BE32 || pk.y_BE32)[12..]   // 20-byte Ethereum address
//! assert address == public input 0
//! ```

use crate::hash::keccak256_short;
use crate::io::ParsedInput;
use crate::publics::{Publics, PUB_FIELDS};
use crate::results::ballot_leaf_hash;
use crate::types::{BallotData, FrRaw, BALLOT_FIELDS, FAIL_ECDSA, ZERO_FR};
use ziskos::zisklib::ecdsa_recover_secp256k1;

/// Domain tag of the vote envelope, 15 ASCII bytes, no length prefix.
const VOTE_TAG: &[u8; 15] = b"davinci-vote-v1";

/// FrRaw (LE limbs) as 32 big-endian bytes.
fn fr_be(x: &FrRaw) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..i * 8 + 8].copy_from_slice(&x[3 - i].to_be_bytes());
    }
    out
}

/// The personal-sign hash of a vote envelope digest, as a `[u64; 4]` LE scalar.
fn vote_message_hash(process_id: &FrRaw, vote_id: u64, ballot: &BallotData) -> [u64; 4] {
    let mut pre = [0u8; 87];
    pre[..15].copy_from_slice(VOTE_TAG);
    pre[15..47].copy_from_slice(&fr_be(process_id));
    pre[47..55].copy_from_slice(&vote_id.to_be_bytes());
    // ballot_leaf_hash returns the digest read big-endian: fr_be gives its raw bytes.
    pre[55..].copy_from_slice(&fr_be(&ballot_leaf_hash(ballot)));
    let digest = keccak256_short(&pre);
    // Prefix: "\x19Ethereum Signed Message:\n32" = 28 bytes
    const PREFIX: &[u8] = b"\x19Ethereum Signed Message:\n32";
    let mut envelope = [0u8; 60];
    envelope[..28].copy_from_slice(PREFIX);
    envelope[28..].copy_from_slice(&digest);
    let h = keccak256_short(&envelope);
    // Interpret the 32-byte hash as a big-endian 256-bit integer, store as [u64; 4] LE.
    [
        u64::from_be_bytes(h[24..32].try_into().unwrap()),
        u64::from_be_bytes(h[16..24].try_into().unwrap()),
        u64::from_be_bytes(h[8..16].try_into().unwrap()),
        u64::from_be_bytes(h[0..8].try_into().unwrap()),
    ]
}

/// Derive the 20-byte big-endian Ethereum address from a recovered secp256k1 pk.
/// `pk_le[0..4]` is px LE limbs, `pk_le[4..8]` is py LE limbs (the layout
/// returned by `ecdsa_recover_secp256k1`).
fn eth_address_from_recovered_pk(pk_le: &[u64; 8]) -> [u8; 20] {
    let mut pubkey = [0u8; 64];
    for i in 0..4 {
        pubkey[i * 8..i * 8 + 8].copy_from_slice(&pk_le[3 - i].to_be_bytes());
        pubkey[32 + i * 8..32 + i * 8 + 8].copy_from_slice(&pk_le[4 + 3 - i].to_be_bytes());
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

/// Verify all ECDSA signatures in `parsed.ecdsa` via public-key recovery,
/// each over the vote envelope of its proof: the process id, the vote id the
/// guest derived and the original ciphertexts the proof was verified against.
///
/// Returns `ecdsa_ok = false` when any signature or address binding check fails.
///
/// # Fail-mask bits
/// - `FAIL_ECDSA` (bit 3): signature recovery or address-binding check failed,
///   the ECDSA block is absent, or the public inputs could not be derived.
pub fn verify_batch(parsed: &ParsedInput, publics: Option<&Publics>, fail_mask: &mut u32) -> bool {
    let Some(publics) = publics else {
        *fail_mask |= FAIL_ECDSA;
        return false;
    };
    if parsed.ecdsa.is_empty() {
        // ECDSA block is mandatory; treat absence as failure.
        *fail_mask |= FAIL_ECDSA;
        return false;
    }
    // ECDSA count must match proof count (guaranteed by io.rs, checked defensively).
    if parsed.ecdsa.len() != parsed.proofs.len() {
        *fail_mask |= FAIL_ECDSA;
        return false;
    }
    let process_id = publics.constants[0];
    let mut ballot = [ZERO_FR; BALLOT_FIELDS];
    for (i, sig) in parsed.ecdsa.iter().enumerate() {
        ballot.copy_from_slice(&publics.proof(i)[PUB_FIELDS..]);
        let z = vote_message_hash(&process_id, publics.vote_id(i), &ballot);

        // Recover the public key. ecdsa_recover_secp256k1 returns Err for invalid
        // r/s/recid, point-not-on-curve, etc. — all collapse to FAIL_ECDSA.
        let pk_le = match ecdsa_recover_secp256k1(&sig.r, &sig.s, &z, sig.recid) {
            Ok(pk) => pk,
            Err(_) => {
                *fail_mask |= FAIL_ECDSA;
                return false;
            }
        };
        let addr = eth_address_from_recovered_pk(&pk_le);
        if !address_matches(&addr, &publics.address(i)) {
            *fail_mask |= FAIL_ECDSA;
            return false;
        }
    }
    true
}
