//! Cryptographic hash functions backed by ZisK hardware precompiles.
//!
//! Both wrappers delegate to the high-level streamed implementations in
//! `ziskos::zisklib`, which call the underlying `sha256f` / `keccak_f`
//! precompiles. They avoid the heap allocations of a hand-rolled
//! padded-buffer + flatten approach — relevant for the SMT path where
//! `sha256_once` is called ~2.5×10⁵ times per 256-voter batch.

use crate::types::{FrRaw, ZERO_FR};
use ziskos::zisklib::{keccak256, sha256};

/// Compute SHA-256 of `data` using the ZisK `sha256f` hardware precompile.
/// Arbitrary length; streams blocks without per-call heap allocation.
#[inline]
pub fn sha256_once(data: &[u8]) -> [u8; 32] {
    sha256(data)
}

/// Compute Keccak-256 of `data` using the ZisK `keccak_f` hardware precompile.
///
/// **Padding**: Keccak-256 (domain byte `0x01`), not SHA3-256 (`0x06`) —
/// matches `go-ethereum/crypto.Keccak256`.
#[inline]
pub fn keccak256_short(data: &[u8]) -> [u8; 32] {
    keccak256(data)
}

/// Compute the arbo leaf value for the encryption key: SHA-256(X_BE32 || Y_BE32) → FrRaw.
/// This encoding matches the sequencer's convention for storing a BabyJubJub public key
/// as a single 256-bit value in the arbo SHA-256 state tree (config key 0x03).
pub fn hash_enc_key(x: &FrRaw, y: &FrRaw) -> FrRaw {
    let mut buf = [0u8; 64];
    // FrRaw [u64;4] LE limbs → 32-byte big-endian (arbo convention for hash inputs)
    for (i, &limb) in x.iter().enumerate() {
        let bytes = limb.to_be_bytes();
        let dst = (3 - i) * 8;
        buf[dst..dst + 8].copy_from_slice(&bytes);
    }
    for (i, &limb) in y.iter().enumerate() {
        let bytes = limb.to_be_bytes();
        let dst = 32 + (3 - i) * 8;
        buf[dst..dst + 8].copy_from_slice(&bytes);
    }
    let digest = sha256_once(&buf);
    digest_to_fr(&digest)
}

/// Compute the arbo leaf value for the ballot verification key: SHA-256 over the
/// raw VK wire bytes (alpha_g1 ‖ beta_g2 ‖ gamma_g2 ‖ delta_g2 ‖ gamma_abc_len ‖
/// gamma_abc[..], LE u64 limbs as they appear in the batch input) → FrRaw.
/// Stored in the state tree at config key 0x07 so the VK is pinned per process.
pub fn hash_vk_bytes(vk_bytes: &[u8]) -> FrRaw {
    digest_to_fr(&sha256_once(vk_bytes))
}

/// 32-byte hash (big-endian) → FrRaw [u64;4] LE limbs.
fn digest_to_fr(digest: &[u8; 32]) -> FrRaw {
    let mut fr = ZERO_FR;
    for i in 0..4 {
        let off = (3 - i) * 8;
        fr[i] = u64::from_be_bytes(digest[off..off + 8].try_into().unwrap());
    }
    fr
}
