//! Cryptographic hash functions backed by ZisK hardware precompiles.
//!
//! Both wrappers delegate to the high-level streamed implementations in
//! `ziskos::zisklib`, which call the underlying `sha256f` / `keccak_f`
//! precompiles. They avoid the heap allocations of a hand-rolled
//! padded-buffer + flatten approach — relevant for the SMT path where
//! `sha256_once` is called ~5×10⁵ times per 512-voter batch.

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
