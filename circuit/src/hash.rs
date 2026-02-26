//! Cryptographic hash functions backed by ZisK hardware precompiles.
//!
//! Both functions use hardware-accelerated ZisK precompiles:
//! - [`sha256_once`]: SHA-256 via `sha256f` (N = 2²² rows, 72 rows/block)
//! - [`keccak256_short`]: Keccak-256 via `keccak_f` (N = 2¹⁷ rows, 25 rows/permutation)

use ziskos::{syscalls::syscall_keccak_f, zisklib::sha256f_compress};

/// Compute SHA-256 of `data` using the ZisK `sha256f` hardware precompile.
///
/// Supports arbitrary-length input via standard SHA-256 Merkle–Damgård padding.
pub fn sha256_once(data: &[u8]) -> [u8; 32] {
    let mut state = [
        0x6a09e667u32, 0xbb67ae85u32, 0x3c6ef372u32, 0xa54ff53au32,
        0x510e527fu32, 0x9b05688cu32, 0x1f83d9abu32, 0x5be0cd19u32,
    ];
    let bit_len = (data.len() as u64) * 8;
    let len = data.len();
    let padded_len = ((len + 9 + 63) / 64) * 64;
    let mut padded = vec![0u8; padded_len];
    padded[..len].copy_from_slice(data);
    padded[len] = 0x80;
    padded[padded_len - 8..].copy_from_slice(&bit_len.to_be_bytes());
    let n_blocks = padded_len / 64;
    let mut blocks: Vec<[u8; 64]> = Vec::with_capacity(n_blocks);
    for i in 0..n_blocks {
        blocks.push(padded[i * 64..(i + 1) * 64].try_into().unwrap());
    }
    sha256f_compress(&mut state, &blocks);
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4..(i + 1) * 4].copy_from_slice(&state[i].to_be_bytes());
    }
    out
}

/// Compute Keccak-256 of `data` using the ZisK `keccak_f` hardware precompile.
///
/// Accepts inputs up to 135 bytes — fits in one Keccak block (rate = 136 bytes).
/// This covers both use cases in this circuit:
/// - 60 bytes: Ethereum signed-message envelope (for ECDSA `z` scalar)
/// - 64 bytes: uncompressed secp256k1 public key (for Ethereum address derivation)
///
/// **Padding**: Keccak-256 (domain byte `0x01`), not SHA3-256 (`0x06`).
/// This matches `go-ethereum/crypto.Keccak256`.
pub fn keccak256_short(data: &[u8]) -> [u8; 32] {
    assert!(data.len() < 136, "keccak256_short: input must be < 136 bytes");
    // Keccak state: 25 × u64 lanes = 200 bytes, initialised to zero.
    // Bytes are packed into lanes in little-endian order:
    //   byte[i] lives in lane[i/8] at bit position (i%8)*8.
    let mut state = [0u64; 25];
    for (i, &b) in data.iter().enumerate() {
        state[i / 8] ^= (b as u64) << ((i % 8) * 8);
    }
    // Keccak-256 multi-rate padding: append 0x01 after message, 0x80 at byte 135.
    let pad = data.len();
    state[pad / 8]   ^= 0x01u64 << ((pad % 8) * 8);
    state[135 / 8]   ^= 0x80u64 << ((135 % 8) * 8);
    syscall_keccak_f(&mut state as *mut [u64; 25]);
    // Extract first 32 bytes from the LE-lane state.
    let mut out = [0u8; 32];
    for i in 0..32usize {
        out[i] = (state[i / 8] >> ((i % 8) * 8)) as u8;
    }
    out
}
