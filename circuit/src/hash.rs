//! Cryptographic hash functions backed by ZisK hardware precompiles.
//!
//! Both functions use hardware-accelerated ZisK precompiles:
//! - [`sha256_once`]: SHA-256 via ZisK's SHA-256 helper on top of `sha256_f`
//! - [`keccak256_short`]: Keccak-256 via `keccak_f` (N = 2¹⁷ rows, 25 rows/permutation)

#[cfg(not(test))]
use ziskos::{syscalls::syscall_keccak_f, zisklib::sha256};

/// Compute SHA-256 of `data` using ZisK's SHA-256 helper.
///
/// Supports arbitrary-length input via standard SHA-256 Merkle–Damgård padding.
pub fn sha256_once(data: &[u8]) -> [u8; 32] {
    #[cfg(test)]
    {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        return hasher.finalize().into();
    }

    #[cfg(not(test))]
    {
        sha256(data)
    }
}

/// Compute Keccak-256 of `data` using the ZisK `keccak_f` hardware precompile.
///
/// Accepts inputs up to 135 bytes: fits in one Keccak block (rate = 136 bytes).
/// This covers both use cases in this circuit:
/// - 60 bytes: Ethereum signed-message envelope (for ECDSA `z` scalar)
/// - 64 bytes: uncompressed secp256k1 public key (for Ethereum address derivation)
///
/// **Padding**: Keccak-256 (domain byte `0x01`), not SHA3-256 (`0x06`).
/// This matches `go-ethereum/crypto.Keccak256`.
pub fn keccak256_short(data: &[u8]) -> [u8; 32] {
    #[cfg(test)]
    {
        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();
        hasher.update(data);
        return hasher.finalize().into();
    }

    #[cfg(not(test))]
    {
        assert!(
            data.len() < 136,
            "keccak256_short: input must be < 136 bytes"
        );
        // Keccak state: 25 × u64 lanes = 200 bytes, initialised to zero.
        // Bytes are packed into lanes in little-endian order:
        //   byte[i] lives in lane[i/8] at bit position (i%8)*8.
        let mut state = [0u64; 25];
        for (i, &b) in data.iter().enumerate() {
            state[i / 8] ^= (b as u64) << ((i % 8) * 8);
        }
        // Keccak-256 multi-rate padding: append 0x01 after message, 0x80 at byte 135.
        let pad = data.len();
        state[pad / 8] ^= 0x01u64 << ((pad % 8) * 8);
        state[135 / 8] ^= 0x80u64 << ((135 % 8) * 8);
        unsafe {
            syscall_keccak_f(&mut state as *mut [u64; 25]);
        }
        // Extract first 32 bytes from the LE-lane state.
        let mut out = [0u8; 32];
        for i in 0..32usize {
            out[i] = (state[i / 8] >> ((i % 8) * 8)) as u8;
        }
        out
    }
}
