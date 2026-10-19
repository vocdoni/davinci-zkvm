//! Cryptographic hash functions backed by ZisK hardware precompiles.
//!
//! Both wrappers delegate to the high-level streamed implementations in
//! `ziskos::zisklib`, which call the underlying `sha256f` / `keccak_f`
//! precompiles. They avoid the heap allocations of a hand-rolled
//! padded-buffer + flatten approach — relevant for the SMT path where
//! `sha256_once` is called ~2.5×10⁵ times per 256-voter batch.

use crate::types::{FrRaw, ZERO_FR};
use ziskos::syscalls::{syscall_sha256_f, SyscallSha256Params};
use ziskos::zisklib::{keccak256, sha256};

// The one-shot helpers below read message bytes as little-endian u64 words,
// which is how `sha256f` sees memory only on a little-endian target.
const _: () = assert!(cfg!(target_endian = "little"));

/// SHA-256 initial hash value in the `sha256f` state layout: the eight u32
/// words in order, two per u64, low half first.
pub(crate) const SHA256_IV: [u64; 4] = [
    0xbb67ae85_6a09e667,
    0xa54ff53a_3c6ef372,
    0x9b05688c_510e527f,
    0x5be0cd19_1f83d9ab,
];

/// One `sha256f` compression. `block` holds the 64 message bytes as
/// little-endian u64 words (bytes in memory order); padding is the caller's.
/// Fixed-size callers use this instead of `sha256_once` to skip the
/// streaming wrapper's copies and final-block assembly.
#[inline(always)]
pub(crate) fn sha256_compress(state: &mut [u64; 4], block: &[u64; 8]) {
    let mut params = SyscallSha256Params { state, input: block };
    syscall_sha256_f(&mut params);
}

/// Final state -> the digest read as a big-endian 256-bit integer, LE limbs
/// (`digest_to_fr` of the digest bytes).
#[inline(always)]
pub(crate) fn sha256_state_to_fr_be(s: &[u64; 4]) -> FrRaw {
    [s[3].rotate_left(32), s[2].rotate_left(32), s[1].rotate_left(32), s[0].rotate_left(32)]
}

/// Final state -> the digest bytes read as little-endian limbs (arbo).
#[inline(always)]
pub(crate) fn sha256_state_to_fr_le(s: &[u64; 4]) -> FrRaw {
    [
        s[0].swap_bytes().rotate_left(32),
        s[1].swap_bytes().rotate_left(32),
        s[2].swap_bytes().rotate_left(32),
        s[3].swap_bytes().rotate_left(32),
    ]
}

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

/// Census lean-IMT node: `keccak256(be32(l) || be32(r))` read big-endian, as
/// LE limbs like every census value (Solidity `keccak256(abi.encode(l, r))`).
/// Full 256-bit output, never reduced.
pub fn keccak_node(l: &FrRaw, r: &FrRaw) -> FrRaw {
    let mut buf = [0u8; 64];
    for i in 0..4 {
        buf[i * 8..i * 8 + 8].copy_from_slice(&l[3 - i].to_be_bytes());
        buf[32 + i * 8..32 + i * 8 + 8].copy_from_slice(&r[3 - i].to_be_bytes());
    }
    digest_to_fr(&keccak256_short(&buf))
}

/// Streaming SHA-256 over u64 words, each word's bytes in little-endian order
/// (the memory layout `sha256f` reads). Hashes a long transcript block by
/// block instead of materialising it.
pub struct Sha256Words {
    state: [u64; 4],
    block: [u64; 8],
    used: usize,
    words: u64,
}

impl Default for Sha256Words {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256Words {
    pub fn new() -> Self {
        Sha256Words { state: SHA256_IV, block: [0; 8], used: 0, words: 0 }
    }

    #[inline]
    pub fn push(&mut self, w: u64) {
        self.block[self.used] = w;
        self.used += 1;
        self.words += 1;
        if self.used == 8 {
            sha256_compress(&mut self.state, &self.block);
            self.used = 0;
        }
    }

    #[inline]
    pub fn push_all(&mut self, ws: &[u64]) {
        for w in ws {
            self.push(*w);
        }
    }

    /// The digest of the `8 * words`-byte message (FIPS 180-4 padding).
    pub fn finish(mut self) -> [u8; 32] {
        // 0x80 is the first byte after the message: the low byte of the next word.
        self.block[self.used] = 0x80;
        for w in &mut self.block[self.used + 1..] {
            *w = 0;
        }
        if self.used == 7 {
            sha256_compress(&mut self.state, &self.block);
            self.block = [0; 8];
        }
        // The bit length, big-endian, in the last 8 bytes.
        self.block[7] = (self.words * 64).swap_bytes();
        sha256_compress(&mut self.state, &self.block);
        let mut out = [0u8; 32];
        for (i, w) in self.state.iter().enumerate() {
            out[i * 8..i * 8 + 4].copy_from_slice(&(*w as u32).to_be_bytes());
            out[i * 8 + 4..i * 8 + 8].copy_from_slice(&((*w >> 32) as u32).to_be_bytes());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_words_matches_one_shot() {
        // Lengths around the block boundaries: 0..=24 words (0..=192 bytes).
        for n in 0..=24u64 {
            let words: std::vec::Vec<u64> = (0..n).map(|i| i.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ 0xdead_beef).collect();
            let mut bytes = std::vec::Vec::new();
            for w in &words {
                bytes.extend_from_slice(&w.to_le_bytes());
            }
            let mut h = Sha256Words::new();
            h.push_all(&words);
            assert_eq!(h.finish(), sha256_once(&bytes), "{n} words");
        }
    }

    #[test]
    fn keccak_node_matches_solidity() {
        // cast keccak $(cast abi-encode "f(uint256,uint256)" 1 2)
        let want: FrRaw = [0x44d599ccd2a7c2e0, 0xc83a08bbccc01a06, 0x18fb78d8ee546e97, 0xe90b7bceb6e7df54];
        assert_eq!(keccak_node(&[1, 0, 0, 0], &[2, 0, 0, 0]), want);
        // keccak256 of 64 zero bytes.
        let zero: FrRaw = [0x405849e597ba5fb5, 0x2b36e491b30a40b2, 0x4284a5443f17f196, 0xad3228b676f7d3cd];
        assert_eq!(keccak_node(&ZERO_FR, &ZERO_FR), zero);
    }
}
