//! Data-availability blob cell layout for the vote-batch guest.
//!
//! Cells are 32-byte big-endian BLS12-381 Fr elements. The guest rebuilds
//! them from verified data, packs them into 4096-cell blobs, and evaluates
//! each blob polynomial at the point derived from that blob's commitment.
//!
//! Layout (byte-exact; the Go producer and the settlement contract mirror it):
//!
//! ```text
//! enc_u64(n_vids)
//! enc_u64(vid_0) .. enc_u64(vid_{n_vids-1})          // ASCENDING
//! enc_u64(n_updates)
//! for each (key, ballot) update, ASCENDING by key (stable):
//!     enc_u64(key)
//!     pack(c1_0) pack(c2_0) .. pack(c1_{nf-1}) pack(c2_{nf-1})
//! for f in 0..nf:
//!     pack(acc_c1_f) pack(acc_c2_f)                  // NEW net accumulator
//! zero cells to end of last blob
//! ```
//!
//! `enc_u64(v)`   = `v` as a 32-byte big-endian integer.
//! `pack(x, y)`   = `y_canon + ((x_canon & 1) << 254)` as 32-byte big-endian,
//!                  with `x_canon`, `y_canon` = coords reduced mod BN254 Fr.
//!                  Fits in BLS12-381 Fr since `p_bn254 + 2^254 < r_bls`.
//!                  The TE identity `(0,1)` packs to `1`.

use crate::bn254_fr;
use crate::hash::sha256_once;
use crate::types::{BallotData, FrRaw};
extern crate alloc;
use alloc::vec::Vec;

/// Cells per EIP-4844 blob (identical to `kzg::N`).
pub const CELLS_PER_BLOB: usize = 4096;

/// Encode a u64 as a 32-byte big-endian integer.
#[inline]
pub fn enc_u64(v: u64) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[24..32].copy_from_slice(&v.to_be_bytes());
    b
}

/// Pack a TE point (x, y) into a 32-byte big-endian BLS12-381 Fr element:
/// `y_canon + ((x_canon & 1) << 254)`, with both coords reduced mod BN254 Fr.
#[inline]
pub fn pack_te(x: &FrRaw, y: &FrRaw) -> [u8; 32] {
    let xc = bn254_fr::reduce(x);
    let yc = bn254_fr::reduce(y);
    // BE bytes of y_canon: LS limb 0 -> bytes 24..32, MS limb 3 -> bytes 0..8.
    let mut out = [0u8; 32];
    for i in 0..4 {
        let start = (3 - i) * 8;
        out[start..start + 8].copy_from_slice(&yc[i].to_be_bytes());
    }
    // BN254 Fr < 2^254, so bit 254 of y_canon is 0 — no collision with the tag.
    if xc[0] & 1 == 1 {
        out[0] |= 0x40; // bit 254
    }
    out
}

/// Total cell count `T = 2 + n_vids + n_updates * (1 + 2 * nf) + 2 * nf`.
#[inline]
pub fn total_cells(n_vids: usize, n_updates: usize, nf: usize) -> usize {
    2 + n_vids + n_updates * (1 + 2 * nf) + 2 * nf
}

/// Number of blobs needed for `t` cells: `ceil(t / 4096)`.
#[inline]
pub fn n_blobs_from_t(t: usize) -> usize {
    t.div_ceil(CELLS_PER_BLOB)
}

/// Build the DA blob cells from pre-sorted inputs. The caller sorts vote ids
/// ascending and the updates ascending by key (stable, ballot-chain first
/// among equal keys). Padded fields `f >= nf` are not emitted.
pub fn build_cells(
    sorted_vote_ids: &[u64],
    sorted_updates: &[(u64, BallotData)],
    net: &BallotData,
    nf: usize,
) -> Vec<[u8; 32]> {
    let t = total_cells(sorted_vote_ids.len(), sorted_updates.len(), nf);
    let mut cells: Vec<[u8; 32]> = Vec::with_capacity(t);
    cells.push(enc_u64(sorted_vote_ids.len() as u64));
    for v in sorted_vote_ids {
        cells.push(enc_u64(*v));
    }
    cells.push(enc_u64(sorted_updates.len() as u64));
    for (key, ballot) in sorted_updates {
        cells.push(enc_u64(*key));
        for f in 0..nf {
            let base = f * 4;
            cells.push(pack_te(&ballot[base], &ballot[base + 1]));
            cells.push(pack_te(&ballot[base + 2], &ballot[base + 3]));
        }
    }
    for f in 0..nf {
        let base = f * 4;
        cells.push(pack_te(&net[base], &net[base + 1]));
        cells.push(pack_te(&net[base + 2], &net[base + 3]));
    }
    debug_assert_eq!(cells.len(), t);
    cells
}

/// Hash the ordered `(commitment_48, y_be32)` pairs into the KZG blobs digest:
/// `SHA-256( com_0 || y_0 || com_1 || y_1 || ... )`.
pub fn digest_pairs(pairs: &[([u8; 48], [u8; 32])]) -> [u8; 32] {
    let mut buf: Vec<u8> = Vec::with_capacity(pairs.len() * (48 + 32));
    for (com, y) in pairs {
        buf.extend_from_slice(com);
        buf.extend_from_slice(y);
    }
    sha256_once(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bn254_fr::{ONE, ZERO};
    use crate::types::{BALLOT_FIELDS, ZERO_FR};

    #[test]
    fn enc_u64_layout() {
        // 0
        assert_eq!(enc_u64(0), [0u8; 32]);
        // small
        let mut want = [0u8; 32];
        want[31] = 0xAB;
        assert_eq!(enc_u64(0xAB), want);
        // full u64
        let v = 0x0123_4567_89AB_CDEFu64;
        let got = enc_u64(v);
        assert_eq!(&got[0..24], &[0u8; 24]);
        assert_eq!(&got[24..32], &v.to_be_bytes());
    }

    #[test]
    fn pack_identity_is_one() {
        // TE identity (0, 1) must pack to the 32-byte BE integer `1`.
        let mut want = [0u8; 32];
        want[31] = 1;
        assert_eq!(pack_te(&ZERO, &ONE), want);
    }

    #[test]
    fn pack_x_parity_sets_bit_254() {
        // y = 1, x parity = 1 (x = 1) -> value = 1 + 2^254.
        let mut want = [0u8; 32];
        want[31] = 1;
        want[0] = 0x40;
        assert_eq!(pack_te(&[1, 0, 0, 0], &ONE), want);
        // y = 1, x parity = 0 (x = 2) -> value = 1.
        let mut want = [0u8; 32];
        want[31] = 1;
        assert_eq!(pack_te(&[2, 0, 0, 0], &ONE), want);
    }

    #[test]
    fn total_and_n_blobs_arithmetic() {
        // T at the 4096 / 4097 boundary must swap n_blobs from 1 to 2.
        assert_eq!(n_blobs_from_t(0), 0);
        assert_eq!(n_blobs_from_t(1), 1);
        assert_eq!(n_blobs_from_t(4095), 1);
        assert_eq!(n_blobs_from_t(4096), 1);
        assert_eq!(n_blobs_from_t(4097), 2);
        assert_eq!(n_blobs_from_t(8192), 2);
        assert_eq!(n_blobs_from_t(8193), 3);
    }

    #[test]
    fn digest_pairs_matches_manual_sha256() {
        // Two fake (commitment, y) pairs.
        let mut com0 = [0u8; 48];
        for i in 0..48 {
            com0[i] = i as u8;
        }
        let y0 = [0xFFu8; 32];
        let mut com1 = [0u8; 48];
        for i in 0..48 {
            com1[i] = (0x30 + i) as u8;
        }
        let mut y1 = [0u8; 32];
        for i in 0..32 {
            y1[i] = i as u8;
        }

        let got = digest_pairs(&[(com0, y0), (com1, y1)]);

        // Hand assemble the byte string and hash it: this locks in the exact
        // (commitment || y) ordering. If digest_pairs regresses (wrong length,
        // wrong order, extra bytes), this diverges.
        let mut expected_input = alloc::vec::Vec::<u8>::with_capacity(2 * (48 + 32));
        expected_input.extend_from_slice(&com0);
        expected_input.extend_from_slice(&y0);
        expected_input.extend_from_slice(&com1);
        expected_input.extend_from_slice(&y1);
        let expected = crate::hash::sha256_once(&expected_input);
        assert_eq!(got, expected);

        // Empty input: digest_pairs must be the sha256 of the empty string.
        let empty_expected = crate::hash::sha256_once(&[]);
        assert_eq!(digest_pairs(&[]), empty_expected);
    }

    #[test]
    fn cell_layout_tiny_transition() {
        // 1 vid, 2 updates, nf=2. Cell count and content of the count cells,
        // plus an identity update packs to 1 in every packed slot.
        let nf = 2usize;
        let vids: alloc::vec::Vec<u64> = alloc::vec![0x8000_0000_0000_0001];
        let mut identity: BallotData = [ZERO_FR; BALLOT_FIELDS];
        for f in 0..crate::types::NUM_FIELDS {
            let b = f * 4;
            identity[b] = ZERO;
            identity[b + 1] = ONE;
            identity[b + 2] = ZERO;
            identity[b + 3] = ONE;
        }
        let updates: alloc::vec::Vec<(u64, BallotData)> = alloc::vec![
            (0x10u64, identity),
            (0x11u64, identity),
        ];
        let cells = build_cells(&vids, &updates, &identity, nf);
        // T = 2 + 1 + 2*(1 + 2*2) + 2*2 = 2 + 1 + 10 + 4 = 17
        assert_eq!(cells.len(), 17);
        assert_eq!(cells.len(), total_cells(1, 2, nf));

        // Count cells.
        assert_eq!(cells[0], enc_u64(1)); // n_vids
        assert_eq!(cells[1], enc_u64(0x8000_0000_0000_0001));
        assert_eq!(cells[2], enc_u64(2)); // n_updates

        // First update: key at cells[3], then 2*nf=4 pack cells.
        assert_eq!(cells[3], enc_u64(0x10));
        // Every identity pack cell = enc_u64(1).
        let one_cell = enc_u64(1);
        for i in 0..4 {
            assert_eq!(cells[4 + i], one_cell, "update0 pack cell {i}");
        }
        // Second update: key at cells[8], 4 pack cells.
        assert_eq!(cells[8], enc_u64(0x11));
        for i in 0..4 {
            assert_eq!(cells[9 + i], one_cell, "update1 pack cell {i}");
        }
        // Accumulator: 2*nf=4 identity pack cells.
        for i in 0..4 {
            assert_eq!(cells[13 + i], one_cell, "acc pack cell {i}");
        }
    }
}
