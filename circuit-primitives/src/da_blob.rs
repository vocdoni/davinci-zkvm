//! Data-availability blob cell layout for the vote-batch guest.
//!
//! Cells are 32-byte big-endian BLS12-381 Fr elements. The guest rebuilds
//! them from verified data, packs them into 4096-cell blobs, and evaluates
//! each blob polynomial at the point derived from that blob's commitment.
//!
//! Layout (byte-exact; the Go and Rust SDKs mirror it):
//!
//! ```text
//! header(n_vids, n_updates)
//! pack4(I[0..4]) pack4(I[4..8]) ..                   // ceil((n_vids + n_updates) / 4)
//!     I = [vid_0 & (2^63 - 1) .. vid_{n_vids-1} & (2^63 - 1), key_0 .. key_{n_updates-1}]
//!     vote ids ASCENDING, keys ASCENDING (stable), missing slots zero
//! for each (key, ballot) update, ASCENDING by key (stable):
//!     pack(c1_0) pack(c2_0) .. pack(c1_{nf-1}) pack(c2_{nf-1})
//! zero cells to end of last blob
//! ```
//!
//! `header(v, u)`   = `v * 2^64 + u`; bits 128..255 (the version) are zero.
//! `pack4(a,b,c,d)` = `a*2^189 + b*2^126 + c*2^63 + d`, below 2^252.
//! `pack(x, y)`     = `y_canon + ((x_canon & 1) << 254)` as 32-byte big-endian,
//!                    with `x_canon`, `y_canon` = coords reduced mod BN254 Fr.
//!                    Fits in BLS12-381 Fr since `p_bn254 + 2^254 < r_bls`.
//!                    The TE identity `(0,1)` packs to `1`.
//!
//! Vote ids live in `[2^63, 2^64)`, so the top bit is implied. The mask, not
//! `vid - 2^63`, keeps an out-of-namespace id (already `FAIL_CONSISTENCY`)
//! from panicking here. The Results accumulator is not emitted: a follower
//! recomputes it from the ballots it holds.

use crate::bn254_fr;
use crate::hash::sha256_once;
use crate::types::{BallotData, FrRaw};
extern crate alloc;
use alloc::vec::Vec;

/// Cells per EIP-4844 blob (identical to `kzg::N`).
pub const CELLS_PER_BLOB: usize = 4096;

/// Low 63 bits: a packed vote id and the width of every integer slot.
pub const LOW63: u64 = (1 << 63) - 1;

/// The header cell `n_vids * 2^64 + n_updates` as 32-byte big-endian.
#[inline]
pub fn header(n_vids: u64, n_updates: u64) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[16..24].copy_from_slice(&n_vids.to_be_bytes());
    b[24..32].copy_from_slice(&n_updates.to_be_bytes());
    b
}

/// `a*2^189 + b*2^126 + c*2^63 + d` as 32-byte big-endian, for integers below
/// 2^63 (the result is below 2^252).
#[inline]
pub fn pack4(a: u64, b: u64, c: u64, d: u64) -> [u8; 32] {
    // Little-endian u64 limbs of the 256-bit cell.
    let limbs = [d | c << 63, c >> 1 | b << 62, b >> 2 | a << 61, a >> 3];
    let mut out = [0u8; 32];
    for i in 0..4 {
        let start = (3 - i) * 8;
        out[start..start + 8].copy_from_slice(&limbs[i].to_be_bytes());
    }
    out
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

/// Total cell count `T = 1 + ceil((n_vids + n_updates) / 4) + 2 * nf * n_updates`.
#[inline]
pub fn total_cells(n_vids: usize, n_updates: usize, nf: usize) -> usize {
    1 + (n_vids + n_updates).div_ceil(4) + 2 * nf * n_updates
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
    nf: usize,
) -> Vec<[u8; 32]> {
    let t = total_cells(sorted_vote_ids.len(), sorted_updates.len(), nf);
    let mut cells: Vec<[u8; 32]> = Vec::with_capacity(t);
    cells.push(header(sorted_vote_ids.len() as u64, sorted_updates.len() as u64));
    let n_ints = sorted_vote_ids.len() + sorted_updates.len();
    let int = |i: usize| -> u64 {
        if i < sorted_vote_ids.len() {
            sorted_vote_ids[i] & LOW63
        } else if i < n_ints {
            sorted_updates[i - sorted_vote_ids.len()].0
        } else {
            0
        }
    };
    let mut i = 0;
    while i < n_ints {
        cells.push(pack4(int(i), int(i + 1), int(i + 2), int(i + 3)));
        i += 4;
    }
    for (_, ballot) in sorted_updates {
        for f in 0..nf {
            let base = f * 4;
            cells.push(pack_te(&ballot[base], &ballot[base + 1]));
            cells.push(pack_te(&ballot[base + 2], &ballot[base + 3]));
        }
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

    // The integer `v` as a 32-byte big-endian cell.
    fn int_cell(v: u64) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[24..32].copy_from_slice(&v.to_be_bytes());
        b
    }

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn header_layout() {
        assert_eq!(header(0, 0), [0u8; 32]);
        assert_eq!(
            header(1, 2),
            hex32("0000000000000000000000000000000000000000000000010000000000000002")
        );
    }

    #[test]
    fn pack4_layout() {
        // First element in the most significant slot; matches the big-integer
        // formula the SDK tests check (a*2^189 + b*2^126 + c*2^63 + d).
        assert_eq!(pack4(0, 0, 0, 0), [0u8; 32]);
        assert_eq!(pack4(0, 0, 0, 7), int_cell(7));
        assert_eq!(
            pack4(1, 0x10, 0x11, LOW63),
            hex32("000000000000000020000000000000040000000000000008ffffffffffffffff")
        );
        assert_eq!(
            pack4(LOW63, LOW63 - 2, LOW63 - 1, LOW63),
            hex32("0fffffffffffffffffffffffffffffff7fffffffffffffff7fffffffffffffff")
        );
    }

    #[test]
    fn pack_identity_is_one() {
        // TE identity (0, 1) must pack to the 32-byte BE integer `1`.
        assert_eq!(pack_te(&ZERO, &ONE), int_cell(1));
    }

    #[test]
    fn pack_x_parity_sets_bit_254() {
        // y = 1, x parity = 1 (x = 1) -> value = 1 + 2^254.
        let mut want = int_cell(1);
        want[0] = 0x40;
        assert_eq!(pack_te(&[1, 0, 0, 0], &ONE), want);
        // y = 1, x parity = 0 (x = 2) -> value = 1.
        assert_eq!(pack_te(&[2, 0, 0, 0], &ONE), int_cell(1));
    }

    #[test]
    fn total_and_n_blobs_arithmetic() {
        assert_eq!(total_cells(0, 0, 1), 1);
        assert_eq!(total_cells(1, 3, 1), 1 + 1 + 6);
        assert_eq!(total_cells(1, 4, 1), 1 + 2 + 8);
        // 126 votes at 16 fields fill one blob; one vote with 126 refreshes
        // puts a cell in a second.
        assert_eq!(total_cells(126, 126, 16), 4096);
        assert_eq!(total_cells(1, 127, 16), 4097);
        // The largest valid transition (1024 votes, 2048 refreshes, 16 fields).
        assert_eq!(n_blobs_from_t(total_cells(1024, 3072, 16)), 25);
        assert_eq!(n_blobs_from_t(0), 0);
        assert_eq!(n_blobs_from_t(1), 1);
        assert_eq!(n_blobs_from_t(4096), 1);
        assert_eq!(n_blobs_from_t(4097), 2);
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
        // 1 vid, 2 updates, nf=2: header, one integer cell, 2 * 2 * 2 point
        // cells. An identity update packs to 1 in every point cell.
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
        let cells = build_cells(&vids, &updates, nf);
        // T = 1 + ceil(3 / 4) + 2 * 2 * 2 = 10
        assert_eq!(cells.len(), 10);
        assert_eq!(cells.len(), total_cells(1, 2, nf));

        assert_eq!(cells[0], header(1, 2));
        // The id without its top bit, then the keys, one unused slot.
        assert_eq!(cells[1], pack4(1, 0x10, 0x11, 0));
        for i in 2..10 {
            assert_eq!(cells[i], int_cell(1), "point cell {i}");
        }
    }

    #[test]
    fn integer_cells_split_at_four() {
        // V + U = 0..=5: ceil((V + U) / 4) integer cells, missing slots zero.
        let id: BallotData = [ZERO_FR; BALLOT_FIELDS];
        for n in 0..=5usize {
            let updates: alloc::vec::Vec<(u64, BallotData)> =
                (0..n).map(|i| (0x10 + i as u64, id)).collect();
            let cells = build_cells(&[], &updates, 1);
            assert_eq!(cells.len(), 1 + n.div_ceil(4) + 2 * n);
            if n == 5 {
                assert_eq!(cells[1], pack4(0x10, 0x11, 0x12, 0x13));
                assert_eq!(cells[2], pack4(0x14, 0, 0, 0));
            }
        }
        // An id below 2^63 (rejected elsewhere) masks, it does not panic.
        let cells = build_cells(&[5], &[(0x10, id)], 1);
        assert_eq!(cells[1], pack4(5, 0x10, 0, 0));
    }
}
