//! KZG EIP-4844 DA blob binding + barycentric evaluation.
//!
//! The blob cells are not host input: the guest rebuilds them from verified
//! state (the sorted vote ids and the sorted slot updates covering new votes,
//! overwrites and silent refreshes alike; layout in `da_blob.rs`), hashes the
//! cell stream into `D` and evaluates each blob polynomial at a point derived
//! from `D` and that blob's commitment. `D` and the digest of the
//! `(commitment, y)` pairs are emitted in the publics; the settlement
//! contract derives the same points from `D` and checks each pair against
//! the blob's versioned hash via the EIP-4844 point-evaluation precompile.
//!
//! Evaluation point per blob (`D` fixes the polynomial before the point exists):
//!   `D   = SHA-256("davinci/cells/v1" || u64_be(nf) || u64_be(T) || cells)`
//!   `Z_b = SHA-256("davinci/point/v1" || processID_be32 || rootHashBefore_be32
//!                  || D || u64_be(n_blobs) || u64_be(b) || commitment_b) mod p_bls`
//!
//! Digest over the ordered pairs:
//!   `digest = SHA-256(com_0 || y_0_be32 || com_1 || y_1_be32 || ...)`

use crate::bls_fr::{self, BlsFrRaw, ONE, ZERO};
use crate::da_blob::{build_cells, digest_pairs, n_blobs_from_t, total_cells};
use crate::hash::sha256_once;
use crate::types::{BallotData, FrRaw, KZGBlock, StateBlock, FAIL_KZG, MAX_BLOBS};
extern crate alloc;
use alloc::vec::Vec;

/// Cells per EIP-4844 blob.
const N: usize = 4096;
/// log2(N) — used for `Z^N` via 12 squarings and the bit-reversal permutation.
const LOG_N: usize = 12;
/// N as a BLS12-381 Fr element (used for the `1/N` factor).
const N_FR: BlsFrRaw = [4096, 0, 0, 0];

/// Domain tag of the cell-stream digest `D`.
const CELLS_TAG: [u8; 16] = *b"davinci/cells/v1";
/// Domain tag of the per-blob evaluation point.
const POINT_TAG: [u8; 16] = *b"davinci/point/v1";

/// `D = SHA-256(CELLS_TAG || u64_be(nf) || u64_be(T) || cell_0 || .. || cell_{T-1})`
/// over the unpadded stream. The tag and counts fill one cell, so the
/// preimage is one buffer of T + 1 cells hashed by the `sha256f` precompile.
fn cells_digest(nf: usize, cells: &[[u8; 32]]) -> [u8; 32] {
    let mut head = [0u8; 32];
    head[..16].copy_from_slice(&CELLS_TAG);
    head[16..24].copy_from_slice(&(nf as u64).to_be_bytes());
    head[24..].copy_from_slice(&(cells.len() as u64).to_be_bytes());
    let mut buf: Vec<[u8; 32]> = Vec::with_capacity(cells.len() + 1);
    buf.push(head);
    buf.extend_from_slice(cells);
    sha256_once(buf.as_flattened())
}

/// Compute the KZG evaluation point `Z` of blob `index` out of `n_blobs`:
/// `SHA-256(POINT_TAG || processID_be32 || rootHashBefore_be32 || D
/// || u64_be(n_blobs) || u64_be(index) || commitment_48) mod p_bls`.
pub fn compute_z(
    process_id: &FrRaw,
    root_hash_before: &FrRaw,
    cells_digest: &[u8; 32],
    n_blobs: usize,
    index: usize,
    commitment: &[u8; 48],
) -> BlsFrRaw {
    // 16 (tag) + 32 (processID) + 32 (rootBefore) + 32 (D) + 8 + 8 + 48 (commitment)
    let mut preimage = [0u8; 176];
    preimage[..16].copy_from_slice(&POINT_TAG);
    for i in 0..4 {
        preimage[16 + (3 - i) * 8..16 + (4 - i) * 8].copy_from_slice(&process_id[i].to_be_bytes());
    }
    for i in 0..4 {
        preimage[48 + (3 - i) * 8..48 + (4 - i) * 8]
            .copy_from_slice(&root_hash_before[i].to_be_bytes());
    }
    preimage[80..112].copy_from_slice(cells_digest);
    preimage[112..120].copy_from_slice(&(n_blobs as u64).to_be_bytes());
    preimage[120..128].copy_from_slice(&(index as u64).to_be_bytes());
    preimage[128..176].copy_from_slice(commitment);

    let hash = sha256_once(&preimage);
    bls_fr::from_be32_mod(&hash)
}

// Omega table

/// BLS12-381 Fr primitive root of unity with order 2^32 (used by go-eth-kzg).
const ROU_BYTES: [u8; 32] = [
    0x16, 0xa2, 0xa1, 0x9e, 0xdf, 0xe8, 0x1f, 0x20,
    0xd0, 0x9b, 0x68, 0x19, 0x22, 0xc8, 0x13, 0xb4,
    0xb6, 0x36, 0x83, 0x50, 0x8c, 0x22, 0x80, 0xb9,
    0x38, 0x29, 0x97, 0x1f, 0x43, 0x9f, 0x0d, 0x2b,
];

/// Generate the 4096 EIP-4844 roots of unity in bit-reversed order. Built
/// once per batch and shared by every blob.
fn gen_omega_table() -> [BlsFrRaw; N] {
    let rou = bls_fr::from_be32_raw(&ROU_BYTES);

    // generator = rou^(2^20)  ->  order = 4096 = 2^12
    let mut generator = rou;
    for _ in 0..20 {
        generator = bls_fr::sqr(&generator);
    }

    let mut domain = [ZERO; N];
    domain[0] = ONE;
    for i in 1..N {
        let (prev, rest) = domain.split_at_mut(i);
        bls_fr::muladd_into(&mut rest[0], &prev[i - 1], &generator, &ZERO);
    }

    let mut omega = [ZERO; N];
    for i in 0..N {
        omega[i] = domain[bit_reverse(i, LOG_N)];
    }
    omega
}

#[inline(always)]
fn bit_reverse(n: usize, log2n: usize) -> usize {
    let mut rev = 0usize;
    let mut x = n;
    for _ in 0..log2n {
        rev = (rev << 1) | (x & 1);
        x >>= 1;
    }
    rev
}

// Barycentric evaluation

/// Evaluate one blob polynomial at `z`. `blob` is a flat 4096 x 32 byte buffer,
/// each cell a big-endian BLS12-381 Fr element (matches EIP-4844 / go-eth-kzg);
/// `omega` is `gen_omega_table()`.
pub fn evaluate_barycentric(blob: &[u8], z: BlsFrRaw, omega: &[BlsFrRaw; N]) -> BlsFrRaw {
    debug_assert_eq!(blob.len(), N * 32, "blob must be exactly 4096 x 32 bytes");

    for (k, w) in omega.iter().enumerate() {
        if *w == z {
            let cell: &[u8; 32] = blob[k * 32..(k + 1) * 32].try_into().unwrap();
            return bls_fr::from_be32_raw(cell);
        }
    }

    let diffs: [BlsFrRaw; N] = core::array::from_fn(|i| bls_fr::sub(&z, &omega[i]));
    let inv_diffs = batch_inverse(&diffs);

    // In-place field ops: the running sum ping-pongs between two words.
    let (mut s0, mut s1, mut d_omega) = (ZERO, ZERO, ZERO);
    let (mut sum, mut next) = (&mut s0, &mut s1);
    for i in 0..N {
        let cell: &[u8; 32] = blob[i * 32..(i + 1) * 32].try_into().unwrap();
        let d = bls_fr::from_be32_raw(cell);
        if d == ZERO {
            continue;
        }
        bls_fr::muladd_into(&mut d_omega, &d, &omega[i], &ZERO);
        bls_fr::muladd_into(next, &d_omega, &inv_diffs[i], sum);
        core::mem::swap(&mut sum, &mut next);
    }
    let sum = *sum;

    let mut z_pow_n = z;
    for _ in 0..LOG_N {
        z_pow_n = bls_fr::sqr(&z_pow_n);
    }
    let z_pow_n_minus_1 = bls_fr::sub(&z_pow_n, &ONE);
    let n_inv = bls_fr::inv(&N_FR);
    let factor = bls_fr::mul(&z_pow_n_minus_1, &n_inv);

    bls_fr::mul(&factor, &sum)
}

fn batch_inverse(v: &[BlsFrRaw; N]) -> [BlsFrRaw; N] {
    let mut prefix = [ZERO; N];
    prefix[0] = v[0];
    for i in 1..N {
        let (prev, rest) = prefix.split_at_mut(i);
        bls_fr::muladd_into(&mut rest[0], &prev[i - 1], &v[i], &ZERO);
    }

    let (mut a0, mut a1) = (bls_fr::inv(&prefix[N - 1]), ZERO);
    let (mut acc, mut next) = (&mut a0, &mut a1);

    let mut result = [ZERO; N];
    for i in (1..N).rev() {
        bls_fr::muladd_into(&mut result[i], &prefix[i - 1], acc, &ZERO);
        bls_fr::muladd_into(next, acc, &v[i], &ZERO);
        core::mem::swap(&mut acc, &mut next);
    }
    result[0] = *acc;
    result
}

// Block verification

/// Verify the KZG DA binding: build cells from the verified state, hash them
/// into `D`, evaluate each blob polynomial at its bound point, and emit
/// `digest = SHA-256(com_0 || y_0 || com_1 || y_1 || ...)` over the ordered
/// pairs. Returns `(ok, digest, n_blobs, D)`.
///
/// Absent KZG block (chained mode) or absent state: trivially pass with a
/// zero digest, `n_blobs = 0` and a zero `D` — output limbs 28..39 and
/// 46..53 stay zero. On FAIL_KZG both digests are zero.
pub fn verify_kzg(
    kzg: &Option<KZGBlock>,
    state: Option<&StateBlock>,
    num_fields: usize,
    refreshed_new: &[BallotData],
    fail_mask: &mut u32,
) -> (bool, [u8; 32], u32, [u8; 32]) {
    let (block, state) = match (kzg, state) {
        (Some(b), Some(s)) => (b, s),
        _ => return (true, [0u8; 32], 0, [0u8; 32]),
    };

    // 1) Vote id list from vote_id_chain (limb 0), sorted ascending.
    let mut vids: Vec<u64> = state.vote_id_chain.iter().map(|t| t.new_key[0]).collect();
    vids.sort();
    let n_vids = vids.len();

    // 2) Update list: (key, ballot) for ballot chain then refresh chain,
    // stable-sorted by key. Ballot-chain order first among equal keys.
    let mut updates: Vec<(u64, BallotData)> =
        Vec::with_capacity(state.ballot_chain.len() + state.refresh_chain.len());
    for (i, t) in state.ballot_chain.iter().enumerate() {
        if i < state.voter_ballots.len() {
            updates.push((t.new_key[0], state.voter_ballots[i]));
        }
    }
    for (j, t) in state.refresh_chain.iter().enumerate() {
        if j < refreshed_new.len() {
            updates.push((t.new_key[0], refreshed_new[j]));
        }
    }
    updates.sort_by_key(|(k, _)| *k);
    let n_updates = updates.len();

    // 3) Cell layout and expected n_blobs.
    let cells = build_cells(&vids, &updates, num_fields);
    let t = total_cells(n_vids, n_updates, num_fields);
    debug_assert_eq!(cells.len(), t);
    let expected_n_blobs = n_blobs_from_t(t);
    let n_blobs_have = block.commitments.len();

    if n_blobs_have < 1
        || n_blobs_have > MAX_BLOBS
        || n_blobs_have != expected_n_blobs
    {
        *fail_mask |= FAIL_KZG;
        return (false, [0u8; 32], n_blobs_have as u32, [0u8; 32]);
    }

    // D from the cells alone, before any commitment value is read: every
    // point below then depends on the exact polynomials, so content cannot
    // be fitted to a point known in advance.
    let d = cells_digest(num_fields, &cells);

    // 4) Per blob: copy cells into a 131072-byte buffer, evaluate at z_b, and
    // collect the (com, y) pairs. The last blob is zero-padded past the cell
    // count. The roots of unity are the same for every blob.
    let omega = gen_omega_table();
    const BLOB_BYTES: usize = N * 32;
    let mut pairs: Vec<([u8; 48], [u8; 32])> = Vec::with_capacity(n_blobs_have);
    let mut blob_buf = alloc::vec![0u8; BLOB_BYTES];
    for b in 0..n_blobs_have {
        for byte in blob_buf.iter_mut() {
            *byte = 0;
        }
        let start = b * N;
        let end = ((b + 1) * N).min(cells.len());
        for (local, global) in (start..end).enumerate() {
            blob_buf[local * 32..(local + 1) * 32].copy_from_slice(&cells[global]);
        }
        let z_b = compute_z(
            &block.process_id,
            &block.root_hash_before,
            &d,
            n_blobs_have,
            b,
            &block.commitments[b],
        );
        let y_b = evaluate_barycentric(&blob_buf, z_b, &omega);
        pairs.push((block.commitments[b], bls_fr::to_be32(&y_b)));
    }
    let digest = digest_pairs(&pairs);
    (true, digest, n_blobs_have as u32, d)
}
