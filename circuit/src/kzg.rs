//! KZG EIP-4844 DA blob binding + barycentric evaluation.
//!
//! The blob cells are NOT trusted host input any more: the guest rebuilds them
//! from verified state (`sha256(vote ids)`, `sha256(slot updates covering new
//! votes, overwrites and silent refreshes alike)` and the NEW net accumulator)
//! and evaluates each blob polynomial at the point derived from that blob's
//! commitment. The `(commitment, y)` pairs are hashed into one digest and
//! emitted in the publics; the settlement contract compares each pair against
//! the blob's versioned hash via the EIP-4844 point-evaluation precompile.
//!
//! Evaluation point per blob:
//!   `Z_b = SHA-256(processID_be32 || rootHashBefore_be32 || commitment_b) mod p_bls`
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

/// Compute the KZG evaluation point `Z` for one blob.
/// `Z = SHA-256(processID_be32 || rootHashBefore_be32 || commitment_48) mod p_bls`.
pub fn compute_z(process_id: &FrRaw, root_hash_before: &FrRaw, commitment: &[u8; 48]) -> BlsFrRaw {
    let mut preimage = [0u8; 112]; // 32 (processID) + 32 (rootBefore) + 48 (commitment)

    for i in 0..4 {
        preimage[(3 - i) * 8..(4 - i) * 8].copy_from_slice(&process_id[i].to_be_bytes());
    }
    for i in 0..4 {
        preimage[32 + (3 - i) * 8..32 + (4 - i) * 8]
            .copy_from_slice(&root_hash_before[i].to_be_bytes());
    }
    preimage[64..112].copy_from_slice(commitment);

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

/// Generate the 4096 EIP-4844 roots of unity in bit-reversed order.
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
        domain[i] = bls_fr::mul(&domain[i - 1], &generator);
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
/// each cell a big-endian BLS12-381 Fr element (matches EIP-4844 / go-eth-kzg).
pub fn evaluate_barycentric(blob: &[u8], z: BlsFrRaw) -> BlsFrRaw {
    debug_assert_eq!(blob.len(), N * 32, "blob must be exactly 4096 x 32 bytes");

    let omega = gen_omega_table();

    for (k, w) in omega.iter().enumerate() {
        if *w == z {
            let cell: &[u8; 32] = blob[k * 32..(k + 1) * 32].try_into().unwrap();
            return bls_fr::from_be32_raw(cell);
        }
    }

    let diffs: [BlsFrRaw; N] = core::array::from_fn(|i| bls_fr::sub(&z, &omega[i]));
    let inv_diffs = batch_inverse(&diffs);

    let mut sum = ZERO;
    for i in 0..N {
        let cell: &[u8; 32] = blob[i * 32..(i + 1) * 32].try_into().unwrap();
        let d = bls_fr::from_be32_raw(cell);
        if d == ZERO {
            continue;
        }
        let d_omega = bls_fr::mul(&d, &omega[i]);
        sum = bls_fr::muladd(&d_omega, &inv_diffs[i], &sum);
    }

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
        prefix[i] = bls_fr::mul(&prefix[i - 1], &v[i]);
    }

    let mut acc = bls_fr::inv(&prefix[N - 1]);

    let mut result = [ZERO; N];
    for i in (1..N).rev() {
        result[i] = bls_fr::mul(&prefix[i - 1], &acc);
        acc = bls_fr::mul(&acc, &v[i]);
    }
    result[0] = acc;
    result
}

// Block verification

/// Verify the KZG DA binding: build cells from the verified state, evaluate
/// each blob polynomial at its bound point, and emit
/// `digest = SHA-256(com_0 || y_0 || com_1 || y_1 || ...)` over the ordered
/// pairs. Returns `(ok, digest, n_blobs)`.
///
/// Absent KZG block (chained mode) or absent state: trivially pass with a
/// zero digest and `n_blobs = 0` — all output limbs 28..39 stay zero.
pub fn verify_kzg(
    kzg: &Option<KZGBlock>,
    state: Option<&StateBlock>,
    num_fields: usize,
    refreshed_new: &[BallotData],
    net: &BallotData,
    fail_mask: &mut u32,
) -> (bool, [u8; 32], u32) {
    let (block, state) = match (kzg, state) {
        (Some(b), Some(s)) => (b, s),
        _ => return (true, [0u8; 32], 0),
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
    let cells = build_cells(&vids, &updates, net, num_fields);
    let t = total_cells(n_vids, n_updates, num_fields);
    debug_assert_eq!(cells.len(), t);
    let expected_n_blobs = n_blobs_from_t(t);
    let n_blobs_have = block.commitments.len();

    if n_blobs_have < 1
        || n_blobs_have > MAX_BLOBS
        || n_blobs_have != expected_n_blobs
    {
        *fail_mask |= FAIL_KZG;
        return (false, [0u8; 32], n_blobs_have as u32);
    }

    // 4) Per blob: copy cells into a 131072-byte buffer, evaluate at z_b, and
    // collect the (com, y) pairs. The last blob is zero-padded past the cell
    // count.
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
        let z_b = compute_z(&block.process_id, &block.root_hash_before, &block.commitments[b]);
        let y_b = evaluate_barycentric(&blob_buf, z_b);
        pairs.push((block.commitments[b], bls_fr::to_be32(&y_b)));
    }
    let digest = digest_pairs(&pairs);
    (true, digest, n_blobs_have as u32)
}
