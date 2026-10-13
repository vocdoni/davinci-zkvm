//! EIP-4844 DA blobs of a transition, byte-identical to the guest
//! (`circuit-primitives/src/da_blob.rs`, `circuit/src/kzg.rs`) and go-sdk
//! `blob.go`, plus the decoder a follower needs to rebuild state.
//!
//! ```text
//! header                         n_vids * 2^64 + n_updates (bits 128.. zero)
//! ceil((V + U) / 4) int cells    [vid & (2^63 - 1) ..., key ...], four per
//!                                cell, the first in the top 63-bit slot
//! [pack(c1_0) pack(c2_0) ...]    per update, ascending by key, fields < nf
//! zero cells to the end of the last blob
//! pack(P) = Point::compress(P)
//! z_b    = int_be(sha256(pid_BE32 || BE32(root_before_int) || com_b)) mod r_bls
//! digest = sha256(com_0 || y_0 || ...)
//! ```
//!
//! The Results accumulator is not in the stream: a follower recomputes it
//! from the ballots it already holds.

use num_bigint::BigUint;
use sha2::{Digest, Sha256};

use crate::ballot::Ballot;
use crate::crypto::babyjubjub::Point;
use crate::crypto::elgamal::Ciphertext;
use crate::crypto::field::{fr_to_be, Fr};
use crate::limits::{
    required_refresh, BALLOT_MAX, BALLOT_MIN, MAX_BATCH_SIZE, MAX_BLOBS, MAX_REFRESH, NUM_FIELDS,
    VOTE_ID_MIN,
};
use crate::Error;

pub const CELLS_PER_BLOB: usize = 4096;
pub const BLOB_SIZE: usize = CELLS_PER_BLOB * 32;
pub type Blob = Box<[u8; BLOB_SIZE]>;

/// What one transition publishes. `updates` are new ballots and refreshed
/// ballots alike (the blob cannot tell them apart).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TransitionData {
    pub vote_ids: Vec<u64>,
    pub updates: Vec<(u64, Ballot)>,
    pub num_fields: u8,
}

/// Everything a settlement transaction needs, one entry per blob.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TransitionBlobs {
    pub blobs: Vec<Blob>,
    pub commitments: Vec<[u8; 48]>,
    pub zs: Vec<[u8; 32]>,
    pub ys: Vec<[u8; 32]>,
    /// KZG openings at `zs`.
    pub proofs: Vec<[u8; 48]>,
    pub versioned_hashes: Vec<[u8; 32]>,
    /// The value the guest publishes in registers 28..35.
    pub digest: [u8; 32],
}

// BLS12-381 scalar field order.
const R_BLS_BE: [u8; 32] = [
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
];

/// A vote id's packed form (its top bit is implied) and every integer
/// slot's width.
const LOW63: u64 = (1 << 63) - 1;

/// `T = 1 + ceil((V + U) / 4) + 2 * nf * U`.
fn total_cells(n_vids: usize, n_updates: usize, nf: usize) -> usize {
    1 + (n_vids + n_updates).div_ceil(4) + 2 * nf * n_updates
}

/// `ceil(T / 4096)` for `T = 1 + ceil((V + U) / 4) + 2 * nf * U`.
pub fn blob_count(n_vote_ids: usize, n_updates: usize, nf: u8) -> usize {
    total_cells(n_vote_ids, n_updates, nf as usize).div_ceil(CELLS_PER_BLOB)
}

/// The header cell: `n_vids * 2^64 + n_updates`.
fn header(n_vids: usize, n_updates: usize) -> [u8; 32] {
    let mut c = [0u8; 32];
    c[16..24].copy_from_slice(&(n_vids as u64).to_be_bytes());
    c[24..].copy_from_slice(&(n_updates as u64).to_be_bytes());
    c
}

/// `e[0] * 2^189 + e[1] * 2^126 + e[2] * 2^63 + e[3]` for integers below 2^63.
fn pack4(e: [u64; 4]) -> [u8; 32] {
    let [a, b, c, d] = e;
    // Little-endian u64 limbs of the 256-bit cell.
    let limbs = [d | c << 63, c >> 1 | b << 62, b >> 2 | a << 61, a >> 3];
    let mut out = [0u8; 32];
    for (i, l) in limbs.iter().enumerate() {
        out[24 - 8 * i..32 - 8 * i].copy_from_slice(&l.to_be_bytes());
    }
    out
}

/// Inverse of [`pack4`] for a cell below 2^252.
fn unpack4(c: &[u8; 32]) -> [u64; 4] {
    let mut l = [0u64; 4];
    for (i, w) in l.iter_mut().enumerate() {
        let mut b = [0u8; 8];
        b.copy_from_slice(&c[24 - 8 * i..32 - 8 * i]);
        *w = u64::from_be_bytes(b);
    }
    [
        (l[2] >> 61 | l[3] << 3) & LOW63,
        (l[1] >> 62 | l[2] << 2) & LOW63,
        (l[0] >> 63 | l[1] << 1) & LOW63,
        l[0] & LOW63,
    ]
}

/// Largest batch (up to `MAX_BATCH_SIZE`) whose transition fits in
/// `cap_blobs` blobs, counting the refreshes the guest demands. `overwrites`
/// is the expected overwrite count, capped at the batch size (pass
/// `usize::MAX` for "every vote overwrites").
pub fn max_votes_for_cap(
    nf: u8,
    overwrites: usize,
    occupied_before: usize,
    cap_blobs: usize,
) -> usize {
    (1..=MAX_BATCH_SIZE)
        .rev()
        .find(|&n| {
            let w = overwrites.min(n);
            let r = required_refresh(n, w, occupied_before);
            blob_count(n, n + r, nf) <= cap_blobs
        })
        .unwrap_or(0)
}

/// The cell stream in guest order (vote ids and updates sorted here; the
/// update sort is stable). `num_fields` above 16 is treated as 16.
pub fn cells(t: &TransitionData) -> Vec<[u8; 32]> {
    let nf = (t.num_fields as usize).min(NUM_FIELDS);
    let mut vids = t.vote_ids.clone();
    vids.sort_unstable();
    let mut updates: Vec<&(u64, Ballot)> = t.updates.iter().collect();
    updates.sort_by_key(|(k, _)| *k);

    let ints: Vec<u64> = vids
        .iter()
        .map(|v| v & LOW63)
        .chain(updates.iter().map(|(k, _)| *k))
        .collect();
    let mut out = Vec::with_capacity(total_cells(vids.len(), updates.len(), nf));
    out.push(header(vids.len(), updates.len()));
    for chunk in ints.chunks(4) {
        let mut e = [0u64; 4];
        e[..chunk.len()].copy_from_slice(chunk);
        out.push(pack4(e));
    }
    for (_, ballot) in updates {
        for ct in &ballot.0[..nf] {
            out.push(ct.c1.compress());
            out.push(ct.c2.compress());
        }
    }
    out
}

/// Packs cells into zero-padded blobs.
pub fn blobs_from_cells(cells: &[[u8; 32]]) -> Result<Vec<Blob>, Error> {
    let n = cells.len().div_ceil(CELLS_PER_BLOB).max(1);
    if n > MAX_BLOBS {
        return Err(Error::Blob(format!("{n} blobs, at most {MAX_BLOBS}")));
    }
    let mut blobs = Vec::with_capacity(n);
    for chunk in 0..n {
        let mut b = new_blob();
        let start = chunk * CELLS_PER_BLOB;
        let end = (start + CELLS_PER_BLOB).min(cells.len());
        for (i, c) in cells[start..end].iter().enumerate() {
            b[i * 32..i * 32 + 32].copy_from_slice(c);
        }
        blobs.push(b);
    }
    Ok(blobs)
}

fn new_blob() -> Blob {
    // Heap-allocated without a 128 KiB stack temporary; the length is a
    // constant, so the conversion cannot fail.
    vec![0u8; BLOB_SIZE]
        .into_boxed_slice()
        .try_into()
        .expect("BLOB_SIZE-sized buffer")
}

/// Evaluation point bound by the guest: `sha256(pid || root_be || com) mod r_bls`.
pub fn compute_z(pid: &Fr, old_root: &[u8; 32], commitment: &[u8; 48]) -> [u8; 32] {
    let mut root_be = *old_root;
    root_be.reverse();
    let mut h = Sha256::new();
    h.update(fr_to_be(pid));
    h.update(root_be);
    h.update(commitment);
    let z = BigUint::from_bytes_be(&h.finalize()) % BigUint::from_bytes_be(&R_BLS_BE);
    let zb = z.to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - zb.len()..].copy_from_slice(&zb);
    out
}

/// EIP-4844 versioned hash: `0x01 || sha256(commitment)[1..]`.
pub fn versioned_hash(commitment: &[u8; 48]) -> [u8; 32] {
    let mut h: [u8; 32] = Sha256::digest(commitment).into();
    h[0] = 0x01;
    h
}

/// `sha256(com_0 || y_0 || ...)`.
pub fn blobs_digest(commitments: &[[u8; 48]], ys: &[[u8; 32]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for (c, y) in commitments.iter().zip(ys) {
        h.update(c);
        h.update(y);
    }
    h.finalize().into()
}

fn kzg_blob(blob: &Blob) -> Result<c_kzg::Blob, Error> {
    c_kzg::Blob::from_bytes(&blob[..]).map_err(|e| Error::Blob(format!("kzg blob: {e:?}")))
}

fn commit(blob: &c_kzg::Blob) -> Result<[u8; 48], Error> {
    let s = c_kzg::ethereum_kzg_settings(0);
    let c = s
        .blob_to_kzg_commitment(blob)
        .map_err(|e| Error::Blob(format!("commitment: {e:?}")))?;
    Ok(*c.to_bytes())
}

/// Cells, blobs, commitments, openings at the guest's `z_b` and the digest.
/// `pid` is the process id, `old_root` the raw arbo root before the batch.
pub fn build_blobs(
    t: &TransitionData,
    pid: &Fr,
    old_root: &[u8; 32],
) -> Result<TransitionBlobs, Error> {
    if t.num_fields == 0 || t.num_fields as usize > NUM_FIELDS {
        return Err(Error::Blob(format!(
            "num_fields {} not in 1..=16",
            t.num_fields
        )));
    }
    let blobs = blobs_from_cells(&cells(t))?;
    let settings = c_kzg::ethereum_kzg_settings(0);
    let n = blobs.len();
    let mut out = TransitionBlobs {
        blobs: Vec::with_capacity(n),
        commitments: Vec::with_capacity(n),
        zs: Vec::with_capacity(n),
        ys: Vec::with_capacity(n),
        proofs: Vec::with_capacity(n),
        versioned_hashes: Vec::with_capacity(n),
        digest: [0u8; 32],
    };
    for blob in blobs {
        let kb = kzg_blob(&blob)?;
        let com = commit(&kb)?;
        let z = compute_z(pid, old_root, &com);
        let (proof, y) = settings
            .compute_kzg_proof(&kb, &c_kzg::Bytes32::from(z))
            .map_err(|e| Error::Blob(format!("opening: {e:?}")))?;
        out.versioned_hashes.push(versioned_hash(&com));
        out.commitments.push(com);
        out.zs.push(z);
        out.ys.push(*y);
        out.proofs.push(*proof.to_bytes());
        out.blobs.push(blob);
    }
    out.digest = blobs_digest(&out.commitments, &out.ys);
    Ok(out)
}

/// Commits to `blob` and checks it against an on-chain versioned hash.
/// Returns the commitment.
pub fn verify_blob_commitment(blob: &Blob, versioned: &[u8; 32]) -> Result<[u8; 48], Error> {
    let com = commit(&kzg_blob(blob)?)?;
    if versioned_hash(&com) != *versioned {
        return Err(Error::Blob("blob does not match its versioned hash".into()));
    }
    Ok(com)
}

struct Cells<'a> {
    blobs: &'a [Blob],
    next: usize,
}

impl<'a> Cells<'a> {
    fn total(&self) -> usize {
        self.blobs.len() * CELLS_PER_BLOB
    }

    fn cell(&self, i: usize) -> Option<&'a [u8]> {
        let blobs: &'a [Blob] = self.blobs;
        let b = blobs.get(i / CELLS_PER_BLOB)?;
        let off = (i % CELLS_PER_BLOB) * 32;
        b.get(off..off + 32)
    }

    fn take(&mut self) -> Result<[u8; 32], Error> {
        let c = self
            .cell(self.next)
            .ok_or_else(|| Error::Blob("truncated blob data".into()))?;
        self.next += 1;
        let mut out = [0u8; 32];
        out.copy_from_slice(c);
        Ok(out)
    }

    fn point(&mut self) -> Result<Point, Error> {
        Point::decompress(&self.take()?).map_err(|e| Error::Blob(format!("bad point cell: {e}")))
    }

    fn ciphertexts(&mut self, nf: usize) -> Result<Ballot, Error> {
        let mut b = Ballot::identity();
        for ct in b.0.iter_mut().take(nf) {
            *ct = Ciphertext {
                c1: self.point()?,
                c2: self.point()?,
            };
        }
        Ok(b)
    }
}

/// Parses a transition's blobs (in order) at the election's `nf`. Rejects a
/// non-zero header version, counts outside the guest's limits or with more
/// vote ids than updates, a blob count other than the header's, integer cells
/// at or above 2^252 or with a non-zero unused slot, unsorted or
/// out-of-namespace keys, invalid points and non-zero padding.
///
/// These are layout checks, not provenance. Points are only checked to be on
/// the curve, not in the prime-order subgroup. Trust the output only for blobs
/// whose commitments and evaluations reproduce the `blobs_digest` of verified
/// batch publics: then the cells are the ones the guest laid out from the
/// ciphertexts it stored.
pub fn decode_blobs(blobs: &[Blob], nf: u8) -> Result<TransitionData, Error> {
    let nfu = nf as usize;
    if nfu == 0 || nfu > NUM_FIELDS {
        return Err(Error::Blob(format!("num_fields {nf} not in 1..=16")));
    }
    if blobs.is_empty() || blobs.len() > MAX_BLOBS {
        return Err(Error::Blob(format!(
            "{} blobs, want 1..={MAX_BLOBS}",
            blobs.len()
        )));
    }
    let mut c = Cells { blobs, next: 0 };

    let head = c.take()?;
    if head[..16] != [0u8; 16] {
        return Err(Error::Blob("header version field not zero".into()));
    }
    let word = |r: std::ops::Range<usize>| {
        let mut b = [0u8; 8];
        b.copy_from_slice(&head[r]);
        u64::from_be_bytes(b)
    };
    let (n_vids, n_updates) = (word(16..24), word(24..32));
    if n_vids > MAX_BATCH_SIZE as u64
        || n_updates < n_vids
        || n_updates > (MAX_BATCH_SIZE + MAX_REFRESH) as u64
    {
        return Err(Error::Blob(format!(
            "header counts {n_vids} vote ids, {n_updates} updates"
        )));
    }
    let (n_vids, n_updates) = (n_vids as usize, n_updates as usize);
    let want = blob_count(n_vids, n_updates, nf);
    if blobs.len() != want {
        return Err(Error::Blob(format!(
            "{} blobs, the header needs {want}",
            blobs.len()
        )));
    }

    let n_ints = n_vids + n_updates;
    let mut ints = Vec::with_capacity(n_ints.next_multiple_of(4));
    for _ in 0..n_ints.div_ceil(4) {
        let cell = c.take()?;
        if cell[0] >> 4 != 0 {
            return Err(Error::Blob("integer cell at or above 2^252".into()));
        }
        ints.extend(unpack4(&cell));
    }
    if ints[n_ints..].iter().any(|x| *x != 0) {
        return Err(Error::Blob("unused integer slot not zero".into()));
    }

    let mut vote_ids: Vec<u64> = Vec::with_capacity(n_vids);
    for &i in &ints[..n_vids] {
        let v = i | VOTE_ID_MIN;
        if vote_ids.last().is_some_and(|p| *p >= v) {
            return Err(Error::Blob("vote ids not strictly ascending".into()));
        }
        vote_ids.push(v);
    }
    let mut keys: Vec<u64> = Vec::with_capacity(n_updates);
    for &key in &ints[n_vids..n_ints] {
        if !(BALLOT_MIN..=BALLOT_MAX).contains(&key) || keys.last().is_some_and(|p| *p >= key) {
            return Err(Error::Blob(
                "slot keys not ascending in the ballot namespace".into(),
            ));
        }
        keys.push(key);
    }
    let mut updates = Vec::with_capacity(n_updates);
    for key in keys {
        updates.push((key, c.ciphertexts(nfu)?));
    }

    for i in c.next..c.total() {
        if c.cell(i).is_none_or(|x| x.iter().any(|b| *b != 0)) {
            return Err(Error::Blob("non-zero data after the last ballot".into()));
        }
    }
    Ok(TransitionData {
        vote_ids,
        updates,
        num_fields: nf,
    })
}
