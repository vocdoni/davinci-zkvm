//! EIP-4844 DA blobs of a transition, byte-identical to the guest
//! (`circuit-primitives/src/da_blob.rs`, `circuit/src/kzg.rs`) and go-sdk
//! `blob.go`, plus the decoder a follower needs to rebuild state.
//!
//! ```text
//! enc(n_vids) enc(vid)...                       vote ids ascending
//! enc(n_updates) [enc(key) pack(c1_0) pack(c2_0) ...]...   ascending by key
//! pack(acc_c1_0) pack(acc_c2_0) ...             new accumulator
//! zero cells to the end of the last blob
//! enc(v) = BE32(v), pack(P) = Point::compress(P), only fields < nf.
//! z_b    = int_be(sha256(pid_BE32 || BE32(root_before_int) || com_b)) mod r_bls
//! digest = sha256(com_0 || y_0 || ...)
//! ```

use num_bigint::BigUint;
use sha2::{Digest, Sha256};

use crate::ballot::Ballot;
use crate::crypto::babyjubjub::Point;
use crate::crypto::elgamal::Ciphertext;
use crate::crypto::field::{fr_to_be, Fr};
use crate::limits::{
    required_refresh, BALLOT_MAX, BALLOT_MIN, MAX_BATCH_SIZE, MAX_BLOBS, NUM_FIELDS, VOTE_ID_MIN,
};
use crate::Error;

pub const CELLS_PER_BLOB: usize = 4096;
pub const BLOB_SIZE: usize = CELLS_PER_BLOB * 32;
pub type Blob = Box<[u8; BLOB_SIZE]>;

/// What one transition publishes. `updates` are new ballots and refreshed
/// ballots alike (the blob cannot tell them apart), `accumulator` is the
/// accumulator after the batch.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TransitionData {
    pub vote_ids: Vec<u64>,
    pub updates: Vec<(u64, Ballot)>,
    pub accumulator: Ballot,
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

fn enc_u64(v: u64) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[24..].copy_from_slice(&v.to_be_bytes());
    b
}

fn total_cells(n_vids: usize, n_updates: usize, nf: usize) -> usize {
    2 + n_vids + n_updates * (1 + 2 * nf) + 2 * nf
}

/// `ceil(T / 4096)` for `T = 2 + n_vids + n_updates*(1 + 2nf) + 2nf`.
pub fn blob_count(n_vote_ids: usize, n_updates: usize, nf: u8) -> usize {
    total_cells(n_vote_ids, n_updates, nf as usize).div_ceil(CELLS_PER_BLOB)
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

    let mut out = Vec::with_capacity(total_cells(vids.len(), updates.len(), nf));
    out.push(enc_u64(vids.len() as u64));
    out.extend(vids.iter().map(|v| enc_u64(*v)));
    out.push(enc_u64(updates.len() as u64));
    for (key, ballot) in updates {
        out.push(enc_u64(*key));
        for ct in &ballot.0[..nf] {
            out.push(ct.c1.compress());
            out.push(ct.c2.compress());
        }
    }
    for ct in &t.accumulator.0[..nf] {
        out.push(ct.c1.compress());
        out.push(ct.c2.compress());
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

    fn u64(&mut self) -> Result<u64, Error> {
        let c = self.take()?;
        if c[..24] != [0u8; 24] {
            return Err(Error::Blob("integer cell above 64 bits".into()));
        }
        let mut w = [0u8; 8];
        w.copy_from_slice(&c[24..]);
        Ok(u64::from_be_bytes(w))
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

    // A count must fit in the cells that are left.
    fn count(&mut self, per_item: usize) -> Result<usize, Error> {
        let n = self.u64()?;
        let left = self.total().saturating_sub(self.next) as u64;
        if n.saturating_mul(per_item as u64) > left {
            return Err(Error::Blob("count exceeds the blob data".into()));
        }
        Ok(n as usize)
    }
}

/// Parses a transition's blobs (in order) at the election's `nf`. Rejects
/// truncated or oversized counts, unsorted or out-of-namespace keys, invalid
/// points, non-zero padding and extra blobs.
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

    let n_vids = c.count(1)?;
    let mut vote_ids = Vec::with_capacity(n_vids);
    for _ in 0..n_vids {
        let v = c.u64()?;
        if v < VOTE_ID_MIN || vote_ids.last().is_some_and(|p| *p >= v) {
            return Err(Error::Blob(
                "vote ids not ascending in the vote-id namespace".into(),
            ));
        }
        vote_ids.push(v);
    }

    let n_updates = c.count(1 + 2 * nfu)?;
    let mut updates: Vec<(u64, Ballot)> = Vec::with_capacity(n_updates);
    for _ in 0..n_updates {
        let key = c.u64()?;
        if !(BALLOT_MIN..=BALLOT_MAX).contains(&key)
            || updates.last().is_some_and(|(p, _)| *p >= key)
        {
            return Err(Error::Blob(
                "slot keys not ascending in the ballot namespace".into(),
            ));
        }
        updates.push((key, c.ciphertexts(nfu)?));
    }
    let accumulator = c.ciphertexts(nfu)?;

    let used = c.next;
    if used.div_ceil(CELLS_PER_BLOB) != blobs.len() {
        return Err(Error::Blob("more blobs than the data needs".into()));
    }
    for i in used..c.total() {
        if c.cell(i).is_none_or(|x| x.iter().any(|b| *b != 0)) {
            return Err(Error::Blob("non-zero data after the accumulator".into()));
        }
    }
    Ok(TransitionData {
        vote_ids,
        updates,
        accumulator,
        num_fields: nf,
    })
}
