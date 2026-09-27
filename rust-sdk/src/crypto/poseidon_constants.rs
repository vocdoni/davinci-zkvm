//! iden3 Poseidon constants (optimized form: C, S, M, P) for t = 2..=17,
//! extracted from go-iden3-crypto by `go-sdk/cmd/sdk-vectors`. The guest's
//! t = 2, 3, 6, 8, 13, 17 tables are the same numbers.
//!
//! Layout per t: `u32le t | u32le len(C) | C | u32le len(S) | S | M | P`, every
//! value a 32-byte big-endian integer, matrices `t*t` row-major.

use std::sync::OnceLock;

use super::field::{fr_from_be, Fr};

static RAW: &[u8] = include_bytes!("../../assets/poseidon_constants.bin");

pub(crate) struct Params {
    pub c: Vec<Fr>,
    pub s: Vec<Fr>,
    /// `m[j][i]` as in go-iden3-crypto (`newState[i] = sum_j m[j][i] * state[j]`).
    pub m: Vec<Vec<Fr>>,
    pub p: Vec<Vec<Fr>>,
}

/// Partial rounds per t = 2..=17 (go-iden3-crypto `NROUNDSP`).
pub(crate) const N_ROUNDS_P: [usize; 16] = [
    56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68,
];
pub(crate) const N_ROUNDS_F: usize = 8;

/// Tables indexed by `t - 2`. `None` only if the embedded asset is corrupt,
/// which the test suite rules out.
pub(crate) fn params() -> Option<&'static [Params]> {
    static P: OnceLock<Option<Vec<Params>>> = OnceLock::new();
    P.get_or_init(|| parse(RAW)).as_deref()
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn u32(&mut self) -> Option<usize> {
        let (h, rest) = self.0.split_first_chunk::<4>()?;
        self.0 = rest;
        Some(u32::from_le_bytes(*h) as usize)
    }
    fn fr(&mut self) -> Option<Fr> {
        let (h, rest) = self.0.split_first_chunk::<32>()?;
        self.0 = rest;
        fr_from_be(h).ok()
    }
    fn frs(&mut self, n: usize) -> Option<Vec<Fr>> {
        (0..n).map(|_| self.fr()).collect()
    }
}

fn parse(raw: &[u8]) -> Option<Vec<Params>> {
    let mut r = Reader(raw);
    let mut out = Vec::with_capacity(16);
    for (i, &rp) in N_ROUNDS_P.iter().enumerate() {
        let t = i + 2;
        if r.u32()? != t {
            return None;
        }
        let nc = r.u32()?;
        if nc != t * N_ROUNDS_F + rp {
            return None;
        }
        let c = r.frs(nc)?;
        let ns = r.u32()?;
        if ns != rp * (2 * t - 1) {
            return None;
        }
        let s = r.frs(ns)?;
        let m = (0..t).map(|_| r.frs(t)).collect::<Option<Vec<_>>>()?;
        let p = (0..t).map(|_| r.frs(t)).collect::<Option<Vec<_>>>()?;
        out.push(Params { c, s, m, p });
    }
    r.0.is_empty().then_some(out)
}
