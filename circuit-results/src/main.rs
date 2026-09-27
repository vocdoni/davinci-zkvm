// DAVINCI results guest: the single-key tally of one election.
//
// Under a given final state root it proves that the election key is leaf
// 0x03, that the net results accumulator is leaf 0x04, and that each of the
// accumulator's 16 ciphertexts decrypts to the claimed plaintext
// (Chaum-Pedersen). Frame, checks, registers and fail bits: RESULTS.md.

#![no_main]
ziskos::entrypoint!(main);

use circuit_primitives::babyjubjub::{
    bjj_identity, bjj_mul, bjj_on_curve, BjjAffine, BJJ_SUBGROUP_L,
};
use circuit_primitives::bn254_fr::{reduce, BN254_FR_MOD};
use circuit_primitives::chaum_pedersen::{verify_decryption, CpProof};
use circuit_primitives::hash::hash_enc_key;
use circuit_primitives::results::ballot_leaf_hash;
use circuit_primitives::smt::{le_to_fr, verify_inclusion};
use circuit_primitives::types::{
    BallotData, FrRaw, BALLOT_FIELDS, NUM_FIELDS, SMT_LEVELS, ZERO_FR,
};
use ziskos::io::{commit_slice, read_slice};

const MAGIC: u64 = u64::from_le_bytes(*b"DAVRSLT1");
const CP_BYTES: usize = 5 * 32;
const FRAME_LEN: usize = 8
    + 32
    + 64
    + 8
    + SMT_LEVELS * 32
    + BALLOT_FIELDS * 32
    + 8
    + SMT_LEVELS * 32
    + NUM_FIELDS * 8
    + NUM_FIELDS * CP_BYTES;

const FAIL_PARSE: u32 = 1 << 0;
const FAIL_KEY: u32 = 1 << 1;
const FAIL_INCL_KEY: u32 = 1 << 2;
const FAIL_INCL_RESULTS: u32 = 1 << 3;
const FAIL_CP: u32 = 1 << 4;
const FAIL_RANGE: u32 = 1 << 5;

const KEY_ENC: FrRaw = [0x03, 0, 0, 0];
const KEY_RESULTS: FrRaw = [0x04, 0, 0, 0];

const N_REGS: usize = 43;
const REG_ROOT: usize = 2;
const REG_RESULTS: usize = 10;
const REG_CP_INDEX: usize = 42;
const NO_INDEX: u32 = u32::MAX;

struct Input {
    state_root: FrRaw,
    pk: BjjAffine,
    key_siblings: [FrRaw; SMT_LEVELS],
    acc: BallotData,
    acc_siblings: [FrRaw; SMT_LEVELS],
    results: [u64; NUM_FIELDS],
    cp: [CpProof; NUM_FIELDS],
}

/// Sequential frame reader; every read is bounds-checked.
struct Reader<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> Reader<'a> {
    fn take<const N: usize>(&mut self) -> Option<[u8; N]> {
        let end = self.off.checked_add(N)?;
        let b = self.buf.get(self.off..end)?.try_into().ok()?;
        self.off = end;
        Some(b)
    }

    fn u64(&mut self) -> Option<u64> {
        self.take::<8>().map(u64::from_le_bytes)
    }

    fn fr(&mut self) -> Option<FrRaw> {
        self.take::<32>().map(|b| le_to_fr(&b))
    }

    fn siblings(&mut self) -> Option<[FrRaw; SMT_LEVELS]> {
        if self.u64()? != SMT_LEVELS as u64 {
            return None;
        }
        let mut s = [ZERO_FR; SMT_LEVELS];
        for v in s.iter_mut() {
            *v = self.fr()?;
        }
        Some(s)
    }
}

/// Parse the exact-length frame; `None` on any deviation.
fn parse(frame: &[u8]) -> Option<Input> {
    if frame.len() != FRAME_LEN {
        return None;
    }
    let mut r = Reader { buf: frame, off: 0 };
    if r.u64()? != MAGIC {
        return None;
    }
    let state_root = r.fr()?;
    let pk = (r.fr()?, r.fr()?);
    let key_siblings = r.siblings()?;
    let mut acc = [ZERO_FR; BALLOT_FIELDS];
    for c in acc.iter_mut() {
        *c = r.fr()?;
    }
    let acc_siblings = r.siblings()?;
    let mut results = [0u64; NUM_FIELDS];
    for m in results.iter_mut() {
        *m = r.u64()?;
    }
    let mut cp: [CpProof; NUM_FIELDS] = core::array::from_fn(|_| CpProof {
        a1: (ZERO_FR, ZERO_FR),
        a2: (ZERO_FR, ZERO_FR),
        z: ZERO_FR,
    });
    for p in cp.iter_mut() {
        p.a1 = (r.fr()?, r.fr()?);
        p.a2 = (r.fr()?, r.fr()?);
        p.z = r.fr()?;
    }
    if r.off != frame.len() {
        return None;
    }
    Some(Input {
        state_root,
        pk,
        key_siblings,
        acc,
        acc_siblings,
        results,
        cp,
    })
}

/// `a < m` for raw LE limbs.
fn lt(a: &FrRaw, m: &FrRaw) -> bool {
    for i in (0..4).rev() {
        if a[i] != m[i] {
            return a[i] < m[i];
        }
    }
    false
}

/// Every coordinate below p and every CP scalar below l. Leaf hashes and the
/// CP challenge see raw bytes, so a second encoding of a point must not pass.
fn canonical(inp: &Input) -> bool {
    let fr_ok = |v: &FrRaw| lt(v, &BN254_FR_MOD);
    fr_ok(&inp.pk.0)
        && fr_ok(&inp.pk.1)
        && inp.acc.iter().all(fr_ok)
        && inp.cp.iter().all(|p| {
            fr_ok(&p.a1.0)
                && fr_ok(&p.a1.1)
                && fr_ok(&p.a2.0)
                && fr_ok(&p.a2.1)
                && lt(&p.z, &BJJ_SUBGROUP_L)
        })
}

/// On the curve, not the identity, in the prime subgroup.
fn key_valid(pk: &BjjAffine) -> bool {
    if !bjj_on_curve(pk) {
        return false;
    }
    let canon = (reduce(&pk.0), reduce(&pk.1));
    canon != bjj_identity() && bjj_mul(pk, &BJJ_SUBGROUP_L) == bjj_identity()
}

fn main() {
    let frame = read_slice();
    let mut fail_mask = 0u32;
    let mut cp_index = NO_INDEX;
    let mut regs = [0u32; N_REGS];

    match parse(&frame) {
        None => fail_mask |= FAIL_PARSE,
        Some(inp) => {
            if !canonical(&inp) {
                fail_mask |= FAIL_RANGE;
            }
            if !key_valid(&inp.pk) {
                fail_mask |= FAIL_KEY;
            }
            let key_leaf = hash_enc_key(&inp.pk.0, &inp.pk.1);
            if !verify_inclusion(&inp.state_root, &KEY_ENC, &key_leaf, &inp.key_siblings) {
                fail_mask |= FAIL_INCL_KEY;
            }
            let acc_leaf = ballot_leaf_hash(&inp.acc);
            if !verify_inclusion(&inp.state_root, &KEY_RESULTS, &acc_leaf, &inp.acc_siblings) {
                fail_mask |= FAIL_INCL_RESULTS;
            }
            for i in 0..NUM_FIELDS {
                let c1 = (inp.acc[i * 4], inp.acc[i * 4 + 1]);
                let c2 = (inp.acc[i * 4 + 2], inp.acc[i * 4 + 3]);
                if !verify_decryption(&inp.pk, &c1, &c2, inp.results[i], &inp.cp[i])
                    && cp_index == NO_INDEX
                {
                    fail_mask |= FAIL_CP;
                    cp_index = i as u32;
                }
            }

            // Root and tallies are published only for an accepted input.
            if fail_mask == 0 {
                for j in 0..4 {
                    regs[REG_ROOT + 2 * j] = inp.state_root[j] as u32;
                    regs[REG_ROOT + 2 * j + 1] = (inp.state_root[j] >> 32) as u32;
                }
                for (i, m) in inp.results.iter().enumerate() {
                    regs[REG_RESULTS + 2 * i] = *m as u32;
                    regs[REG_RESULTS + 2 * i + 1] = (*m >> 32) as u32;
                }
            }
        }
    }

    regs[0] = (fail_mask == 0) as u32;
    regs[1] = fail_mask;
    regs[REG_CP_INDEX] = cp_index;

    let mut out = [0u8; N_REGS * 4];
    for (i, r) in regs.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&r.to_le_bytes());
    }
    commit_slice(&out);
}
