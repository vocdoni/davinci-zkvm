//! Ballots, the ballot mode word and the hashes that bind them: leaf values,
//! vote ids and the circom ballot proof's inputs hash.

use ark_ff::{BigInteger, PrimeField};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::babyjubjub::Point;
use crate::crypto::elgamal::{encrypt, Ciphertext};
use crate::crypto::field::{fr_from_le, fr_to_be, fr_to_u256, Fr};
use crate::crypto::poseidon::{multi_poseidon, poseidon};
use crate::limits::{BALLOT_COORDS, NUM_FIELDS, VOTE_ID_MIN};
use crate::Error;

/// 16 ElGamal ciphertexts; fields at or above the election's `num_fields`
/// hold the TE identity.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Ballot(pub [Ciphertext; NUM_FIELDS]);

impl Ballot {
    pub fn identity() -> Self {
        Ballot([Ciphertext::IDENTITY; NUM_FIELDS])
    }

    /// Fields `>= nf` are the identity (the guest asserts this before skipping them).
    pub fn is_padded_ok(&self, nf: u8) -> bool {
        self.0.iter().skip(nf as usize).all(Ciphertext::is_identity)
    }

    pub fn add(&self, o: &Self) -> Self {
        let mut out = *self;
        for (a, b) in out.0.iter_mut().zip(o.0.iter()) {
            *a = a.add(b);
        }
        out
    }

    pub fn sub(&self, o: &Self) -> Self {
        let mut out = *self;
        for (a, b) in out.0.iter_mut().zip(o.0.iter()) {
            *a = a.sub(b);
        }
        out
    }

    /// `[c1x, c1y, c2x, c2y] x 16`, the layout every hash and wire format uses.
    pub fn coords(&self) -> [Fr; BALLOT_COORDS] {
        let mut out = [Fr::from(0u64); BALLOT_COORDS];
        for (i, c) in self.0.iter().enumerate() {
            out[i * 4] = c.c1.x;
            out[i * 4 + 1] = c.c1.y;
            out[i * 4 + 2] = c.c2.x;
            out[i * 4 + 3] = c.c2.y;
        }
        out
    }

    /// Inverse of [`Ballot::coords`]; every point must be on the curve.
    pub fn from_coords(c: &[Fr; BALLOT_COORDS]) -> Result<Self, Error> {
        let mut out = Self::identity();
        for (i, ct) in out.0.iter_mut().enumerate() {
            ct.c1 = Point {
                x: c[i * 4],
                y: c[i * 4 + 1],
            };
            ct.c2 = Point {
                x: c[i * 4 + 2],
                y: c[i * 4 + 3],
            };
            if !ct.c1.is_on_curve() || !ct.c2.is_on_curve() {
                return Err(Error::Point("ballot point not on the curve"));
            }
        }
        Ok(out)
    }
}

/// davinci-node `spec.BallotMode`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BallotMode {
    pub num_fields: u8,
    pub group_size: u8,
    pub unique_values: bool,
    pub cost_exponent: u8,
    pub max_value: u64,
    pub min_value: u64,
    pub max_value_sum: u64,
    pub min_value_sum: u64,
}

// Bit offsets and widths of the packed word (247 bits).
const MAX_VALUE_BITS: u32 = 48;
const SUM_BITS: u32 = 63;

impl BallotMode {
    /// `numFields[0:8] | groupSize[8:16] | unique[16] | costExp[17:25] |
    /// maxValue[25:73] | minValue[73:121] | maxValueSum[121:184] | minValueSum[184:247]`.
    /// Fails like Go's `Pack` on out-of-range values instead of overlapping bits.
    pub fn pack(&self) -> Result<Fr, Error> {
        if self.group_size > self.num_fields {
            return Err(Error::Input(
                "ballot mode: groupSize exceeds numFields".into(),
            ));
        }
        if self.max_value >> MAX_VALUE_BITS != 0 || self.min_value >> MAX_VALUE_BITS != 0 {
            return Err(Error::Input("ballot mode: value exceeds 48 bits".into()));
        }
        if self.max_value_sum >> SUM_BITS != 0 || self.min_value_sum >> SUM_BITS != 0 {
            return Err(Error::Input("ballot mode: sum exceeds 63 bits".into()));
        }
        let mut v = [0u64; 4];
        let mut put = |off: u32, val: u64| {
            let (w, b) = ((off / 64) as usize, off % 64);
            v[w] |= val << b;
            if b != 0 && w + 1 < 4 {
                v[w + 1] |= val >> (64 - b);
            }
        };
        put(0, self.num_fields as u64);
        put(8, self.group_size as u64);
        put(16, self.unique_values as u64);
        put(17, self.cost_exponent as u64);
        put(25, self.max_value);
        put(73, self.min_value);
        put(121, self.max_value_sum);
        put(184, self.min_value_sum);
        Ok(Fr::from_bigint(ark_ff::BigInt(v)).unwrap_or_default())
    }

    /// Inverse of [`BallotMode::pack`]; rejects bits at or above 247 and a
    /// group size above the field count.
    pub fn unpack(v: &Fr) -> Result<Self, Error> {
        let bi = v.into_bigint();
        if bi.num_bits() > 247 {
            return Err(Error::Input("ballot mode: bits above 247 set".into()));
        }
        let w = bi.0;
        let get = |off: u32, bits: u32| -> u64 {
            let (i, b) = ((off / 64) as usize, off % 64);
            let mut x = w[i] >> b;
            if b != 0 && i + 1 < 4 {
                x |= w[i + 1] << (64 - b);
            }
            if bits == 64 {
                x
            } else {
                x & ((1u64 << bits) - 1)
            }
        };
        let m = BallotMode {
            num_fields: get(0, 8) as u8,
            group_size: get(8, 8) as u8,
            unique_values: get(16, 1) == 1,
            cost_exponent: get(17, 8) as u8,
            max_value: get(25, MAX_VALUE_BITS),
            min_value: get(73, MAX_VALUE_BITS),
            max_value_sum: get(121, SUM_BITS),
            min_value_sum: get(184, SUM_BITS),
        };
        if m.group_size > m.num_fields {
            return Err(Error::Input(
                "ballot mode: groupSize exceeds numFields".into(),
            ));
        }
        Ok(m)
    }
}

/// Voter-side encryption as in davinci-circom: `k_1 = Poseidon(k)`,
/// `k_{i+1} = Poseidon(k_i)`, field `i` encrypted under `k_{i+1}`; fields
/// `>= nf` become the identity (for `1 <= nf < 16`, like the Go client).
/// Missing `fields` entries are zero.
pub fn encrypt_ballot(pk: &Point, fields: &[u64], k: &Fr, nf: u8) -> Ballot {
    let mut out = Ballot::identity();
    let pad = nf > 0 && (nf as usize) < NUM_FIELDS;
    let mut ki = *k;
    for (i, ct) in out.0.iter_mut().enumerate() {
        // A single input is always a valid Poseidon width.
        ki = poseidon(&[ki]).unwrap_or_default();
        if pad && i >= nf as usize {
            continue;
        }
        let m = fields.get(i).copied().unwrap_or(0);
        *ct = encrypt(pk, m, &fr_to_u256(&ki));
    }
    out
}

/// SMT leaf digest of a ballot: sha256 of the 64 coordinates as BE32 words.
/// The leaf value is this digest read big-endian (see [`leaf_value_bytes`]).
pub fn ballot_leaf_hash(b: &Ballot) -> [u8; 32] {
    let mut h = Sha256::new();
    for c in b.coords().iter() {
        h.update(fr_to_be(c));
    }
    h.finalize().into()
}

/// Config leaf 0x03 digest: `sha256(x_BE32 || y_BE32)`.
pub fn enc_key_hash(pk: &Point) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(fr_to_be(&pk.x));
    h.update(fr_to_be(&pk.y));
    h.finalize().into()
}

/// `2^63 + (Poseidon(pid, address, k) & (2^63 - 1))`.
pub fn vote_id(pid: &Fr, address: &Fr, k: &Fr) -> u64 {
    // Three inputs is always a valid Poseidon width.
    let h = poseidon(&[*pid, *address, *k]).unwrap_or_default();
    VOTE_ID_MIN | (h.into_bigint().0[0] & (VOTE_ID_MIN - 1))
}

/// Third public signal of the ballot proof: MultiPoseidon over
/// `[pid, mode, pk.x, pk.y, address, vote_id, 64 ballot coords, weight]`.
pub fn inputs_hash(
    pid: &Fr,
    mode: &BallotMode,
    pk: &Point,
    address: &Fr,
    vote_id: u64,
    ballot: &Ballot,
    weight: &Fr,
) -> Result<Fr, Error> {
    let mut inputs = Vec::with_capacity(71);
    inputs.extend_from_slice(&[*pid, mode.pack()?, pk.x, pk.y, *address, Fr::from(vote_id)]);
    inputs.extend_from_slice(&ballot.coords());
    inputs.push(*weight);
    multi_poseidon(&inputs)
}

/// Arbo leaf value bytes of a digest-valued leaf: the integer `int_be(digest)`
/// in LE32, i.e. `reverse(digest)`. Never reduced mod p.
pub fn leaf_value_bytes(digest: &[u8; 32]) -> [u8; 32] {
    let mut out = *digest;
    out.reverse();
    out
}

/// Address (20 bytes, BE) as a field element.
pub fn address_to_fr(address: &[u8; 20]) -> Fr {
    let mut le = [0u8; 32];
    for (i, b) in address.iter().rev().enumerate() {
        le[i] = *b;
    }
    // 160 bits is always below p.
    fr_from_le(&le).unwrap_or_default()
}
