//! Exponential ElGamal on BabyJubJub (TE form, generator B8), as used by the
//! ballot circuit and the guest's accumulator.

use std::collections::HashMap;

use num_bigint::BigUint;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use super::babyjubjub::{Point, SUBGROUP_ORDER};
use super::field::{biguint_to_u256, u256_to_biguint, U256};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Ciphertext {
    pub c1: Point,
    pub c2: Point,
}

impl Ciphertext {
    /// `((0,1),(0,1))`: the padding value and the empty accumulator.
    pub const IDENTITY: Ciphertext = Ciphertext {
        c1: Point::IDENTITY,
        c2: Point::IDENTITY,
    };

    pub fn add(&self, o: &Self) -> Self {
        Ciphertext {
            c1: self.c1.add(&o.c1),
            c2: self.c2.add(&o.c2),
        }
    }

    pub fn sub(&self, o: &Self) -> Self {
        Ciphertext {
            c1: self.c1.sub(&o.c1),
            c2: self.c2.sub(&o.c2),
        }
    }

    pub fn is_identity(&self) -> bool {
        *self == Self::IDENTITY
    }
}

/// Uniform scalar in `[1, l)`.
pub fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> U256 {
    let l = u256_to_biguint(&SUBGROUP_ORDER);
    loop {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        b[31] &= 0x07; // l < 2^251: about 1 in 4 draws is rejected
        let v = BigUint::from_bytes_le(&b);
        if v.bits() > 0 && v < l {
            if let Some(s) = biguint_to_u256(&v) {
                return s;
            }
        }
    }
}

/// Fresh key pair: `sk` uniform in `[1, l)`, `pk = sk * B8`.
pub fn keygen<R: RngCore + CryptoRng>(rng: &mut R) -> (U256, Point) {
    let sk = random_scalar(rng);
    (sk, Point::generator().mul(&sk))
}

/// `(k*B8, m*B8 + k*pk)`.
pub fn encrypt(pk: &Point, m: u64, k: &U256) -> Ciphertext {
    let g = Point::generator();
    Ciphertext {
        c1: g.mul(k),
        c2: g.mul(&U256::from(m)).add(&pk.mul(k)),
    }
}

/// `c + Enc(0; r)`.
pub fn reencrypt(c: &Ciphertext, pk: &Point, r: &U256) -> Ciphertext {
    c.add(&encrypt(pk, 0, r))
}

/// Largest baby-step table (entries) `decrypt` builds.
const MAX_BABY_STEPS: u64 = 1 << 20;

/// Decrypts `m` in `[0, max]` by baby-step giant-step; `None` if out of range.
pub fn decrypt(sk: &U256, c: &Ciphertext, max: u64) -> Option<u64> {
    let target = c.c2.sub(&c.c1.mul(sk));
    let g = Point::generator();
    // step = ceil(sqrt(max + 1)), capped so the table stays bounded.
    let span = max as u128 + 1;
    let mut step = (span as f64).sqrt() as u64;
    while (step as u128) * (step as u128) < span {
        step += 1;
    }
    let step = step.clamp(1, MAX_BABY_STEPS);
    let mut table = HashMap::with_capacity(step as usize);
    let mut p = Point::IDENTITY;
    for j in 0..step {
        table.entry(p.compress()).or_insert(j);
        p = p.add(&g);
    }
    let giant = g.mul(&U256::from(step)).neg();
    let mut cur = target;
    let mut i: u64 = 0;
    loop {
        if let Some(&j) = table.get(&cur.compress()) {
            let m = i.checked_mul(step)?.checked_add(j)?;
            return (m <= max).then_some(m);
        }
        i = i.checked_add(1)?;
        if (i as u128) * (step as u128) > max as u128 {
            return None;
        }
        cur = cur.add(&giant);
    }
}

// l as a BigInt, for callers that reduce scalars.
pub(crate) fn subgroup_order() -> BigUint {
    u256_to_biguint(&SUBGROUP_ORDER)
}
