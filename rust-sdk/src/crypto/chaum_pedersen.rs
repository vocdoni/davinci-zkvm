//! Chaum-Pedersen proof that `m` is the ElGamal decryption of `(C1, C2)`
//! under `pk = sk*B8`, in the guest's format (`circuit-primitives/src/chaum_pedersen.rs`):
//!
//! ```text
//! D  = C2 - m*G
//! e  = Poseidon12(rte(P), rte(P), rte(C1), rte(D), rte(A1), rte(A2))
//! ok = z*G == A1 + e*P  &&  z*C1 == A2 + e*D
//! ```
//!
//! Points travel in TE form; only the hash sees RTE coordinates, because
//! davinci-node hashed gnark's in-memory form.

use num_bigint::BigUint;
use rand::{CryptoRng, RngCore};

use super::babyjubjub::Point;
use super::elgamal::{random_scalar, subgroup_order, Ciphertext};
use super::field::{biguint_to_u256, fr_to_u256, u256_to_biguint, Fr, U256};
use super::poseidon::poseidon;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DecryptionProof {
    pub a1: Point,
    pub a2: Point,
    pub z: U256,
}

fn challenge(pk: &Point, c1: &Point, d: &Point, a1: &Point, a2: &Point) -> Fr {
    let mut inputs = [Fr::from(0u64); 12];
    for (i, p) in [pk, pk, c1, d, a1, a2].iter().enumerate() {
        let (x, y) = p.to_rte();
        inputs[2 * i] = x;
        inputs[2 * i + 1] = y;
    }
    // 12 inputs is always a valid width.
    poseidon(&inputs).unwrap_or_default()
}

/// Proof with a fresh nonce `r` uniform in `[1, l)`.
pub fn prove_decryption<R: RngCore + CryptoRng>(
    sk: &U256,
    pk: &Point,
    c: &Ciphertext,
    m: u64,
    rng: &mut R,
) -> DecryptionProof {
    let r = random_scalar(rng);
    prove_decryption_with_nonce(sk, pk, c, m, &r)
}

/// Deterministic core of [`prove_decryption`]. `r` must be secret, uniform and
/// never reused: two proofs sharing `r` reveal `sk`.
pub fn prove_decryption_with_nonce(
    sk: &U256,
    pk: &Point,
    c: &Ciphertext,
    m: u64,
    r: &U256,
) -> DecryptionProof {
    let g = Point::generator();
    let a1 = g.mul(r);
    let a2 = c.c1.mul(r);
    let d = c.c2.sub(&g.mul(&U256::from(m)));
    let e = challenge(pk, &c.c1, &d, &a1, &a2);
    let l = subgroup_order();
    let z: BigUint =
        (u256_to_biguint(r) + u256_to_biguint(&fr_to_u256(&e)) * u256_to_biguint(sk)) % l;
    DecryptionProof {
        a1,
        a2,
        // z < l < 2^256.
        z: biguint_to_u256(&z).unwrap_or_default(),
    }
}

/// Same acceptance rule as the guest: every point on the curve, `e` and `z`
/// used unreduced.
pub fn verify_decryption(pk: &Point, c: &Ciphertext, m: u64, p: &DecryptionProof) -> bool {
    if ![pk, &c.c1, &c.c2, &p.a1, &p.a2]
        .iter()
        .all(|q| q.is_on_curve())
    {
        return false;
    }
    let g = Point::generator();
    let d = c.c2.sub(&g.mul(&U256::from(m)));
    let e = fr_to_u256(&challenge(pk, &c.c1, &d, &p.a1, &p.a2));
    g.mul(&p.z) == p.a1.add(&pk.mul(&e)) && c.c1.mul(&p.z) == p.a2.add(&d.mul(&e))
}
