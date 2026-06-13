//! Chaum-Pedersen decryption-proof verification, bit-exact with
//! davinci-node `crypto/elgamal/proof.go::VerifyDecryptionProof`.
//!
//! The proof shows that `msg` is the correct ElGamal decryption of
//! `(C1, C2)` under the private key matching `pub_key`:
//!
//! ```text
//! D  = C2 - msg*G
//! e  = Poseidon12(rte(P), rte(P), rte(C1), rte(D), rte(A1), rte(A2))
//! ok = z*G == A1 + e*P  &&  z*C1 == A2 + e*D
//! ```
//!
//! All points arrive in standard Twisted Edwards coordinates (the form
//! stored in the state tree). davinci-node hashes the gnark in-memory
//! Reduced Twisted Edwards coordinates, so each coordinate pair is
//! converted as `x' = x * (-f)` (y unchanged) before hashing. Scalars
//! `z` and `e` are used unreduced; double-and-add over the full 256 bits
//! gives the same group element as gnark's mod-order multiplication.

use crate::babyjubjub::{bjj_add, bjj_generator, bjj_mul, bjj_neg, bjj_on_curve, BjjAffine};
use crate::bn254_fr;
use crate::poseidon::poseidon12;
use crate::types::FrRaw;

/// `-f mod p` where `f` is the gnark/iden3 BabyJubJub scaling factor
/// 6360561867910373094066688120553762416144456282423235903351243436111059670888.
/// `x_rte = x_te * (-f)`.
const NEG_F: FrRaw = [
    0xd76612d2174d2899,
    0xb38df17e479acf79,
    0x8bd584e7fc9b46e5,
    0x22545b22db5abade,
];

/// Convert a TE x-coordinate to the RTE form used by the Fiat-Shamir hash.
fn te_x_to_rte(x: &FrRaw) -> FrRaw {
    bn254_fr::mul(x, &NEG_F)
}

/// One decryption proof: commitments A1, A2 and response z.
pub struct CpProof {
    pub a1: BjjAffine,
    pub a2: BjjAffine,
    pub z: FrRaw,
}

/// Verify one Chaum-Pedersen decryption proof.
///
/// `pub_key`, `c1`, `c2` and the proof points are TE-affine. `msg` is the
/// claimed plaintext (small tally value).
pub fn verify_decryption(
    pub_key: &BjjAffine,
    c1: &BjjAffine,
    c2: &BjjAffine,
    msg: u64,
    proof: &CpProof,
) -> bool {
    for p in [pub_key, c1, c2, &proof.a1, &proof.a2] {
        if !bjj_on_curve(p) {
            return false;
        }
    }

    let g = bjj_generator();

    // D = C2 - msg*G
    let m_g = bjj_mul(&g, &[msg, 0, 0, 0]);
    let d = bjj_add(c2, &bjj_neg(&m_g));

    // e = Poseidon12 over RTE coordinates of (P, P, C1, D, A1, A2)
    let mut inputs = [bn254_fr::ZERO; 12];
    for (i, pt) in [pub_key, pub_key, c1, &d, &proof.a1, &proof.a2].iter().enumerate() {
        inputs[i * 2] = te_x_to_rte(&pt.0);
        inputs[i * 2 + 1] = pt.1;
    }
    let e = poseidon12(&inputs);

    // z*G == A1 + e*P
    let left1 = bjj_mul(&g, &proof.z);
    let right1 = bjj_add(&proof.a1, &bjj_mul(pub_key, &e));
    if left1 != right1 {
        return false;
    }

    // z*C1 == A2 + e*D
    let left2 = bjj_mul(c1, &proof.z);
    let right2 = bjj_add(&proof.a2, &bjj_mul(&d, &e));
    left2 == right2
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon::poseidon12;
    use serde_json::Value;

    const VECTORS: &str = include_str!("../testdata/cp_vectors.json");

    /// Decimal string → FrRaw (little-endian u64 words). Values are < BN254 p.
    fn dec_to_fr(s: &str) -> FrRaw {
        let mut limbs = [0u64; 4];
        for ch in s.bytes() {
            let digit = (ch - b'0') as u128;
            let mut carry = digit;
            for limb in limbs.iter_mut() {
                let v = (*limb as u128) * 10 + carry;
                *limb = v as u64;
                carry = v >> 64;
            }
        }
        limbs
    }

    fn te_point(v: &Value) -> BjjAffine {
        (
            dec_to_fr(v["te_x"].as_str().unwrap()),
            dec_to_fr(v["te_y"].as_str().unwrap()),
        )
    }

    #[test]
    fn generator_matches_reference() {
        let root: Value = serde_json::from_str(VECTORS).unwrap();
        assert_eq!(bjj_generator(), te_point(&root["generator"]));
    }

    // The Fiat-Shamir hash is the riskiest part of bit-exactness. Check the
    // standalone Poseidon-12 vector independently of the curve arithmetic.
    #[test]
    fn poseidon12_matches_reference() {
        let root: Value = serde_json::from_str(VECTORS).unwrap();
        let inputs: Vec<FrRaw> = root["poseidon12_in"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| dec_to_fr(x.as_str().unwrap()))
            .collect();
        let arr: [FrRaw; 12] = inputs.try_into().unwrap();
        let expected = dec_to_fr(root["poseidon12_out"].as_str().unwrap());
        assert_eq!(poseidon12(&arr), expected);
    }

    // Full end-to-end: every davinci-node vector must verify, and the
    // recomputed challenge e must match the reference value bit-for-bit.
    #[test]
    fn verifies_all_reference_vectors() {
        let root: Value = serde_json::from_str(VECTORS).unwrap();
        let pub_key = te_point(&root["pub_key"]);
        for (i, vec) in root["vectors"].as_array().unwrap().iter().enumerate() {
            let c1 = te_point(&vec["c1"]);
            let c2 = te_point(&vec["c2"]);
            let msg: u64 = vec["msg"].as_str().unwrap().parse().unwrap();
            let proof = CpProof {
                a1: te_point(&vec["a1"]),
                a2: te_point(&vec["a2"]),
                z: dec_to_fr(vec["z"].as_str().unwrap()),
            };

            // Recompute the challenge and compare to the reference e.
            let m_g = bjj_mul(&bjj_generator(), &[msg, 0, 0, 0]);
            let d = bjj_add(&c2, &bjj_neg(&m_g));
            let mut inputs = [bn254_fr::ZERO; 12];
            for (j, pt) in [&pub_key, &pub_key, &c1, &d, &proof.a1, &proof.a2]
                .iter()
                .enumerate()
            {
                inputs[j * 2] = te_x_to_rte(&pt.0);
                inputs[j * 2 + 1] = pt.1;
            }
            let e = poseidon12(&inputs);
            assert_eq!(
                e,
                dec_to_fr(vec["e"].as_str().unwrap()),
                "vector {i}: challenge mismatch"
            );

            assert!(
                verify_decryption(&pub_key, &c1, &c2, msg, &proof),
                "vector {i}: verification failed"
            );
        }
    }

    // A wrong plaintext must be rejected (soundness).
    #[test]
    fn rejects_wrong_plaintext() {
        let root: Value = serde_json::from_str(VECTORS).unwrap();
        let pub_key = te_point(&root["pub_key"]);
        let vec = &root["vectors"][0];
        let c1 = te_point(&vec["c1"]);
        let c2 = te_point(&vec["c2"]);
        let msg: u64 = vec["msg"].as_str().unwrap().parse().unwrap();
        let proof = CpProof {
            a1: te_point(&vec["a1"]),
            a2: te_point(&vec["a2"]),
            z: dec_to_fr(vec["z"].as_str().unwrap()),
        };
        assert!(!verify_decryption(&pub_key, &c1, &c2, msg + 1, &proof));
    }
}
