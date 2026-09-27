//! Field, Poseidon, BabyJubJub, ElGamal and Chaum-Pedersen against the Go
//! reference vectors (go-sdk/cmd/sdk-vectors) and the guest's cp_vectors.json.

mod common;

use ark_ff::{BigInteger, PrimeField};
use common::*;
use davinci_zkvm_sdk::crypto::babyjubjub::{Point, SUBGROUP_ORDER};
use davinci_zkvm_sdk::crypto::chaum_pedersen::{
    prove_decryption, prove_decryption_with_nonce, verify_decryption, DecryptionProof,
};
use davinci_zkvm_sdk::crypto::elgamal::{decrypt, encrypt, keygen, reencrypt, Ciphertext};
use davinci_zkvm_sdk::crypto::field::*;
use davinci_zkvm_sdk::crypto::poseidon::{multi_poseidon, poseidon};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

const P_DEC: &str = "21888242871839275222246405745257275088548364400416034343698204186575808495617";

#[test]
fn field_encodings() {
    let x = fr_from_dec("123456789").unwrap();
    assert_eq!(fr_to_dec(&x), "123456789");
    let be = fr_to_be(&x);
    assert_eq!(fr_from_be(&be).unwrap(), x);
    let mut le = be;
    le.reverse();
    assert_eq!(fr_to_le(&x), le);
    assert!(fr_from_dec(P_DEC).is_err());
    assert!(fr_from_dec("-1").is_err());
    assert!(fr_from_dec("").is_err());
    assert!(fr_from_dec("0x10").is_err());
    let p_be =
        hex::decode("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001").unwrap();
    assert!(fr_from_be(&p_be.try_into().unwrap()).is_err());
}

#[test]
fn poseidon_matches_go_iden3() {
    let v = load("poseidon.json");
    let cases = v.as_array().unwrap();
    assert_eq!(cases.len(), 64);
    for c in cases {
        let inputs = frs(&c["inputs"]);
        assert_eq!(
            poseidon(&inputs).unwrap(),
            fr(&c["output"]),
            "width {}",
            inputs.len()
        );
    }
    assert!(poseidon(&[]).is_err());
    assert!(poseidon(&[Fr::from(1u64); 17]).is_err());
}

#[test]
fn poseidon12_matches_guest_vector() {
    let v = load("cp_vectors.json");
    assert_eq!(
        poseidon(&frs(&v["poseidon12_in"])).unwrap(),
        fr(&v["poseidon12_out"])
    );
}

#[test]
fn multi_poseidon_chunks_by_16() {
    let inputs: Vec<Fr> = (1..=71u64).map(Fr::from).collect();
    let chunks: Vec<Fr> = inputs.chunks(16).map(|c| poseidon(c).unwrap()).collect();
    assert_eq!(multi_poseidon(&inputs).unwrap(), poseidon(&chunks).unwrap());
    // guest wide_tests::ballot_inputs_hash_matches_multihash
    let expected = [
        0x766291e2382e3ef5u64,
        0x2c3d2b8c7b372e69,
        0x0fdddd04802ddbe4,
        0x057bfc2b042c3647,
    ];
    assert_eq!(fr_to_u256(&multi_poseidon(&inputs).unwrap()).0, expected);
}

#[test]
fn babyjubjub_matches_iden3() {
    let v = load("babyjubjub.json");
    assert_eq!(Point::generator(), point(&v["b8"]));
    assert_eq!(u256_to_dec(&SUBGROUP_ORDER), s(&v["sub_order"]));
    for m in v["muls"].as_array().unwrap() {
        let p = point(&m["p"]);
        let k = u256(&m["k"]);
        assert_eq!(Point::generator().mul(&k), p, "k = {}", s(&m["k"]));
        assert!(p.is_on_curve());
        assert!(p.in_subgroup());
        assert_eq!(hex::encode(p.compress()), s(&m["compressed"]));
        assert_eq!(Point::decompress(&p.compress()).unwrap(), p);
        let (rx, ry) = p.to_rte();
        assert_eq!((rx, ry), (fr(&m["rte"]["x"]), fr(&m["rte"]["y"])));
        assert_eq!(Point::from_rte(rx, ry), p);
    }
    for a in v["adds"].as_array().unwrap() {
        let (p, q, sum) = (point(&a["a"]), point(&a["b"]), point(&a["sum"]));
        assert_eq!(p.add(&q), sum);
        assert_eq!(sum.sub(&q), p);
    }
}

#[test]
fn babyjubjub_group_laws() {
    let g = Point::generator();
    assert_eq!(g.add(&Point::IDENTITY), g);
    assert_eq!(g.add(&g.neg()), Point::IDENTITY);
    assert_eq!(g.mul(&SUBGROUP_ORDER), Point::IDENTITY);
    assert_eq!(Point::IDENTITY.compress()[31], 1);
    assert_eq!(
        Point::decompress(&Point::IDENTITY.compress()).unwrap(),
        Point::IDENTITY
    );
}

#[test]
fn compress_roundtrip_1000_points() {
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let bases: Vec<Point> = (0..20).map(|_| keygen(&mut rng).1).collect();
    let mut p = Point::generator();
    for i in 0..1000 {
        p = p.add(&bases[i % bases.len()]);
        let q = if i % 2 == 0 { p } else { p.neg() };
        assert_eq!(Point::decompress(&q.compress()).unwrap(), q, "point {i}");
    }
}

#[test]
fn decompress_rejects_bad_encodings() {
    // y = p
    let p_be: [u8; 32] =
        hex::decode("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001")
            .unwrap()
            .try_into()
            .unwrap();
    assert!(Point::decompress(&p_be).is_err());
    // bit 255 set
    let mut c = Point::generator().compress();
    c[0] |= 0x80;
    assert!(Point::decompress(&c).is_err());
    // x = 0 with the parity bit: (0, 1) and (0, -1) only have x = 0.
    let mut c = Point::IDENTITY.compress();
    c[0] |= 0x40;
    assert!(Point::decompress(&c).is_err());
    // Some small y has no x (x^2 is a non-residue).
    let mut rejected = 0;
    for y in 2u64..40 {
        let mut c = [0u8; 32];
        c[24..].copy_from_slice(&y.to_be_bytes());
        match Point::decompress(&c) {
            Ok(p) => assert!(p.is_on_curve()),
            Err(e) => {
                assert!(e.to_string().contains("not on the curve"), "{e}");
                rejected += 1;
            }
        }
    }
    assert!(rejected > 0);
}

#[test]
fn subgroup_check() {
    let minus_one = -Fr::from(1u64);
    let order2 = Point {
        x: Fr::from(0u64),
        y: minus_one,
    };
    assert!(order2.is_on_curve());
    assert!(!order2.in_subgroup());
    // A generic curve point (from a y with a square root) is outside the
    // prime-order subgroup 7 times in 8.
    let mut outside = 0;
    for y in 2u64..60 {
        let mut c = [0u8; 32];
        c[24..].copy_from_slice(&y.to_be_bytes());
        if let Ok(p) = Point::decompress(&c) {
            if !p.in_subgroup() {
                outside += 1;
                assert!(p.mul(&ark_ff::BigInt::from(8u64)).in_subgroup());
            }
        }
    }
    assert!(outside > 0);
    assert!(!Point {
        x: Fr::from(1u64),
        y: Fr::from(1u64)
    }
    .in_subgroup());
}

#[test]
fn elgamal_matches_go() {
    let v = load("elgamal.json");
    let sk = u256(&v["sk"]);
    let pk = point(&v["pk"]);
    assert_eq!(Point::generator().mul(&sk), pk);
    for e in v["encryptions"].as_array().unwrap() {
        let m = u64v(&e["m"]);
        let c = encrypt(&pk, m, &u256(&e["k"]));
        assert_eq!(c, ct(&e["ct"]), "m = {m}");
        assert_eq!(decrypt(&sk, &c, 1_000_000), Some(m));
    }
}

#[test]
fn decrypt_bounds() {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let (sk, pk) = keygen(&mut rng);
    let k = keygen(&mut rng).0;
    for m in [0u64, 1, 2, 999, 1000, 1001, 123_456, 999_999, 1_000_000] {
        assert_eq!(
            decrypt(&sk, &encrypt(&pk, m, &k), 1_000_000),
            Some(m),
            "m = {m}"
        );
    }
    assert_eq!(decrypt(&sk, &encrypt(&pk, 1_000_001, &k), 1_000_000), None);
    assert_eq!(decrypt(&sk, &encrypt(&pk, 5, &k), 4), None);
    assert_eq!(decrypt(&sk, &encrypt(&pk, 0, &k), 0), Some(0));
    // Homomorphic sum and re-encryption keep the plaintext.
    let r = keygen(&mut rng).0;
    let sum = encrypt(&pk, 40, &k).add(&reencrypt(&encrypt(&pk, 2, &r), &pk, &k));
    assert_eq!(decrypt(&sk, &sum, 100), Some(42));
    assert_eq!(decrypt(&sk, &sum.sub(&encrypt(&pk, 2, &r)), 100), Some(40));
    assert_eq!(decrypt(&sk, &Ciphertext::IDENTITY, 10), Some(0));
}

fn cp_case(v: &serde_json::Value, pk: &Point) -> (Ciphertext, u64, DecryptionProof) {
    let c = Ciphertext {
        c1: point(&v["ct"]["c1"]),
        c2: point(&v["ct"]["c2"]),
    };
    let p = DecryptionProof {
        a1: point(&v["a1"]),
        a2: point(&v["a2"]),
        z: u256(&v["z"]),
    };
    let _ = pk;
    (c, u64v(&v["m"]), p)
}

#[test]
fn chaum_pedersen_matches_go() {
    let v = load("chaum_pedersen.json");
    let sk = u256(&v["sk"]);
    let pk = point(&v["pk"]);
    for case in v["vectors"].as_array().unwrap() {
        let (c, m, proof) = cp_case(case, &pk);
        let built = prove_decryption_with_nonce(&sk, &pk, &c, m, &u256(&case["r"]));
        assert_eq!(built, proof, "m = {m}");
        assert!(verify_decryption(&pk, &c, m, &proof));
    }
}

#[test]
fn chaum_pedersen_guest_vectors() {
    let v = load("cp_vectors.json");
    let pk = point(&v["pub_key"]);
    for case in v["vectors"].as_array().unwrap() {
        let c = Ciphertext {
            c1: point(&case["c1"]),
            c2: point(&case["c2"]),
        };
        let p = DecryptionProof {
            a1: point(&case["a1"]),
            a2: point(&case["a2"]),
            z: u256(&case["z"]),
        };
        assert!(verify_decryption(&pk, &c, u64v(&case["msg"]), &p));
    }
}

#[test]
fn chaum_pedersen_rejects_tampering() {
    let mut rng = ChaCha20Rng::seed_from_u64(3);
    let (sk, pk) = keygen(&mut rng);
    let c = encrypt(&pk, 17, &keygen(&mut rng).0);
    let p = prove_decryption(&sk, &pk, &c, 17, &mut rng);
    assert!(verify_decryption(&pk, &c, 17, &p));
    assert!(!verify_decryption(&pk, &c, 18, &p));
    assert!(!verify_decryption(&pk, &c, 16, &p));
    let mut z = p.z;
    z.add_with_carry(&ark_ff::BigInt::from(1u64));
    assert!(!verify_decryption(&pk, &c, 17, &DecryptionProof { z, ..p }));
    let g = Point::generator();
    assert!(!verify_decryption(
        &pk,
        &c,
        17,
        &DecryptionProof {
            a1: p.a1.add(&g),
            ..p
        }
    ));
    assert!(!verify_decryption(
        &pk,
        &c,
        17,
        &DecryptionProof {
            a2: p.a2.add(&g),
            ..p
        }
    ));
    // Off-curve commitment.
    let bad = Point {
        x: p.a1.x,
        y: p.a1.y + Fr::from(1u64),
    };
    assert!(!verify_decryption(
        &pk,
        &c,
        17,
        &DecryptionProof { a1: bad, ..p }
    ));
    // A different key.
    let (_, pk2) = keygen(&mut rng);
    assert!(!verify_decryption(&pk2, &c, 17, &p));
    // z is reduced below l.
    assert!(p.z < SUBGROUP_ORDER);
    assert!(p.z.num_bits() <= 252 && Fr::from_bigint(p.z).is_some());
}
