//! DKG point map and organizer Schnorr proof of possession — vector and property tests.

mod common;

use common::*;
use davinci_zkvm_sdk::crypto::babyjubjub::{Point, SUBGROUP_ORDER};
use davinci_zkvm_sdk::crypto::field::{fr_from_dec, fr_to_be, u256_from_dec, u256_to_le};
use davinci_zkvm_sdk::dkg::{
    point_from_rte, point_to_rte, prove_organizer, prove_organizer_with_witness,
    sample_organizer_sk,
};
use num_bigint::BigUint;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

// Reduced-form d parameter for the on-curve identity check.
const D_RTE: &str = "12181644023421730124874158521699555681764249180949974110617291017600649128846";
// Q (BN254 scalar field prime)
const Q_DEC: &str = "21888242871839275222246405745257275088548364400416034343698204186575808495617";

// Reduced-form generator G = to_rte(B8).
const G_X: &str = "9671717474070082183213120605117400219616337014328744928644933853176787189663";
const G_Y: &str = "16950150798460657717958625567821834550301663161624707787222815936182638968203";

fn be32_to_biguint(b: &[u8; 32]) -> BigUint {
    BigUint::from_bytes_be(b)
}

fn u256_bi(x: &davinci_zkvm_sdk::crypto::field::U256) -> BigUint {
    BigUint::from_bytes_le(&u256_to_le(x))
}

fn parse_dec(s: &str) -> BigUint {
    BigUint::parse_bytes(s.as_bytes(), 10).unwrap()
}

// ----- point map -----

#[test]
fn b8_maps_to_g() {
    let b8 = Point::generator();
    let (gx, gy) = point_to_rte(&b8);
    let gx_expected = fr_from_dec(G_X).unwrap();
    let gy_expected = fr_from_dec(G_Y).unwrap();
    assert_eq!(gx, fr_to_be(&gx_expected), "G x mismatch");
    assert_eq!(gy, fr_to_be(&gy_expected), "G y mismatch");
}

#[test]
fn g_maps_back_to_b8() {
    let b8 = Point::generator();
    let (gx_be, gy_be) = point_to_rte(&b8);
    let b8_rt = point_from_rte(&gx_be, &gy_be).expect("G should be on-curve");
    assert_eq!(b8_rt, b8, "round-trip failed");
}

#[test]
fn random_multiple_round_trips() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xdead_beef_cafe_1234);
    for _ in 0..8 {
        let k = sample_organizer_sk(&mut rng);
        let p = Point::generator().mul(&k);
        let (xr, yr) = point_to_rte(&p);
        let p_rt = point_from_rte(&xr, &yr).expect("point should be on-curve after round-trip");
        assert_eq!(p_rt, p);
    }
}

#[test]
fn image_on_reduced_curve() {
    // `-x^2 + y^2 = 1 + d_rte * x^2 * y^2` over BN254 Fr.
    let q = parse_dec(Q_DEC);
    let d_rte = parse_dec(D_RTE);
    let one = BigUint::from(1u32);

    let b8 = Point::generator();
    let (gx_be, gy_be) = point_to_rte(&b8);
    let xr = BigUint::from_bytes_be(&gx_be);
    let yr = BigUint::from_bytes_be(&gy_be);

    let x2 = (&xr * &xr) % &q;
    let y2 = (&yr * &yr) % &q;
    // lhs = -x^2 + y^2 = (q - x^2 + y^2) mod q
    let lhs = (&q - &x2 + &y2) % &q;
    // rhs = 1 + d_rte * x^2 * y^2 mod q
    let rhs = (&one + (&d_rte * &x2 % &q) * &y2 % &q) % &q;
    assert_eq!(lhs, rhs, "G not on reduced curve");
}

#[test]
fn from_rte_rejects_non_canonical() {
    // A coordinate equal to Q should be rejected as non-canonical.
    let q_be = {
        let q = parse_dec(Q_DEC);
        let b = q.to_bytes_be();
        let mut out = [0u8; 32];
        out[32 - b.len()..].copy_from_slice(&b);
        out
    };
    let zero = [0u8; 32];
    assert!(
        point_from_rte(&q_be, &zero).is_err(),
        "Q should be rejected as non-canonical x"
    );
}

// ----- challenge values match the research -----

#[test]
fn challenge_values_match_research() {
    // For each organizer vector, re-derive c from (z, w, sk) using
    // z = w + c*sk mod L  =>  c = (z - w) * sk^-1 mod L,
    // then compare to the research-computed value.
    let expected: &[(&str, &str)] = &[
        (
            "basic",
            "1349113307004817985936567427214153127579695431529803276712364580653602553064",
        ),
        (
            "different-aid",
            "943102449099162291962543359808627931948072259128121530001302619583274744389",
        ),
        (
            "different-secret",
            "800073265847646822934321894599357101429609167859181988381948321347179123226",
        ),
    ];

    let vectors = load("dkg_schnorr.json");
    let cases = vectors["organizer"].as_array().unwrap();
    let l = parse_dec(vectors["subgroupOrderL"].as_str().unwrap());

    for (label, c_expected_dec) in expected {
        let case = cases
            .iter()
            .find(|v| v["label"].as_str().unwrap() == *label)
            .unwrap_or_else(|| panic!("case {label} not found"));

        let sk_bi = parse_dec(case["secret"].as_str().unwrap());
        let w_bi = parse_dec(case["witness"].as_str().unwrap());
        let z_bi = parse_dec(case["z"].as_str().unwrap());
        let c_expected = parse_dec(c_expected_dec);

        // c = (z - w) * sk^-1 mod L
        let z_minus_w = (&z_bi + &l - &w_bi) % &l;
        let sk_inv = sk_bi.modinv(&l).unwrap();
        let c_actual = (z_minus_w * sk_inv) % &l;
        assert_eq!(c_actual, c_expected, "challenge mismatch for {label}");
    }
}

// ----- vector test: all three organizer cases -----

#[test]
fn organizer_vectors() {
    let vectors = load("dkg_schnorr.json");
    let cases = vectors["organizer"].as_array().unwrap();

    for case in cases {
        let label = case["label"].as_str().unwrap();
        let sk = u256_from_dec(case["secret"].as_str().unwrap()).unwrap();
        let w = u256_from_dec(case["witness"].as_str().unwrap()).unwrap();

        let epoch_id = hex12(case["epochId"].as_str().unwrap());
        let aid = hex32_json(&case["aid"]);

        let (pk_x, pk_y, a_x, a_y, z) =
            prove_organizer_with_witness(epoch_id, aid, sk, w).expect(label);

        let exp_px = fr_from_dec(case["pkOrgX"].as_str().unwrap()).unwrap();
        let exp_py = fr_from_dec(case["pkOrgY"].as_str().unwrap()).unwrap();
        let exp_ax = fr_from_dec(case["ax"].as_str().unwrap()).unwrap();
        let exp_ay = fr_from_dec(case["ay"].as_str().unwrap()).unwrap();
        let exp_z = parse_dec(case["z"].as_str().unwrap());

        assert_eq!(pk_x, fr_to_be(&exp_px), "{label}: pkOrgX");
        assert_eq!(pk_y, fr_to_be(&exp_py), "{label}: pkOrgY");
        assert_eq!(a_x, fr_to_be(&exp_ax), "{label}: ax");
        assert_eq!(a_y, fr_to_be(&exp_ay), "{label}: ay");
        assert_eq!(be32_to_biguint(&z), exp_z, "{label}: z");
    }
}

// ----- proof verifier: z*G == A + c*PK in TE form -----

#[test]
fn random_proof_verifies() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x1234_5678_abcd_ef01);
    let sk = sample_organizer_sk(&mut rng);

    let epoch_id = [0u8; 12];
    let aid = [0xab; 32];

    let (pk_x, pk_y, a_x, a_y, z_be) = prove_organizer(epoch_id, aid, sk, &mut rng).unwrap();

    // Convert everything back to TE for the check.
    let pk = point_from_rte(&pk_x, &pk_y).unwrap();
    let a = point_from_rte(&a_x, &a_y).unwrap();

    let vectors = load("dkg_schnorr.json");
    let l_bi = parse_dec(vectors["subgroupOrderL"].as_str().unwrap());

    // Re-derive c from the public transcript.
    let c_hash = {
        use sha3::{Digest, Keccak256};
        const DOMAIN: [u8; 32] = [
            0x41, 0xea, 0x6f, 0x3f, 0xa9, 0x5e, 0xcc, 0xd1, 0xf3, 0xb1, 0xce, 0x8e, 0x05, 0xef,
            0xa1, 0x10, 0x27, 0x28, 0x0a, 0xa0, 0xc6, 0xb4, 0x16, 0x7f, 0xd6, 0x69, 0x5d, 0xb6,
            0x59, 0xc3, 0x0b, 0x28,
        ];
        let mut h = Keccak256::new();
        h.update(DOMAIN);
        h.update(epoch_id);
        h.update(aid);
        h.update(pk_x);
        h.update(pk_y);
        h.update(a_x);
        h.update(a_y);
        let hash = h.finalize();
        BigUint::from_bytes_be(&hash) % &l_bi
    };

    // Convert c to U256 (LE limbs).
    let c_le_bytes = {
        let b = c_hash.to_bytes_le();
        let mut out = [0u8; 32];
        out[..b.len()].copy_from_slice(&b);
        out
    };
    let c_u256 = davinci_zkvm_sdk::crypto::field::u256_from_le(&c_le_bytes);

    // z as U256.
    let z_le_bytes = {
        let bi = be32_to_biguint(&z_be);
        let b = bi.to_bytes_le();
        let mut out = [0u8; 32];
        out[..b.len()].copy_from_slice(&b);
        out
    };
    let z_u256 = davinci_zkvm_sdk::crypto::field::u256_from_le(&z_le_bytes);

    // z * G (TE form)
    let g = Point::generator();
    let lhs = g.mul(&z_u256);

    // A + c * PK
    let rhs = a.add(&pk.mul(&c_u256));

    assert_eq!(lhs, rhs, "Schnorr equation z*G == A + c*PK failed");
}

// ----- rejection sampling bounds -----

#[test]
fn sample_sk_in_range() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xf00d_cafe);
    let l = u256_bi(&SUBGROUP_ORDER);
    let one = BigUint::from(1u32);
    for _ in 0..100 {
        let sk = sample_organizer_sk(&mut rng);
        let sk_bi = u256_bi(&sk);
        assert!(sk_bi >= one, "sk must be >= 1");
        assert!(sk_bi < l, "sk must be < L");
    }
}

// ----- local helpers -----

fn hex12(s: &str) -> [u8; 12] {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let b = hex::decode(s).unwrap();
    b.try_into()
        .unwrap_or_else(|v: Vec<u8>| panic!("expected 12 bytes, got {}", v.len()))
}

fn hex32_json(v: &serde_json::Value) -> [u8; 32] {
    let s = v.as_str().unwrap();
    let s = s.strip_prefix("0x").unwrap_or(s);
    let b = hex::decode(s).unwrap();
    let mut out = [0u8; 32];
    // right-align if shorter (some aids in the vectors are short)
    let offset = 32usize.saturating_sub(b.len());
    out[offset..].copy_from_slice(&b);
    out
}
