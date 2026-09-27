//! Helpers shared by the vector tests.
#![allow(dead_code)]

use davinci_zkvm_sdk::ballot::Ballot;
use davinci_zkvm_sdk::crypto::babyjubjub::Point;
use davinci_zkvm_sdk::crypto::elgamal::Ciphertext;
use davinci_zkvm_sdk::crypto::field::{fr_from_dec, u256_from_dec, Fr, U256};
use serde_json::Value;

pub fn load(name: &str) -> Value {
    let path = format!("{}/testdata/{name}", env!("CARGO_MANIFEST_DIR"));
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&raw).unwrap()
}

pub fn s(v: &Value) -> &str {
    v.as_str().unwrap_or_else(|| panic!("not a string: {v}"))
}

pub fn fr(v: &Value) -> Fr {
    fr_from_dec(s(v)).unwrap()
}

pub fn u256(v: &Value) -> U256 {
    u256_from_dec(s(v)).unwrap()
}

pub fn u64v(v: &Value) -> u64 {
    match v {
        Value::String(x) => x.parse().unwrap(),
        _ => v.as_u64().unwrap(),
    }
}

/// `{"x": dec, "y": dec}` or the cp_vectors `{"te_x", "te_y"}` form.
pub fn point(v: &Value) -> Point {
    if v.get("te_x").is_some() {
        return Point {
            x: fr(&v["te_x"]),
            y: fr(&v["te_y"]),
        };
    }
    Point {
        x: fr(&v["x"]),
        y: fr(&v["y"]),
    }
}

pub fn ct(v: &Value) -> Ciphertext {
    Ciphertext {
        c1: point(&v["c1"]),
        c2: point(&v["c2"]),
    }
}

pub fn frs(v: &Value) -> Vec<Fr> {
    v.as_array().unwrap().iter().map(fr).collect()
}

/// 64 decimal TE coordinates.
pub fn ballot(v: &Value) -> Ballot {
    let c: [Fr; 64] = frs(v).try_into().unwrap();
    Ballot::from_coords(&c).unwrap()
}

pub fn hex32(v: &Value) -> [u8; 32] {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s(v), &mut out).unwrap();
    out
}

pub fn hex20(v: &Value) -> [u8; 20] {
    let mut out = [0u8; 20];
    hex::decode_to_slice(s(v), &mut out).unwrap();
    out
}
