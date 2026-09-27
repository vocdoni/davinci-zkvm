//! BN254 scalar field helpers (the BabyJubJub base field) and the byte orders
//! the protocol uses for it.

use ark_ff::{BigInteger, PrimeField};
use num_bigint::BigUint;

use crate::Error;

pub use ark_bn254::Fr;
/// Raw 256-bit integer, 4 little-endian u64 limbs. Used for scalars that are
/// not reduced (BabyJubJub scalars, `z` of a CP proof).
pub type U256 = ark_ff::BigInt<4>;

/// Canonical big-endian bytes to Fr; rejects values `>= p`.
pub fn fr_from_be(b: &[u8; 32]) -> Result<Fr, Error> {
    let mut le = *b;
    le.reverse();
    fr_from_le(&le)
}

/// Canonical little-endian bytes to Fr; rejects values `>= p`.
pub fn fr_from_le(b: &[u8; 32]) -> Result<Fr, Error> {
    Fr::from_bigint(u256_from_le(b)).ok_or_else(|| Error::Field("value >= p".into()))
}

/// Big-endian bytes read as an integer and reduced mod p.
pub fn fr_from_be_mod_order(b: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(b)
}

pub fn fr_to_be(x: &Fr) -> [u8; 32] {
    let mut out = fr_to_le(x);
    out.reverse();
    out
}

pub fn fr_to_le(x: &Fr) -> [u8; 32] {
    u256_to_le(&x.into_bigint())
}

/// Decimal string (digits only) to Fr; rejects values `>= p`.
pub fn fr_from_dec(s: &str) -> Result<Fr, Error> {
    let v = biguint_from_dec(s)?;
    let bytes = v.to_bytes_le();
    if bytes.len() > 32 {
        return Err(Error::Field("value >= p".into()));
    }
    let mut le = [0u8; 32];
    le[..bytes.len()].copy_from_slice(&bytes);
    fr_from_le(&le)
}

pub fn fr_to_dec(x: &Fr) -> String {
    BigUint::from_bytes_le(&fr_to_le(x)).to_string()
}

/// Decimal string (digits only, < 2^256) to a raw 256-bit integer.
pub fn u256_from_dec(s: &str) -> Result<U256, Error> {
    let bytes = biguint_from_dec(s)?.to_bytes_le();
    if bytes.len() > 32 {
        return Err(Error::Field("value >= 2^256".into()));
    }
    let mut le = [0u8; 32];
    le[..bytes.len()].copy_from_slice(&bytes);
    Ok(u256_from_le(&le))
}

pub fn u256_to_dec(x: &U256) -> String {
    BigUint::from_bytes_le(&u256_to_le(x)).to_string()
}

pub fn u256_from_le(b: &[u8; 32]) -> U256 {
    let mut limbs = [0u64; 4];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let mut w = [0u8; 8];
        w.copy_from_slice(&b[i * 8..i * 8 + 8]);
        *limb = u64::from_le_bytes(w);
    }
    ark_ff::BigInt(limbs)
}

pub fn u256_from_be(b: &[u8; 32]) -> U256 {
    let mut le = *b;
    le.reverse();
    u256_from_le(&le)
}

pub fn u256_to_le(x: &U256) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&x.to_bytes_le());
    out
}

pub fn u256_to_be(x: &U256) -> [u8; 32] {
    let mut out = u256_to_le(x);
    out.reverse();
    out
}

/// Fr as a raw integer (for scalar multiplication).
pub fn fr_to_u256(x: &Fr) -> U256 {
    x.into_bigint()
}

pub(crate) fn biguint_from_dec(s: &str) -> Result<BigUint, Error> {
    if s.is_empty() || s.len() > 80 || !s.bytes().all(|c| c.is_ascii_digit()) {
        return Err(Error::Field(format!("not a decimal integer: {s:.20}")));
    }
    BigUint::parse_bytes(s.as_bytes(), 10).ok_or_else(|| Error::Field("bad decimal".into()))
}

pub(crate) fn biguint_to_u256(v: &BigUint) -> Option<U256> {
    let bytes = v.to_bytes_le();
    if bytes.len() > 32 {
        return None;
    }
    let mut le = [0u8; 32];
    le[..bytes.len()].copy_from_slice(&bytes);
    Some(u256_from_le(&le))
}

pub(crate) fn u256_to_biguint(x: &U256) -> BigUint {
    BigUint::from_bytes_le(&u256_to_le(x))
}
