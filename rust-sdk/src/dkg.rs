//! DKG point map and organizer Schnorr proof of possession.
//!
//! Maps BabyJubJub points between the circomlib TE form (a=168700, d=168696,
//! generator B8) and the DKG reduced TE form (a=-1, generator G). Provides the
//! Schnorr proof of possession needed by `DKGAppManager.registerApplication` in
//! OrganizerLocked mode. All five output values are canonical BE32 `uint256`s
//! ready for the Solidity call.

use num_bigint::BigUint;
use rand::{CryptoRng, RngCore};
use sha3::{Digest, Keccak256};

use crate::crypto::babyjubjub::{Point, SUBGROUP_ORDER};
use crate::crypto::field::{biguint_to_u256, fr_from_be, fr_to_be, u256_to_biguint, U256};
use crate::Error;

/// `(pk_x, pk_y, a_x, a_y, z)` as BE32 `uint256`s in reduced TE form.
pub type OrganizerPoP = ([u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32]);

// `keccak256("davinci-dkg:organizer-register:v1")` — raw 32 bytes.
// The vector file records the value reduced mod Q; the hash uses these raw bytes.
const DOMAIN: [u8; 32] = [
    0x41, 0xea, 0x6f, 0x3f, 0xa9, 0x5e, 0xcc, 0xd1, 0xf3, 0xb1, 0xce, 0x8e, 0x05, 0xef, 0xa1, 0x10,
    0x27, 0x28, 0x0a, 0xa0, 0xc6, 0xb4, 0x16, 0x7f, 0xd6, 0x69, 0x5d, 0xb6, 0x59, 0xc3, 0x0b, 0x28,
];

/// Convert a circomlib TE point to the DKG reduced TE form.
///
/// `x_rte = x_te · k mod Q`, `y_rte = y_te`. Returns `(x_rte_be32, y_be32)`.
pub fn point_to_rte(p: &Point) -> ([u8; 32], [u8; 32]) {
    let (xr, yr) = p.to_rte();
    (fr_to_be(&xr), fr_to_be(&yr))
}

/// Convert reduced TE coordinates to a circomlib TE `Point`, checking on-curve.
///
/// Coordinates must be canonical (`< Q`). Returns an error if either coordinate
/// is out of range or the resulting TE point is not on the circomlib curve.
pub fn point_from_rte(x: &[u8; 32], y: &[u8; 32]) -> Result<Point, Error> {
    let xr = fr_from_be(x)?;
    let yr = fr_from_be(y)?;
    let p = Point::from_rte(xr, yr);
    if !p.is_on_curve() {
        return Err(Error::Point("not on the TE curve"));
    }
    Ok(p)
}

/// Rejection-sampled organizer secret key, uniform in `[1, L)`.
///
/// Uses 256 random bits per attempt; about 1 in 4 draws is rejected (L < 2^251).
pub fn sample_organizer_sk<R: RngCore + CryptoRng>(rng: &mut R) -> U256 {
    let l = u256_to_biguint(&SUBGROUP_ORDER);
    loop {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        b[31] &= 0x07; // L < 2^251
        let v = BigUint::from_bytes_le(&b);
        if v.bits() > 0 && v < l {
            if let Some(s) = biguint_to_u256(&v) {
                return s;
            }
        }
    }
}

/// Schnorr challenge: `keccak256(domain ‖ epoch_id ‖ aid ‖ pk_x ‖ pk_y ‖ a_x ‖ a_y) mod L`.
///
/// All coordinates are BE32 (204 bytes total).
fn organizer_challenge(
    epoch_id: &[u8; 12],
    aid: &[u8; 32],
    pk_x: &[u8; 32],
    pk_y: &[u8; 32],
    a_x: &[u8; 32],
    a_y: &[u8; 32],
) -> BigUint {
    let mut h = Keccak256::new();
    h.update(DOMAIN);
    h.update(epoch_id);
    h.update(aid);
    h.update(pk_x);
    h.update(pk_y);
    h.update(a_x);
    h.update(a_y);
    let hash = h.finalize();
    let l = u256_to_biguint(&SUBGROUP_ORDER);
    BigUint::from_bytes_be(&hash) % l
}

fn biguint_to_be32(v: &BigUint) -> [u8; 32] {
    let b = v.to_bytes_be();
    debug_assert!(b.len() <= 32, "scalar >= 2^256");
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(&b);
    out
}

/// Build an organizer proof of possession with a known witness `w`.
///
/// Used for deterministic test vectors. `sk` and `w` must both be in `[1, L)`.
/// Returns `(pk_x, pk_y, a_x, a_y, z)` as BE32, all in reduced form.
pub fn prove_organizer_with_witness(
    epoch_id: [u8; 12],
    aid: [u8; 32],
    sk: U256,
    w: U256,
) -> Result<OrganizerPoP, Error> {
    let l = u256_to_biguint(&SUBGROUP_ORDER);
    let sk_bi = u256_to_biguint(&sk);
    let w_bi = u256_to_biguint(&w);
    if sk_bi.bits() == 0 || sk_bi >= l {
        return Err(Error::Input("sk not in [1, L)".into()));
    }
    if w_bi.bits() == 0 || w_bi >= l {
        return Err(Error::Input("w not in [1, L)".into()));
    }

    let b8 = Point::generator();
    let pk = b8.mul(&sk); // PK = sk * B8 in TE form
    let a = b8.mul(&w); // A = w * B8 in TE form

    let (pk_x, pk_y) = point_to_rte(&pk);
    let (a_x, a_y) = point_to_rte(&a);

    let c = organizer_challenge(&epoch_id, &aid, &pk_x, &pk_y, &a_x, &a_y);

    // z = (w + c * sk) mod L
    let z_bi = (w_bi + c * sk_bi) % &l;
    let z = biguint_to_be32(&z_bi);

    Ok((pk_x, pk_y, a_x, a_y, z))
}

/// Build an organizer proof of possession with a fresh random witness.
///
/// `sk` must be in `[1, L)`. Returns `(pk_x, pk_y, a_x, a_y, z)` as BE32,
/// all in reduced form, ready for `DKGAppManager.registerApplication`.
pub fn prove_organizer<R: RngCore + CryptoRng>(
    epoch_id: [u8; 12],
    aid: [u8; 32],
    sk: U256,
    rng: &mut R,
) -> Result<OrganizerPoP, Error> {
    let w = sample_organizer_sk(rng);
    prove_organizer_with_witness(epoch_id, aid, sk, w)
}
