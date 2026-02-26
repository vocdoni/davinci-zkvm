//! BN254 curve helper operations used by the Groth16 verifier.

use crate::types::*;
use ziskos::zisklib::{
    is_on_curve_bn254, is_on_curve_twist_bn254, is_on_subgroup_twist_bn254,
};

/// Identity element of G1 (point at infinity in homogeneous coordinates).
pub fn g1_identity() -> G1 {
    let mut id = [0u64; 8];
    id[4] = 1;
    id
}

/// Identity element of G2 (point at infinity in homogeneous coordinates).
pub fn g2_identity() -> G2 {
    let mut id = [0u64; 16];
    id[8] = 1;
    id
}

/// Multiplicative identity of GT (the value 1).
pub fn gt_one() -> GT {
    let mut one = [0u64; 48];
    one[0] = 1;
    one
}

/// Returns `true` if `p` is on the BN254 G1 curve or is the point at infinity.
pub fn g1_is_valid(p: &G1) -> bool {
    if *p == g1_identity() { true } else { is_on_curve_bn254(p) }
}

/// Returns `true` if `p` is on the BN254 G2 curve and in the prime-order subgroup.
pub fn g2_is_valid(p: &G2) -> bool {
    if *p == g2_identity() {
        true
    } else {
        is_on_curve_twist_bn254(p) && is_on_subgroup_twist_bn254(p)
    }
}

/// Returns `true` if two GT elements are equal.
#[inline]
pub fn gt_eq(a: &GT, b: &GT) -> bool { a == b }

/// Returns `true` if two BN254 scalar field elements are equal.
#[inline]
pub fn fr_eq(a: &FrRaw, b: &FrRaw) -> bool { a == b }
