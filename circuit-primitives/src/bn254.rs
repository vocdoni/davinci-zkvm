//! BN254 curve helper operations used by the Groth16 verifier.

use crate::types::*;
use ziskos::zisklib::{
    is_on_curve_twist_bn254, is_on_subgroup_twist_bn254,
};

/// Identity element of G1 (point at infinity, all-zero encoding).
/// Matches zisklib's `G1_IDENTITY`/`G2_IDENTITY`: the pairing precompile
/// treats the all-zero encoding as 𝒪 and skips it. (The previous `(0,1)`
/// encoding was NOT treated as infinity by the precompile — a `(0,1)` point
/// would have been Miller-looped as an invalid curve point.)
pub fn g1_identity() -> G1 {
    [0u64; 8]
}

/// Identity element of G2 (point at infinity, all-zero encoding).
pub fn g2_identity() -> G2 {
    [0u64; 16]
}

/// Multiplicative identity of GT (the value 1).
pub fn gt_one() -> GT {
    let mut one = [0u64; 48];
    one[0] = 1;
    one
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
