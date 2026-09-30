//! BN254 curve helper operations used by the Groth16 verifier.

use crate::types::*;
use ziskos::zisklib::{is_on_curve_bn254, is_on_curve_twist_bn254, is_on_subgroup_twist_bn254};

/// Identity element of G1 (point at infinity, all-zero encoding).
/// Matches zisklib's `G1_IDENTITY`/`G2_IDENTITY`: the pairing precompile
/// treats the all-zero encoding as 𝒪 and skips it. A `(0,1)` encoding is
/// not treated as infinity: the precompile would Miller-loop it as an invalid
/// curve point.
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

/// Returns `true` if `p` is on the BN254 G2 curve and in the prime-order
/// subgroup. Rejects the identity: it is only used on VK points (β, γ, δ),
/// which are never 𝒪 in an honest setup, and a 𝒪 γ or δ would drop its
/// pairing term entirely (the precompile skips 𝒪 pairs), unbinding the
/// public inputs or C points. The VK-hash pin already blocks substitution;
/// this is free defense in depth.
pub fn g2_is_valid(p: &G2) -> bool {
    if *p == g2_identity() {
        return false;
    }
    is_on_curve_twist_bn254(p) && is_on_subgroup_twist_bn254(p)
}

/// Returns `true` if `p` is on the BN254 G1 curve and is not the identity.
///
/// The identity check is ours to make: zisklib's `is_on_curve_bn254` ends in
/// `eq(lhs, rhs) || eq(p, G1_IDENTITY)`, so it accepts the all-zero encoding.
/// Every G1 point we validate feeds the batch MSM, and `add_bn254` requires
/// on-curve, non-identity, canonical inputs. An identity term is also skipped
/// outright by the pairing precompile, which is exactly the degree of freedom
/// the batch random linear combination exists to remove.
///
/// No subgroup check: BN254 G1 has prime order, so on-curve implies
/// in-group.
pub fn g1_is_valid(p: &G1) -> bool {
    if *p == g1_identity() {
        return false;
    }
    is_on_curve_bn254(p)
}

/// Returns `true` if two GT elements are equal.
#[inline]
pub fn gt_eq(a: &GT, b: &GT) -> bool {
    a == b
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BN254 G2 generator (EIP-197), [xc0, xc1, yc0, yc1] LE limbs.
    const G2_GEN: G2 = [
        0x46debd5cd992f6ed,
        0x674322d4f75edadd,
        0x426a00665e5c4479,
        0x1800deef121f1e76,
        0x97e485b7aef312c2,
        0xf1aa493335a9e712,
        0x7260bfb731fb5d25,
        0x198e9393920d483a,
        0x4ce6cc0166fa7daa,
        0xe3d1e7690c43d37b,
        0x4aab71808dcb408f,
        0x12c85ea5db8c6deb,
        0x55acdadcd122975b,
        0xbc4b313370b38ef3,
        0xec9e99ad690c3395,
        0x090689d0585ff075,
    ];

    #[test]
    fn g2_valid_accepts_generator() {
        assert!(g2_is_valid(&G2_GEN));
    }

    #[test]
    fn g2_valid_rejects_identity() {
        assert!(!g2_is_valid(&g2_identity()));
    }

    #[test]
    fn g2_valid_rejects_off_curve() {
        let mut p = G2_GEN;
        p[0] ^= 1;
        assert!(!g2_is_valid(&p));
    }
}
