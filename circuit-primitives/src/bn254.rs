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

/// BN254 base field modulus q as [u64; 4] little-endian.
pub const BN254_FQ_MODULUS: [u64; 4] = [
    0x3c208c16d87cfd47,
    0x97816a916871ca8d,
    0xb85045b68181585d,
    0x30644e72e131a029,
];

/// Returns `true` if the 4-limb LE value `x` is below q.
pub fn fq_is_canonical(x: &[u64]) -> bool {
    for i in (0..4).rev() {
        if x[i] != BN254_FQ_MODULUS[i] {
            return x[i] < BN254_FQ_MODULUS[i];
        }
    }
    false
}

/// Returns `true` if every coordinate of `p` is canonical, `p` is on the
/// BN254 G2 twist and in the prime-order subgroup, and is not the identity.
///
/// Used on the VK's β, γ, δ and on every proof's B. The batch randomises the
/// G1 slot of each pairing, which is sound only when B is in G2: otherwise
/// `e(r·A, B)` is no power of a fixed `e(A, B)`. A 𝒪 B, γ or δ would drop its
/// pairing term (the precompile skips 𝒪 pairs). The bound comes first: the
/// transcript hashes the raw limbs, and the Fq2 precompiles abort on a limb
/// at or above q.
pub fn g2_is_valid(p: &G2) -> bool {
    if !(0..4).all(|i| fq_is_canonical(&p[4 * i..4 * i + 4])) || *p == g2_identity() {
        return false;
    }
    is_on_curve_twist_bn254(p) && is_on_subgroup_twist_bn254(p)
}

/// Returns `true` if both coordinates of `p` are canonical and `p` is on the
/// BN254 G1 curve and is not the identity.
///
/// The bound comes first: zisklib's curve check reduces its input, while the
/// transcript hashes the raw limbs, so `x + q` would be a second encoding of
/// the same point. The identity check is ours to make too: zisklib's
/// `is_on_curve_bn254` ends in `eq(lhs, rhs) || eq(p, G1_IDENTITY)`, so it
/// accepts the all-zero encoding. Every G1 point we validate feeds the batch
/// MSM, and `add_bn254` requires on-curve, non-identity, canonical inputs. An
/// identity term is also skipped outright by the pairing precompile, which is
/// exactly the degree of freedom the batch random linear combination exists
/// to remove.
///
/// No subgroup check: BN254 G1 has prime order, so on-curve implies
/// in-group.
pub fn g1_is_valid(p: &G1) -> bool {
    if !fq_is_canonical(&p[0..4]) || !fq_is_canonical(&p[4..8]) || *p == g1_identity() {
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

    /// `v + q` as LE limbs (no carry out for the values used here).
    fn plus_q(v: &[u64]) -> [u64; 4] {
        let mut out = [0u64; 4];
        let mut carry = 0u128;
        for i in 0..4 {
            let s = v[i] as u128 + BN254_FQ_MODULUS[i] as u128 + carry;
            out[i] = s as u64;
            carry = s >> 64;
        }
        assert_eq!(carry, 0);
        out
    }

    #[test]
    fn fq_bound() {
        assert!(fq_is_canonical(&[0, 0, 0, 0]));
        let mut below = BN254_FQ_MODULUS;
        below[0] -= 1;
        assert!(fq_is_canonical(&below));
        assert!(!fq_is_canonical(&BN254_FQ_MODULUS));
        assert!(!fq_is_canonical(&[u64::MAX; 4]));
    }

    #[test]
    fn non_canonical_coordinates_rejected() {
        // G1 generator (1, 2), and the same point with x + q.
        let g1: G1 = [1, 0, 0, 0, 2, 0, 0, 0];
        assert!(g1_is_valid(&g1));
        let mut alias = g1;
        alias[0..4].copy_from_slice(&plus_q(&g1[0..4]));
        assert!(!g1_is_valid(&alias));
        for c in 0..4 {
            let mut alias = G2_GEN;
            alias[4 * c..4 * c + 4].copy_from_slice(&plus_q(&G2_GEN[4 * c..4 * c + 4]));
            assert!(!g2_is_valid(&alias), "coordinate {c}");
        }
    }
}
