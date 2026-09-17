//! BN254 Fr (scalar field) arithmetic backed by the ZisK `arith256_mod` precompile.
//!
//! Mirrors `bls_fr.rs` but for the BN254 scalar field.  Used by Poseidon hash
//! (census proofs) and BabyJubJub curve operations (re-encryption verification).
//!
//! # Motivation
//!
//! Each BN254 Fr multiplication via `ark-ff` compiles to ~50 RISC-V instructions
//! (Montgomery form) in the Fibonacci SM table.  The ZisK `arith256_mod` precompile
//! computes `(a*b + c) mod p` in a single dedicated ArithMod row => roughly 50×
//! cheaper per operation.  For 128 voters, Poseidon + BabyJubJub generate ~1.1M
//! field multiplications; this module reduces prover cost by replacing all of
//! them with single-row precompile calls.
//!
//! # Representation
//!
//! All elements are `BnFr = [u64; 4]` in **standard (non-Montgomery)** little-endian
//! form, matching the `arith256_mod` input/output convention.  This is the same
//! representation used by `types::FrRaw`.

use ziskos::syscalls::{syscall_arith256_mod, SyscallArith256ModParams};
use ziskos::zisklib::fcall_uint256_inv_mod;

/// BN254 scalar field modulus (Fr):
///   p = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
pub const BN254_FR_MOD: [u64; 4] = [
    0x43e1f593f0000001,
    0x2833e84879b97091,
    0xb85045b68181585d,
    0x30644e72e131a029,
];

/// p - 2: exponent for the legacy Fermat inversion `a^(p-2) mod p`.
/// Retained for reference; `inv()` now uses `fcall_uint256_inv_mod` instead.
#[allow(dead_code)]
const PM2: [u64; 4] = [
    0x43e1f593efffffff,
    0x2833e84879b97091,
    0xb85045b68181585d,
    0x30644e72e131a029,
];

/// A BN254 Fr element in standard little-endian form.
pub type BnFr = [u64; 4];

pub const ZERO: BnFr = [0, 0, 0, 0];
pub const ONE: BnFr = [1, 0, 0, 0];

// Core primitive

/// Compute `(a * b + c) mod p` via the ZisK `arith256_mod` precompile.
/// One call ≈ 1 ArithMod prover row (vs ~50 Fibonacci SM rows for software
/// Montgomery multiplication).
#[inline]
pub fn muladd(a: &BnFr, b: &BnFr, c: &BnFr) -> BnFr {
    let mut d = [0u64; 4];
    let mut params = SyscallArith256ModParams {
        a,
        b,
        c,
        module: &BN254_FR_MOD,
        d: &mut d,
    };
    syscall_arith256_mod(&mut params);
    d
}

// Derived operations

#[inline(always)]
pub fn mul(a: &BnFr, b: &BnFr) -> BnFr {
    muladd(a, b, &ZERO)
}

#[inline(always)]
pub fn sqr(a: &BnFr) -> BnFr {
    mul(a, a)
}

#[inline(always)]
pub fn add(a: &BnFr, b: &BnFr) -> BnFr {
    muladd(a, &ONE, b)
}

/// `(a - b) mod p`.
#[inline]
pub fn sub(a: &BnFr, b: &BnFr) -> BnFr {
    if b == &ZERO {
        return *a;
    }
    muladd(a, &ONE, &neg(b))
}

/// `-a mod p = p - a`.  Returns `ZERO` for `a = 0`.
/// The input is reduced first: attacker-controlled FrRaw may be non-canonical
/// (≥ p), and `sub_256` underflows on such input, silently producing the wrong
/// group element downstream (e.g. in the results-accumulator subtraction).
#[inline]
pub fn neg(a: &BnFr) -> BnFr {
    let a = reduce(a);
    if a == ZERO {
        return ZERO;
    }
    sub_256(&BN254_FR_MOD, &a)
}

/// Compute `a^(-1) mod p`.
///
/// # Implementation (optimized)
///
/// Uses `fcall_uint256_inv_mod` — a ZisK *free-input call* (fcall) that reads
/// the inverse as an unverified hint from the prover. Because fcalls are not
/// constrained by the ZisK VM, the result is **verified** with a single checked
/// `arith256_mod` syscall: `a * result ≡ 1 (mod p)`. If the hint is wrong (e.g.
/// a malicious prover), the check fails and `ZERO` is returned, which propagates
/// as a verification failure downstream — no unsoundness.
///
/// This replaces the legacy Fermat `a^(p-2) mod p` (~383 `arith256_mod` syscalls)
/// with **1 fcall hint + 1 checked multiply**.
///
/// Returns `ZERO` when `a` is `ZERO`.
#[inline]
pub fn inv(a: &BnFr) -> BnFr {
    if a == &ZERO {
        return ZERO;
    }
    match fcall_uint256_inv_mod(a, &BN254_FR_MOD) {
        Some(result) if muladd(a, &result, &ZERO) == ONE => result,
        _ => ZERO,
    }
}

/// Modular exponentiation `a^exp mod p` (square-and-multiply, LSB-first).
/// Retained for reference; `inv()` now uses `fcall_uint256_inv_mod`.
#[allow(dead_code)]
pub fn pow(a: &BnFr, exp: &[u64; 4]) -> BnFr {
    let mut result = ONE;
    let mut base = *a;
    for i in 0..4 {
        let mut word = exp[i];
        for _ in 0..64 {
            if word & 1 == 1 {
                result = mul(&result, &base);
            }
            base = sqr(&base);
            word >>= 1;
        }
    }
    result
}

/// x^5 => Poseidon S-box.  3 precompile calls (sqr, sqr, mul).
#[inline]
pub fn exp5(x: &BnFr) -> BnFr {
    let x2 = sqr(x);
    let x4 = sqr(&x2);
    mul(&x4, x)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neg_matches_reference() {
        for v in [
            [0u64, 0, 0, 0],
            [1, 0, 0, 0],
            [0xDEADBEEF, 0x12345, 0xFFF, 0x1],
            BN254_FR_MOD,
        ] {
            let a = reduce(&v);
            let expected = if a == ZERO {
                ZERO
            } else {
                sub_256(&BN254_FR_MOD, &a)
            };
            assert_eq!(neg(&v), expected);
        }
    }

    #[test]
    fn neg_reduces_noncanonical_input() {
        // p + 5 (non-canonical encoding of 5) must negate like 5: neg = p - 5.
        let mut nc = BN254_FR_MOD;
        nc[0] += 5;
        let expected = sub_256(&BN254_FR_MOD, &[5, 0, 0, 0]);
        assert_eq!(neg(&nc), expected);
        // 2^256 - 1 (worst-case non-canonical) must not underflow.
        let max = [u64::MAX; 4];
        let r = reduce(&max);
        let expected = if r == ZERO {
            ZERO
        } else {
            sub_256(&BN254_FR_MOD, &r)
        };
        assert_eq!(neg(&max), expected);
    }

    #[test]
    fn sub_tolerates_noncanonical_rhs() {
        let a = [7u64, 0, 0, 0];
        let mut b = BN254_FR_MOD;
        b[0] += 3; // non-canonical encoding of 3
        assert_eq!(sub(&a, &b), [4, 0, 0, 0]);
    }
}

// Conversion

/// Reduce a raw 256-bit value modulo p.
/// Use for values that may be ≥ p (e.g. hash outputs interpreted as integers).
#[inline]
pub fn reduce(a: &BnFr) -> BnFr {
    muladd(a, &ONE, &ZERO)
}

/// 256-bit subtraction `a - b` without modular reduction.
/// Precondition: `a ≥ b`.
fn sub_256(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let (r0, borrow0) = a[0].overflowing_sub(b[0]);
    let (r1, borrow1a) = a[1].overflowing_sub(b[1]);
    let (r1, borrow1b) = r1.overflowing_sub(borrow0 as u64);
    let borrow1 = borrow1a || borrow1b;
    let (r2, borrow2a) = a[2].overflowing_sub(b[2]);
    let (r2, borrow2b) = r2.overflowing_sub(borrow1 as u64);
    let borrow2 = borrow2a || borrow2b;
    let (r3, _) = a[3].overflowing_sub(b[3]);
    let (r3, _) = r3.overflowing_sub(borrow2 as u64);
    [r0, r1, r2, r3]
}
