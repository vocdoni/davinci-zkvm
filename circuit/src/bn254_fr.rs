//! BN254 Fr (scalar field) arithmetic backed by the ZisK `arith256_mod` precompile.
//!
//! Mirrors `bls_fr.rs` but for the BN254 scalar field.  Used by Poseidon hash
//! (census proofs) and auxiliary BN254 field arithmetic used by the guest.
//!
//! # Motivation
//!
//! Each BN254 Fr multiplication via `ark-ff` compiles to ~50 RISC-V instructions
//! (Montgomery form) in the Fibonacci SM table.  The ZisK `arith256_mod` precompile
// ! computes `(a*b + c) mod p` in a single dedicated ArithMod row => roughly 50×
//! cheaper per operation.  For large batches, the remaining SHA-256/field-heavy paths generate substantial
//! field multiplications; this module reduces prover cost by replacing all of
//! them with single-row precompile calls.
//!
//! # Representation
//!
//! All elements are `BnFr = [u64; 4]` in **standard (non-Montgomery)** little-endian
//! form, matching the `arith256_mod` input/output convention.  This is the same
//! representation used by `types::FrRaw`.

use ziskos::syscalls::{SyscallArith256ModParams, syscall_arith256_mod};

/// BN254 scalar field modulus (Fr):
///   p = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
pub const BN254_FR_MOD: [u64; 4] = [
    0x43e1f593f0000001,
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

/// x^5 => Poseidon S-box.  3 precompile calls (sqr, sqr, mul).
#[inline]
pub fn exp5(x: &BnFr) -> BnFr {
    let x2 = sqr(x);
    let x4 = sqr(&x2);
    mul(&x4, x)
}

// Conversion

/// Reduce a raw 256-bit value modulo p.
/// Use for values that may be ≥ p (e.g. hash outputs interpreted as integers).
#[inline]
#[allow(dead_code)]
pub fn reduce(a: &BnFr) -> BnFr {
    muladd(a, &ONE, &ZERO)
}
