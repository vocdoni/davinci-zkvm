//! BN254 Fr (scalar field) arithmetic backed by the ZisK `arith256_mod` precompile.
//!
//! Mirrors `bls_fr.rs` but for the BN254 scalar field.  Used by Poseidon hash
//! (census proofs) and BabyJubJub curve operations (re-encryption verification).
//!
//! # Motivation
//!
//! Each BN254 Fr multiplication via `ark-ff` compiles to ~50 RISC-V instructions
//! (Montgomery form) in the Fibonacci SM table.  The ZisK `arith256_mod` precompile
//! computes `(a·b + c) mod p` in a single dedicated ArithMod row — roughly 50×
//! cheaper per operation.  For 128 voters, Poseidon + BabyJubJub generate ~1.1M
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

/// p − 2: exponent for Fermat inversion `a^(p−2) mod p`.
const PM2: [u64; 4] = [
    0x43e1f593efffffff,
    0x2833e84879b97091,
    0xb85045b68181585d,
    0x30644e72e131a029,
];

/// A BN254 Fr element in standard little-endian form.
pub type BnFr = [u64; 4];

pub const ZERO: BnFr = [0, 0, 0, 0];
pub const ONE:  BnFr = [1, 0, 0, 0];

// ─── Core primitive ──────────────────────────────────────────────────────────

/// Compute `(a · b + c) mod p` via the ZisK `arith256_mod` precompile.
///
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

// ─── Derived operations ──────────────────────────────────────────────────────

#[inline(always)]
pub fn mul(a: &BnFr, b: &BnFr) -> BnFr { muladd(a, b, &ZERO) }

#[inline(always)]
pub fn sqr(a: &BnFr) -> BnFr { mul(a, a) }

#[inline(always)]
pub fn add(a: &BnFr, b: &BnFr) -> BnFr { muladd(a, &ONE, b) }

/// `(a − b) mod p`.
#[inline]
pub fn sub(a: &BnFr, b: &BnFr) -> BnFr {
    if b == &ZERO { return *a; }
    muladd(a, &ONE, &neg(b))
}

/// `−a mod p = p − a`.  Returns `ZERO` for `a = 0`.
#[inline]
pub fn neg(a: &BnFr) -> BnFr {
    if a == &ZERO { return ZERO; }
    sub_256(&BN254_FR_MOD, a)
}

/// Fermat inversion: `a^(p−2) mod p`.
/// Returns `ZERO` when `a` is `ZERO` (caller should avoid inverting zero).
#[inline]
pub fn inv(a: &BnFr) -> BnFr {
    if a == &ZERO { return ZERO; }
    pow(a, &PM2)
}

/// Modular exponentiation `a^exp mod p` (square-and-multiply, LSB-first).
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

/// x^5 — Poseidon S-box.  3 precompile calls (sqr, sqr, mul).
#[inline]
pub fn exp5(x: &BnFr) -> BnFr {
    let x2 = sqr(x);
    let x4 = sqr(&x2);
    mul(&x4, x)
}

// ─── Conversion ──────────────────────────────────────────────────────────────

/// Reduce a raw 256-bit value modulo p.
///
/// Use for values that may be ≥ p (e.g. hash outputs interpreted as integers).
#[inline]
#[allow(dead_code)]
pub fn reduce(a: &BnFr) -> BnFr {
    muladd(a, &ONE, &ZERO)
}

/// Check if a 256-bit value is strictly less than the BN254 Fr modulus.
///
/// Compares limbs from most-significant to least-significant.
#[inline]
pub fn is_canonical(a: &BnFr) -> bool {
    for i in (0..4).rev() {
        if a[i] < BN254_FR_MOD[i] { return true; }
        if a[i] > BN254_FR_MOD[i] { return false; }
    }
    false // equal to p → not canonical
}

/// Try to interpret 32 bytes as a canonical Fr element (for Fiat-Shamir).
///
/// Reads the first 32 bytes as a little-endian `[u64; 4]`, masks the top 2 bits
/// (since BN254 Fr has 254-bit modulus), and returns `Some(value)` if the result
/// is < p and non-zero.  Returns `None` otherwise.
pub fn from_random_bytes_32(bytes: &[u8; 32]) -> Option<BnFr> {
    let mut r = [0u64; 4];
    for i in 0..4 {
        let off = i * 8;
        r[i] = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
    }
    // BN254 Fr modulus is 254 bits — mask top 2 bits for uniform sampling
    r[3] &= 0x3FFFFFFFFFFFFFFF;
    if !is_canonical(&r) || r == ZERO {
        return None;
    }
    Some(r)
}

// ─── Internal ────────────────────────────────────────────────────────────────

/// 256-bit subtraction `a − b` without modular reduction.
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
