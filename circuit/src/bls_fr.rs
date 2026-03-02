//! BLS12-381 Fr field arithmetic backed by the ZisK `arith256_mod` precompile.
//!
//! # Why this module exists
//!
//! The KZG barycentric evaluation (`kzg.rs`) performs roughly 20,000 BLS12-381 Fr
//! field multiplications (omega table generation + barycentric sum + batch inverse).
//! Using `ark-bls12-381::Fr` maps each multiplication to ~50 pure RISC-V instructions
//! in the Fibonacci SM table.  The ZisK `arith256_mod` precompile computes
//! `d = (a·b + c) mod p` in a single, dedicated ArithMod row — replacing ~50
//! Fibonacci SM rows per operation with 1 precompile row.
//!
//! # Representation
//!
//! All elements are `BlsFrRaw = [u64; 4]` in **standard (non-Montgomery)** form,
//! little-endian limbs (`r[0]` is least significant).  This matches the
//! `arith256_mod` input/output convention exactly.
//!
//! # Safety
//!
//! All inputs to arithmetic functions must be reduced (i.e. in `[0, p)`).
//! Outputs are always fully reduced.  The only exception is `from_be32_raw`, which
//! skips reduction and requires the caller to guarantee the value is already `< p`.

use ziskos::syscalls::{SyscallArith256ModParams, syscall_arith256_mod};

/// BLS12-381 Fr modulus:
///   p = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
///
/// Stored as [u64; 4] little-endian (limb[0] is least significant).
pub const BLS_FR_MOD: [u64; 4] = [
    0xffffffff00000001,
    0x53bda402fffe5bfe,
    0x3339d80809a1d805,
    0x73eda753299d7d48,
];

/// p − 2: exponent for Fermat inversion  `a^(p−2) mod p`.
const PM2: [u64; 4] = [
    0xfffffffeffffffff,
    0x53bda402fffe5bfe,
    0x3339d80809a1d805,
    0x73eda753299d7d48,
];

/// A BLS12-381 Fr element in standard little-endian form (`[u64; 4]`).
pub type BlsFrRaw = [u64; 4];

/// Additive identity.
pub const ZERO: BlsFrRaw = [0, 0, 0, 0];
/// Multiplicative identity.
pub const ONE: BlsFrRaw = [1, 0, 0, 0];

// ─── Serialization ───────────────────────────────────────────────────────────

/// Parse 32 big-endian bytes into a `BlsFrRaw` **without** reducing modulo p.
///
/// The caller must guarantee the value is already in `[0, p)`.  Suitable for
/// EIP-4844 blob cells, which are required by the spec to be valid Fr elements.
#[inline]
pub fn from_be32_raw(b: &[u8; 32]) -> BlsFrRaw {
    let mut r = [0u64; 4];
    for i in 0..4 {
        let off = (3 - i) * 8;
        r[i] = u64::from_be_bytes(b[off..off + 8].try_into().unwrap());
    }
    r
}

/// Parse 32 big-endian bytes and reduce modulo p via `arith256_mod`.
///
/// Use for SHA-256 derived inputs (e.g. evaluation point Z) that may be ≥ p.
#[inline]
pub fn from_be32_mod(b: &[u8; 32]) -> BlsFrRaw {
    let raw = from_be32_raw(b);
    // raw * 1 + 0 mod p  →  raw mod p  (arith256_mod handles values ≥ p correctly)
    muladd(&raw, &ONE, &ZERO)
}

/// Encode a `BlsFrRaw` as 32 big-endian bytes.
#[inline]
pub fn to_be32(a: &BlsFrRaw) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..(i + 1) * 8].copy_from_slice(&a[3 - i].to_be_bytes());
    }
    out
}

// ─── Core operation ──────────────────────────────────────────────────────────

/// Compute `(a · b + c) mod p` using the ZisK `arith256_mod` precompile.
///
/// This is the single primitive all other field operations are built upon.
/// One call ≈ 1 ArithMod prover row (vs ~50 Fibonacci SM rows for a software
/// Montgomery multiplication).
#[inline]
pub fn muladd(a: &BlsFrRaw, b: &BlsFrRaw, c: &BlsFrRaw) -> BlsFrRaw {
    let mut d = [0u64; 4];
    let mut params = SyscallArith256ModParams {
        a,
        b,
        c,
        module: &BLS_FR_MOD,
        d: &mut d,
    };
    syscall_arith256_mod(&mut params);
    d
}

// ─── Derived operations ───────────────────────────────────────────────────────

/// Compute `a · b mod p`.
#[inline(always)]
pub fn mul(a: &BlsFrRaw, b: &BlsFrRaw) -> BlsFrRaw {
    muladd(a, b, &ZERO)
}

/// Compute `a² mod p`.
#[inline(always)]
pub fn sqr(a: &BlsFrRaw) -> BlsFrRaw {
    mul(a, a)
}

/// Compute `(a + b) mod p` as `(a · 1 + b) mod p`.
#[inline(always)]
pub fn add(a: &BlsFrRaw, b: &BlsFrRaw) -> BlsFrRaw {
    muladd(a, &ONE, b)
}

/// Compute `(a − b) mod p = (a + (p − b)) mod p`.
#[inline]
pub fn sub(a: &BlsFrRaw, b: &BlsFrRaw) -> BlsFrRaw {
    if b == &ZERO {
        return *a;
    }
    // neg(b) = p − b (pure 256-bit subtraction, no precompile needed since p > b)
    muladd(a, &ONE, &neg(b))
}

/// Compute `−a mod p = p − a`.
///
/// Returns `ZERO` when `a` is `ZERO`.
#[inline]
pub fn neg(a: &BlsFrRaw) -> BlsFrRaw {
    if a == &ZERO {
        return ZERO;
    }
    // p − a: since 0 < a < p, no underflow.
    sub_256(&BLS_FR_MOD, a)
}

/// Compute `a^(−1) mod p` using Fermat's little theorem: `a^(p−2) mod p`.
///
/// Returns `ZERO` when `a` is `ZERO` (caller should avoid inverting zero).
/// Cost: ~383 `arith256_mod` calls (255 squarings + ~128 multiplications).
#[inline]
pub fn inv(a: &BlsFrRaw) -> BlsFrRaw {
    if a == &ZERO {
        return ZERO;
    }
    pow(a, &PM2)
}

/// Modular exponentiation `a^exp mod p`, square-and-multiply (LSB-first).
///
/// Uses ~256 squarings and up to ~128 extra multiplications.
pub fn pow(a: &BlsFrRaw, exp: &[u64; 4]) -> BlsFrRaw {
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

// ─── Internal helpers ─────────────────────────────────────────────────────────

/// 256-bit subtraction `a − b` without modular reduction.
///
/// Precondition: `a ≥ b` (no underflow).
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
