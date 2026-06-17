//! BabyJubJub elliptic curve operations over BN254 Fr.
//!
//! Twisted Edwards: `a*x^2 + y^2 = 1 + d*x^2*y^2`
//! Constants (iden3 standard): `a = 168700`, `d = 168696`
//!
//! Generator B8 (= 8 * base point, iden3 standard):
//!   Bx = 5299619240641551281634865583518297030282874472190772894086521144482721001553
//!   By = 16950150798460657717958625567821834550301663161624707787222815936182638968203
//!
//! ## Re-encryption verification
//!
//! `reencryptionK = poseidon1(k)`
//! For each field i: `newC1[i] = origC1[i] + k'*B8`, `newC2[i] = origC2[i] + k'*pubKey`
//!
//! Since all 8 fields use the same k', only 2 scalar multiplications are needed per voter.
//!
//! ## Hardware acceleration
//!
//! All BN254 Fr field operations are backed by the ZisK `arith256_mod` precompile
//! via the `bn254_fr` module.  Re-encryption scalar muls use 4-bit fixed-base
//! window tables (built once per batch for B8 and the election public key),
//! cutting each 256-bit mul from ~384 point ops to at most 63 additions.

use crate::bn254_fr::{self, BnFr};
use crate::poseidon::poseidon1;
use crate::types::{FrRaw, BjjCiphertext, ReencEntry, FAIL_REENC};

// Curve constants

/// a = 168700 as BN254 Fr element.
const CURVE_A: BnFr = [168700, 0, 0, 0];

/// d = 168696 as BN254 Fr element.
const CURVE_D: BnFr = [168696, 0, 0, 0];

/// B8 generator x = 5299619240641551281634865583518297030282874472190772894086521144482721001553
const B8X_LE: FrRaw = [
    0x2893f3f6bb957051,
    0x2ab8d8010534e0b6,
    0x4eacb2e09d6277c1,
    0x0bb77a6ad63e739b,
];
/// B8 generator y = 16950150798460657717958625567821834550301663161624707787222815936182638968203
const B8Y_LE: FrRaw = [
    0x4b3c257a872d7d8b,
    0xfce0051fb9e13377,
    0x25572e1cd16bf9ed,
    0x25797203f7a0b249,
];

// Projective twisted Edwards point

/// BabyJubJub point in projective coordinates (X:Y:Z).
/// Affine: (X/Z, Y/Z).  Identity: (0:1:1).
#[derive(Clone)]
struct BJJProj {
    x: BnFr,
    y: BnFr,
    z: BnFr,
}

impl BJJProj {
    fn identity() -> Self {
        BJJProj { x: bn254_fr::ZERO, y: bn254_fr::ONE, z: bn254_fr::ONE }
    }

    #[allow(dead_code)]
    fn is_identity(&self) -> bool {
        self.x == bn254_fr::ZERO
    }

    fn from_affine(ax: BnFr, ay: BnFr) -> Self {
        BJJProj { x: ax, y: ay, z: bn254_fr::ONE }
    }

    /// Projective twisted Edwards addition (add-2008-bbjlp formula).
    /// https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html#addition-add-2008-bbjlp
    fn add(&self, o: &BJJProj) -> BJJProj {
        let aa = bn254_fr::mul(&self.z, &o.z);             // A = Z1*Z2
        let b  = bn254_fr::sqr(&aa);                       // B = A^2
        let c  = bn254_fr::mul(&self.x, &o.x);             // C = X1*X2
        let d  = bn254_fr::mul(&self.y, &o.y);             // D = Y1*Y2
        let e  = bn254_fr::mul(&CURVE_D, &bn254_fr::mul(&c, &d)); // E = d*C*D
        let f  = bn254_fr::sub(&b, &e);                    // F = B - E
        let g  = bn254_fr::add(&b, &e);                    // G = B + E
        let x1y1 = bn254_fr::add(&self.x, &self.y);
        let x2y2 = bn254_fr::add(&o.x, &o.y);
        let mut h = bn254_fr::mul(&x1y1, &x2y2);           // (X1+Y1)*(X2+Y2)
        h = bn254_fr::sub(&h, &c);
        h = bn254_fr::sub(&h, &d);                          // h = (X1+Y1)*(X2+Y2) - C - D
        let x3 = bn254_fr::mul(&aa, &bn254_fr::mul(&f, &h));  // X3 = A*F*h
        let ac = bn254_fr::mul(&CURVE_A, &c);
        let y3 = bn254_fr::mul(&aa, &bn254_fr::mul(&g, &bn254_fr::sub(&d, &ac))); // Y3 = A*G*(D-a*C)
        let z3 = bn254_fr::mul(&f, &g);                    // Z3 = F*G
        BJJProj { x: x3, y: y3, z: z3 }
    }

    /// Projective twisted Edwards doubling (dbl-2008-bbjlp formula).
    /// Cheaper than `add(self, self)`: ~14 field ops vs ~19.
    /// https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html#doubling-dbl-2008-bbjlp
    fn dbl(&self) -> BJJProj {
        let b = bn254_fr::sqr(&bn254_fr::add(&self.x, &self.y)); // B = (X1+Y1)^2
        let c = bn254_fr::sqr(&self.x);                          // C = X1^2
        let d = bn254_fr::sqr(&self.y);                          // D = Y1^2
        let e = bn254_fr::mul(&CURVE_A, &c);                     // E = a*C
        let f = bn254_fr::add(&e, &d);                           // F = E + D
        let h = bn254_fr::sqr(&self.z);                          // H = Z1^2
        let j = bn254_fr::sub(&f, &bn254_fr::add(&h, &h));       // J = F - 2H
        let bcd = bn254_fr::sub(&bn254_fr::sub(&b, &c), &d);
        let x3 = bn254_fr::mul(&bcd, &j);                        // X3 = (B-C-D)*J
        let y3 = bn254_fr::mul(&f, &bn254_fr::sub(&e, &d));      // Y3 = F*(E-D)
        let z3 = bn254_fr::mul(&f, &j);                          // Z3 = F*J
        BJJProj { x: x3, y: y3, z: z3 }
    }

    /// Convert to affine: (X/Z, Y/Z).
    fn to_affine(&self) -> (BnFr, BnFr) {
        let z_inv = bn254_fr::inv(&self.z);
        (bn254_fr::mul(&self.x, &z_inv), bn254_fr::mul(&self.y, &z_inv))
    }

    /// Projective equality against an affine point: `(X/Z, Y/Z) == (ax, ay)`,
    /// checked as `X == ax*Z && Y == ay*Z`. Avoids the field inversion in
    /// `to_affine`. Valid curve points have Z != 0, so this is exact.
    fn eq_affine(&self, ax: &BnFr, ay: &BnFr) -> bool {
        bn254_fr::mul(ax, &self.z) == self.x && bn254_fr::mul(ay, &self.z) == self.y
    }
}

// Scalar multiplication

/// Scalar multiply: `scalar * point` using double-and-add (LSB-first),
/// stopping at the highest set bit (small scalars like CP's `msg` cost
/// proportionally less).
fn scalar_mult(point: &BJJProj, scalar: &FrRaw) -> BJJProj {
    let top = match (0..4).rev().find(|&i| scalar[i] != 0) {
        None => return BJJProj::identity(),
        Some(t) => t,
    };
    let mut result = BJJProj::identity();
    let mut exp = point.clone();
    for i in 0..=top {
        let mut word = scalar[i];
        let bits = if i == top { 64 - word.leading_zeros() } else { 64 };
        for _ in 0..bits {
            if (word & 1) == 1 {
                result = result.add(&exp);
            }
            exp = exp.dbl();
            word >>= 1;
        }
    }
    result
}

/// Precomputed 4-bit window table for a fixed base point.
///
/// `windows[w][v-1] = (v << 4w) * P` for w in 0..64, v in 1..=15, so a
/// 256-bit scalar mul is at most 63 point additions (zero nibbles skipped)
/// with no doublings.  Building the table costs ~960 adds + 256 dbls, paid
/// once per batch; each re-encryption entry then saves ~2x256 dbls + adds,
/// so it amortizes after ~2 entries.
struct BjjFixedBase {
    windows: Vec<[BJJProj; 15]>,
}

impl BjjFixedBase {
    fn new(x: &FrRaw, y: &FrRaw) -> Self {
        let mut windows = Vec::with_capacity(64);
        let mut base = BJJProj::from_affine(*x, *y);
        for _ in 0..64 {
            let mut acc = BJJProj::identity();
            let entries: [BJJProj; 15] = core::array::from_fn(|_| {
                acc = acc.add(&base);
                acc.clone()
            });
            windows.push(entries);
            base = base.dbl().dbl().dbl().dbl();
        }
        BjjFixedBase { windows }
    }

    fn mul(&self, scalar: &FrRaw) -> BJJProj {
        let mut result = BJJProj::identity();
        for i in 0..4 {
            let mut word = scalar[i];
            for j in 0..16 {
                let nib = (word & 0xF) as usize;
                if nib != 0 {
                    result = result.add(&self.windows[i * 16 + j][nib - 1]);
                }
                word >>= 4;
            }
        }
        result
    }
}

// Curve membership

/// Check that `(x, y)` satisfies the BabyJubJub twisted Edwards equation:
///   `a*x² + y² = 1 + d*x²*y²`  (with a = 168700, d = 168696).
fn is_on_bjj_curve(x: &BnFr, y: &BnFr) -> bool {
    let x2 = bn254_fr::sqr(x);
    let y2 = bn254_fr::sqr(y);
    let lhs = bn254_fr::add(&bn254_fr::mul(&CURVE_A, &x2), &y2);  // a*x² + y²
    let rhs = bn254_fr::add(&bn254_fr::ONE, &bn254_fr::mul(&CURVE_D, &bn254_fr::mul(&x2, &y2))); // 1 + d*x²*y²
    lhs == rhs
}

// Public API

/// Verify that `reencrypted[i] = original[i] + encZero(k_i, pubKey)` for all
/// active fields, where each field uses a *distinct* scalar chained through
/// Poseidon: `k_0 = poseidon1(k)`, `k_{i+1} = poseidon1(k_i)`. This matches
/// davinci-node `Ballot.Reencrypt`/`EncryptedZero`, which advances the offset
/// scalar once per field. `k` is the raw re-encryption seed.
/// Padded fields `i >= num_fields` carry the TE identity on both sides and are
/// asserted (cheap field compares) rather than re-encrypted, so their per-field
/// scalar mults are skipped entirely.
/// `b8_table` / `pk_table` are the fixed-base window tables for B8 and the
/// (already curve-validated) ElGamal public key.
fn verify_reencryption(
    k: &FrRaw,
    b8_table: &BjjFixedBase,
    pk_table: &BjjFixedBase,
    num_fields: usize,
    original: &[BjjCiphertext],
    reencrypted: &[BjjCiphertext],
) -> bool {
    if original.len() != reencrypted.len() {
        return false;
    }

    // Per-field offset scalar, chained through Poseidon. k_0 = poseidon1(k).
    let mut k_i = poseidon1(k);

    // For each active field: delta1_i = k_i * B8, delta2_i = k_i * pubKey, then
    // newC1 = origC1 + delta1_i, newC2 = origC2 + delta2_i. Compare the expected
    // projective point against the claimed affine one by cross-multiplication,
    // skipping the per-point field inversion. Advance k_i once per field.
    for i in 0..original.len() {
        if i >= num_fields {
            // Padded slot: assert identity on both sides, skip EC work.
            let o = &original[i];
            let r = &reencrypted[i];
            if o.c1x != bn254_fr::ZERO || o.c1y != bn254_fr::ONE
                || o.c2x != bn254_fr::ZERO || o.c2y != bn254_fr::ONE
                || r.c1x != bn254_fr::ZERO || r.c1y != bn254_fr::ONE
                || r.c2x != bn254_fr::ZERO || r.c2y != bn254_fr::ONE {
                return false;
            }
            continue;
        }
        let delta1_proj = b8_table.mul(&k_i);
        let delta2_proj = pk_table.mul(&k_i);

        let orig1 = BJJProj::from_affine(original[i].c1x, original[i].c1y);
        let expected1 = orig1.add(&delta1_proj);
        if !expected1.eq_affine(&reencrypted[i].c1x, &reencrypted[i].c1y) {
            return false;
        }

        let orig2 = BJJProj::from_affine(original[i].c2x, original[i].c2y);
        let expected2 = orig2.add(&delta2_proj);
        if !expected2.eq_affine(&reencrypted[i].c2x, &reencrypted[i].c2y) {
            return false;
        }

        // Advance the offset scalar for the next field.
        k_i = poseidon1(&k_i);
    }
    true
}

/// Verify all re-encryption entries from the ParsedInput REENCBLK.
/// Returns true if all are valid (or if the block is absent).
/// The public key is curve-checked once and the fixed-base window tables
/// for B8 and the public key are built once, shared by all entries.
pub fn verify_batch_from_parsed(
    reenc_pub_key: &Option<(FrRaw, FrRaw)>,
    reenc_entries: &[ReencEntry],
    num_fields: usize,
    fail_mask: &mut u32,
) -> bool {
    let (pub_key_x, pub_key_y) = match reenc_pub_key {
        None => {
            *fail_mask |= crate::types::FAIL_MISSING_BLOCK;
            return false;
        }
        Some(pk) => pk,
    };
    // No entries: nothing to re-encrypt, so skip the fixed-base table build.
    if reenc_entries.is_empty() {
        return true;
    }
    if !is_on_bjj_curve(pub_key_x, pub_key_y) {
        *fail_mask |= FAIL_REENC;
        return false;
    }
    let b8_table = BjjFixedBase::new(&B8X_LE, &B8Y_LE);
    let pk_table = BjjFixedBase::new(pub_key_x, pub_key_y);
    for entry in reenc_entries {
        if !verify_reencryption(
            &entry.k,
            &b8_table,
            &pk_table,
            num_fields,
            &entry.original,
            &entry.reencrypted,
        ) {
            *fail_mask |= FAIL_REENC;
            return false;
        }
    }
    true
}

// Affine point API (TE coordinates) for the Chaum-Pedersen verifier.

/// Affine BabyJubJub point in standard Twisted Edwards coordinates.
pub type BjjAffine = (FrRaw, FrRaw);

/// The identity point (0, 1).
pub fn bjj_identity() -> BjjAffine {
    (bn254_fr::ZERO, bn254_fr::ONE)
}

/// The iden3 generator B8.
pub fn bjj_generator() -> BjjAffine {
    (B8X_LE, B8Y_LE)
}

/// `a + b` in affine TE coordinates.
pub fn bjj_add(a: &BjjAffine, b: &BjjAffine) -> BjjAffine {
    BJJProj::from_affine(a.0, a.1).add(&BJJProj::from_affine(b.0, b.1)).to_affine()
}

/// `scalar * p`, scalar as raw 256-bit LE limbs (not reduced).
pub fn bjj_mul(p: &BjjAffine, scalar: &FrRaw) -> BjjAffine {
    scalar_mult(&BJJProj::from_affine(p.0, p.1), scalar).to_affine()
}

/// `-p` = (-x, y) in twisted Edwards form.
pub fn bjj_neg(p: &BjjAffine) -> BjjAffine {
    (bn254_fr::neg(&p.0), p.1)
}

/// Running point sum kept in projective coordinates, so a chain of N
/// additions costs one field inversion total (in `finish`) instead of
/// one per addition.
pub struct BjjAccumulator(BJJProj);

impl BjjAccumulator {
    pub fn new(p: &BjjAffine) -> Self {
        BjjAccumulator(BJJProj::from_affine(p.0, p.1))
    }

    pub fn add(&mut self, p: &BjjAffine) {
        self.0 = self.0.add(&BJJProj::from_affine(p.0, p.1));
    }

    /// Homomorphic subtraction: add the group inverse `(-x, y)`. One
    /// projective add, no field inversion until `finish`.
    pub fn sub(&mut self, p: &BjjAffine) {
        let n = bjj_neg(p);
        self.0 = self.0.add(&BJJProj::from_affine(n.0, n.1));
    }

    pub fn finish(&self) -> BjjAffine {
        self.0.to_affine()
    }
}

/// Curve membership check for an affine TE point.
pub fn bjj_on_curve(p: &BjjAffine) -> bool {
    is_on_bjj_curve(&p.0, &p.1)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCALARS: [[u64; 4]; 4] = [
        [1, 0, 0, 0],
        [0xF0F0F0F0F0F0F0F0, 0x0123456789ABCDEF, 0xFFFFFFFFFFFFFFFF, 0x0000000000000001],
        [0xDEADBEEFCAFEBABE, 0, 0x8000000000000000, 0x00FFFFFFFFFFFFFF],
        [0, 0, 0, 0],
    ];

    #[test]
    fn dbl_matches_add_self() {
        let p = BJJProj::from_affine(B8X_LE, B8Y_LE);
        let q = p.add(&p).add(&p); // odd multiple, generic point
        assert_eq!(q.dbl().to_affine(), q.add(&q).to_affine());
    }

    #[test]
    fn fixed_base_matches_double_and_add() {
        let table = BjjFixedBase::new(&B8X_LE, &B8Y_LE);
        let b8 = BJJProj::from_affine(B8X_LE, B8Y_LE);
        for s in &SCALARS {
            assert_eq!(table.mul(s).to_affine(), scalar_mult(&b8, s).to_affine());
        }
    }

    #[test]
    fn eq_affine_matches_to_affine() {
        let b8 = BJJProj::from_affine(B8X_LE, B8Y_LE);
        for s in &SCALARS {
            let p = scalar_mult(&b8, s); // non-trivial Z != 1
            let (ax, ay) = p.to_affine();
            assert!(p.eq_affine(&ax, &ay));
            // A wrong affine coordinate must be rejected.
            let bad = bn254_fr::add(&ax, &bn254_fr::ONE);
            assert!(!p.eq_affine(&bad, &ay));
        }
    }
}
