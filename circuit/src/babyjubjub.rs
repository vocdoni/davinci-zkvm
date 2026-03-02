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
//! via the `bn254_fr` module.  Each scalar multiplication (256-bit double-and-add)
//! does ~5,000 field operations, so the ~50x speedup from the precompile is
//! significant for batches with many voters.

use crate::bn254_fr::{self, BnFr};
use crate::poseidon::poseidon1;
use crate::types::{FrRaw, BjjCiphertext, ReencEntry, FAIL_REENC};

// ─── Curve constants ────────────────────────────────────────────────────────

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

// ─── Projective twisted Edwards point ─────────────────────────────────────

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

    /// Convert to affine: (X/Z, Y/Z).
    fn to_affine(&self) -> (BnFr, BnFr) {
        let z_inv = bn254_fr::inv(&self.z);
        (bn254_fr::mul(&self.x, &z_inv), bn254_fr::mul(&self.y, &z_inv))
    }
}

// ─── Scalar multiplication ─────────────────────────────────────────────────

/// Scalar multiply: `scalar * point` using double-and-add (LSB-first).
fn scalar_mult(point: &BJJProj, scalar: &FrRaw) -> BJJProj {
    let mut result = BJJProj::identity();
    let mut exp = point.clone();
    for i in 0..4 {
        let mut word = scalar[i];
        for _ in 0..64 {
            if (word & 1) == 1 {
                result = result.add(&exp);
            }
            exp = exp.add(&exp);
            word >>= 1;
        }
    }
    result
}

// ─── Curve membership ─────────────────────────────────────────────────────────

/// Check that `(x, y)` satisfies the BabyJubJub twisted Edwards equation:
///   `a·x² + y² = 1 + d·x²·y²`  (with a = 168700, d = 168696).
fn is_on_bjj_curve(x: &BnFr, y: &BnFr) -> bool {
    let x2 = bn254_fr::sqr(x);
    let y2 = bn254_fr::sqr(y);
    let lhs = bn254_fr::add(&bn254_fr::mul(&CURVE_A, &x2), &y2);  // a·x² + y²
    let rhs = bn254_fr::add(&bn254_fr::ONE, &bn254_fr::mul(&CURVE_D, &bn254_fr::mul(&x2, &y2))); // 1 + d·x²·y²
    lhs == rhs
}

// ─── Public API ─────────────────────────────────────────────────────────────

/// Verify that `reencrypted[i] = original[i] + encZero(k', pubKey)` for all i.
///
/// `k` is the raw re-encryption seed; `k' = poseidon1(k)` is derived inside.
/// `pub_key` is the ElGamal encryption public key point.
/// All 8 fields use the same delta since `EncryptedZero` uses the same k' for all fields.
///
/// The public key is validated to be on the BabyJubJub curve before use, preventing
/// degenerate inputs from causing silent incorrect results.
pub fn verify_reencryption(
    k: &FrRaw,
    pub_key_x: &FrRaw,
    pub_key_y: &FrRaw,
    original: &[BjjCiphertext],
    reencrypted: &[BjjCiphertext],
) -> bool {
    if original.len() != reencrypted.len() {
        return false;
    }

    // Validate public key is on the BabyJubJub curve.
    if !is_on_bjj_curve(pub_key_x, pub_key_y) {
        return false;
    }

    // k' = poseidon1(k)
    let k_prime = poseidon1(k);

    // delta1 = k' * B8
    let b8 = BJJProj::from_affine(B8X_LE, B8Y_LE);
    let delta1_proj = scalar_mult(&b8, &k_prime);

    // delta2 = k' * pubKey
    let pub_key_proj = BJJProj::from_affine(*pub_key_x, *pub_key_y);
    let delta2_proj = scalar_mult(&pub_key_proj, &k_prime);

    // For each field: newC1 = origC1 + delta1, newC2 = origC2 + delta2
    for i in 0..original.len() {
        let orig1 = BJJProj::from_affine(original[i].c1x, original[i].c1y);
        let expected1 = orig1.add(&delta1_proj);
        let (ex1, ey1) = expected1.to_affine();
        if ex1 != reencrypted[i].c1x || ey1 != reencrypted[i].c1y {
            return false;
        }

        let orig2 = BJJProj::from_affine(original[i].c2x, original[i].c2y);
        let expected2 = orig2.add(&delta2_proj);
        let (ex2, ey2) = expected2.to_affine();
        if ex2 != reencrypted[i].c2x || ey2 != reencrypted[i].c2y {
            return false;
        }
    }
    true
}

/// Verify all re-encryption entries from the ParsedInput REENCBLK.
/// Returns true if all are valid (or if the block is absent).
pub fn verify_batch_from_parsed(
    reenc_pub_key: &Option<(FrRaw, FrRaw)>,
    reenc_entries: &[ReencEntry],
    fail_mask: &mut u32,
) -> bool {
    let (pub_key_x, pub_key_y) = match reenc_pub_key {
        None => {
            *fail_mask |= crate::types::FAIL_MISSING_BLOCK;
            return false;
        }
        Some(pk) => pk,
    };
    for entry in reenc_entries {
        if !verify_reencryption(
            &entry.k,
            pub_key_x,
            pub_key_y,
            &entry.original,
            &entry.reencrypted,
        ) {
            *fail_mask |= FAIL_REENC;
            return false;
        }
    }
    true
}
