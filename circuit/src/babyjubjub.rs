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

use ark_bn254::Fr;
use ark_ff::{BigInteger256, Field, PrimeField, Zero};
use crate::poseidon::poseidon1;
use crate::types::{FrRaw, BjjCiphertext, ReencEntry, FAIL_REENC};

// ─── Fr helpers ────────────────────────────────────────────────────────────

fn raw_to_fr(r: &FrRaw) -> Fr {
    Fr::from_bigint(BigInteger256::new(*r)).unwrap_or(Fr::ZERO)
}

fn fr_to_raw(f: Fr) -> FrRaw {
    f.into_bigint().0
}

// ─── Curve constants ────────────────────────────────────────────────────────

// a = 168700 as Fr
fn curve_a() -> Fr {
    Fr::from(168700u64)
}

// d = 168696 as Fr
fn curve_d() -> Fr {
    Fr::from(168696u64)
}

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

/// A BabyJubJub point in projective coordinates (X:Y:Z).
/// Affine: (X/Z, Y/Z).
/// Identity: (0:1:1).
#[derive(Clone)]
struct BJJProj {
    x: Fr,
    y: Fr,
    z: Fr,
}

impl BJJProj {
    fn identity() -> Self {
        BJJProj { x: Fr::ZERO, y: Fr::from(1u64), z: Fr::from(1u64) }
    }

    fn is_identity(&self) -> bool {
        self.x.is_zero()
    }

    fn from_affine(ax: Fr, ay: Fr) -> Self {
        BJJProj { x: ax, y: ay, z: Fr::from(1u64) }
    }

    /// add-2008-bbjlp projective twisted Edwards addition.
    /// https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html#addition-add-2008-bbjlp
    fn add(&self, o: &BJJProj) -> BJJProj {
        let a_val = curve_a();
        let d_val = curve_d();

        let aa = self.z * o.z;             // A = Z1*Z2
        let b = aa.square();               // B = A^2
        let c = self.x * o.x;             // C = X1*X2
        let d = self.y * o.y;             // D = Y1*Y2
        let e = d_val * c * d;            // E = d*C*D
        let f = b - e;                    // F = B - E
        let g = b + e;                    // G = B + E
        let x1y1 = self.x + self.y;
        let x2y2 = o.x + o.y;
        let mut x3 = x1y1 * x2y2;
        x3 -= c;
        x3 -= d;
        x3 = aa * f * x3;                 // X3 = A*F*((X1+Y1)*(X2+Y2)-C-D)
        let ac = a_val * c;
        let y3 = aa * g * (d - ac);       // Y3 = A*G*(D - a*C)
        let z3 = f * g;                   // Z3 = F*G
        BJJProj { x: x3, y: y3, z: z3 }
    }

    /// Convert to affine: (X/Z, Y/Z).
    fn to_affine(&self) -> (Fr, Fr) {
        let z_inv = self.z.inverse().unwrap_or(Fr::ZERO);
        (self.x * z_inv, self.y * z_inv)
    }
}

// ─── Scalar multiplication ─────────────────────────────────────────────────

/// Scalar multiply: `scalar * point` using double-and-add (LSB-first).
/// `scalar` is a BN254 Fr element (LE limbs).
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

// ─── Public API ─────────────────────────────────────────────────────────────

/// Verify that `reencrypted[i] = original[i] + encZero(k', pubKey)` for all i.
///
/// `k` is the raw re-encryption seed; `k' = poseidon1(k)` is derived inside.
/// `pub_key` is the ElGamal encryption public key point.
/// All 8 fields use the same delta since `EncryptedZero` uses the same k' for all fields.
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

    // k' = poseidon1(k)
    let k_prime = poseidon1(k);

    // delta1 = k' * B8
    let b8 = BJJProj::from_affine(raw_to_fr(&B8X_LE), raw_to_fr(&B8Y_LE));
    let delta1_proj = scalar_mult(&b8, &k_prime);
    let (d1x, d1y) = delta1_proj.to_affine();

    // delta2 = k' * pubKey
    let pub_key_proj = BJJProj::from_affine(raw_to_fr(pub_key_x), raw_to_fr(pub_key_y));
    let delta2_proj = scalar_mult(&pub_key_proj, &k_prime);
    let (d2x, d2y) = delta2_proj.to_affine();

    // For each field: newC1 = origC1 + delta1, newC2 = origC2 + delta2
    for i in 0..original.len() {
        let orig1 = BJJProj::from_affine(raw_to_fr(&original[i].c1x), raw_to_fr(&original[i].c1y));
        let expected1 = orig1.add(&delta1_proj);
        let (ex1, ey1) = expected1.to_affine();
        if fr_to_raw(ex1) != reencrypted[i].c1x || fr_to_raw(ey1) != reencrypted[i].c1y {
            return false;
        }

        let orig2 = BJJProj::from_affine(raw_to_fr(&original[i].c2x), raw_to_fr(&original[i].c2y));
        let expected2 = orig2.add(&delta2_proj);
        let (ex2, ey2) = expected2.to_affine();
        if fr_to_raw(ex2) != reencrypted[i].c2x || fr_to_raw(ey2) != reencrypted[i].c2y {
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
        None => return true,  // absent = pass
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
