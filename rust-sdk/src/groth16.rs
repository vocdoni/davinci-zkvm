//! Ballot proof (circom Groth16, BN254) verification, with the same parsing
//! and VK hashing as the service and guest (`input-gen` `build_vk` /
//! `g1_to_raw`, guest `hash_vk_bytes`). snarkjs G2 ordering is assumed:
//! `[[x_c0, x_c1], [y_c0, y_c1], [1, 0]]`.

use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G1Projective, G2Affine};
use ark_ec::{AffineRepr, VariableBaseMSM};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::crypto::field::{biguint_from_dec, biguint_to_u256, Fr};
use crate::limits::BALLOT_COORDS;
use crate::types::{SnarkJsProof, SnarkJsVk};
use crate::Error;

/// Public signals per ballot proof: address, vote id, process id, packed
/// ballot mode, encryption key x and y, weight, then the 64 ballot
/// coordinates (see [`crate::ballot::public_signals`]).
pub const N_PUBLIC: usize = 7 + BALLOT_COORDS;
const _: () = assert!(N_PUBLIC == 71);

pub struct BallotVerifier {
    pvk: PreparedVerifyingKey<Bn254>,
    wire: Vec<u8>,
}

impl std::fmt::Debug for BallotVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BallotVerifier(vk_hash={})", hex::encode(self.vk_hash()))
    }
}

fn fq_from_dec(s: &str) -> Result<Fq, Error> {
    let v = biguint_to_u256(&biguint_from_dec(s)?).ok_or(Error::Point("coordinate >= 2^256"))?;
    Fq::from_bigint(v).ok_or(Error::Point("coordinate >= q"))
}

fn parse_g1(v: &[String; 3]) -> Result<G1Affine, Error> {
    if v[2] == "0" {
        return Ok(G1Affine::zero());
    }
    let p = G1Affine::new_unchecked(fq_from_dec(&v[0])?, fq_from_dec(&v[1])?);
    if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(Error::Point("invalid G1 point"));
    }
    Ok(p)
}

fn parse_g2(v: &[[String; 2]; 3]) -> Result<G2Affine, Error> {
    if v[2][0] == "0" && v[2][1] == "0" {
        return Ok(G2Affine::zero());
    }
    let x = Fq2::new(fq_from_dec(&v[0][0])?, fq_from_dec(&v[0][1])?);
    let y = Fq2::new(fq_from_dec(&v[1][0])?, fq_from_dec(&v[1][1])?);
    let p = G2Affine::new_unchecked(x, y);
    if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(Error::Point("invalid G2 point"));
    }
    Ok(p)
}

fn put_fq(buf: &mut Vec<u8>, x: &Fq) {
    buf.extend_from_slice(&x.into_bigint().to_bytes_le());
}

// Identity is all zeros, as `g1_to_raw` writes it.
fn put_g1(buf: &mut Vec<u8>, p: &G1Affine) {
    if p.is_zero() {
        buf.extend_from_slice(&[0u8; 64]);
        return;
    }
    put_fq(buf, &p.x);
    put_fq(buf, &p.y);
}

fn put_g2(buf: &mut Vec<u8>, p: &G2Affine) {
    if p.is_zero() {
        buf.extend_from_slice(&[0u8; 128]);
        return;
    }
    for c in [&p.x.c0, &p.x.c1, &p.y.c0, &p.y.c1] {
        put_fq(buf, c);
    }
}

impl BallotVerifier {
    /// Parses a snarkjs `verification_key.json`; see [`Self::from_snarkjs`].
    pub fn from_snarkjs_json(vk: &str) -> Result<Self, Error> {
        let vk: SnarkJsVk = serde_json::from_str(vk)?;
        Self::from_snarkjs(&vk)
    }

    /// Refuses a VK the batch guest would reject: not groth16/bn128, without
    /// `N_PUBLIC + 1` IC points, or with `delta == gamma` (no phase-2
    /// contribution, so anyone can forge proofs).
    pub fn from_snarkjs(vk: &SnarkJsVk) -> Result<Self, Error> {
        if vk.protocol != "groth16" || vk.curve != "bn128" {
            return Err(Error::Input("vk is not groth16/bn128".into()));
        }
        if vk.ic.len() != N_PUBLIC + 1 {
            return Err(Error::Input(format!(
                "vk has {} IC points, want {}",
                vk.ic.len(),
                N_PUBLIC + 1
            )));
        }
        let ark = VerifyingKey::<Bn254> {
            alpha_g1: parse_g1(&vk.vk_alpha_1)?,
            beta_g2: parse_g2(&vk.vk_beta_2)?,
            gamma_g2: parse_g2(&vk.vk_gamma_2)?,
            delta_g2: parse_g2(&vk.vk_delta_2)?,
            gamma_abc_g1: vk.ic.iter().map(parse_g1).collect::<Result<_, _>>()?,
        };
        if ark.delta_g2 == ark.gamma_g2 {
            return Err(Error::Input(
                "vk has delta == gamma (no phase-2 contribution)".into(),
            ));
        }
        let mut wire = Vec::with_capacity(64 + 3 * 128 + 8 + 64 * ark.gamma_abc_g1.len());
        put_g1(&mut wire, &ark.alpha_g1);
        put_g2(&mut wire, &ark.beta_g2);
        put_g2(&mut wire, &ark.gamma_g2);
        put_g2(&mut wire, &ark.delta_g2);
        wire.extend_from_slice(&(ark.gamma_abc_g1.len() as u64).to_le_bytes());
        for p in &ark.gamma_abc_g1 {
            put_g1(&mut wire, p);
        }
        Ok(BallotVerifier {
            pvk: prepare_verifying_key(&ark),
            wire,
        })
    }

    /// Verifies one proof. Anything the service or guest would refuse
    /// (bad encoding, identity points, wrong protocol) is `false`.
    pub fn verify(&self, proof: &SnarkJsProof, pubs: &[Fr; N_PUBLIC]) -> bool {
        if proof.protocol != "groth16" || proof.curve != "bn128" {
            return false;
        }
        let (Ok(a), Ok(b), Ok(c)) = (
            parse_g1(&proof.pi_a),
            parse_g2(&proof.pi_b),
            parse_g1(&proof.pi_c),
        ) else {
            return false;
        };
        if a.is_zero() || b.is_zero() || c.is_zero() {
            return false;
        }
        // vk_x = IC[0] + MSM(IC[1..], pubs): ark-groth16's per-input loop is
        // about 4x slower at 71 inputs.
        let ic = &self.pvk.vk.gamma_abc_g1;
        let Ok(acc) = G1Projective::msm(&ic[1..], pubs) else {
            return false;
        };
        let vk_x = acc + ic[0];
        Groth16::<Bn254>::verify_proof_with_prepared_inputs(&self.pvk, &Proof { a, b, c }, &vk_x)
            .unwrap_or(false)
    }

    /// sha256 of the VK wire bytes (guest `hash_vk_bytes`); config leaf 0x07
    /// is this digest read big-endian.
    pub fn vk_hash(&self) -> [u8; 32] {
        Sha256::digest(&self.wire).into()
    }
}
