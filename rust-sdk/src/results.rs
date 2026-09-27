//! The circuit-results request: decrypt the final accumulator with the
//! election key and prove every plaintext (circuit-results/RESULTS.md).

use rand::{CryptoRng, RngCore};

use crate::ballot::Ballot;
use crate::crypto::babyjubjub::Point;
use crate::crypto::chaum_pedersen::{prove_decryption, verify_decryption};
use crate::crypto::elgamal::decrypt;
use crate::crypto::field::{fr_to_le, u256_to_le, Fr, U256};
use crate::limits::{NUM_FIELDS, SMT_LEVELS};
use crate::types::{CpProofJson, ResultsRequest};
use crate::Error;

// Arbo-LE hex without `0x`, as the results JSON and go-sdk ResultsPayload use.
fn le(x: &Fr) -> String {
    hex::encode(fr_to_le(x))
}

fn siblings(s: &[[u8; 32]]) -> Result<Vec<String>, Error> {
    if s.len() > SMT_LEVELS {
        return Err(Error::Input(format!(
            "{} siblings, at most {SMT_LEVELS}",
            s.len()
        )));
    }
    let mut out: Vec<String> = s.iter().map(hex::encode).collect();
    out.resize(SMT_LEVELS, hex::encode([0u8; 32]));
    Ok(out)
}

/// Builds the `/results` body for the final `state_root` (raw arbo bytes).
/// The siblings are the inclusion proofs of keys 0x03 and 0x04 under that
/// root, root to leaf (zero-padded to 64 here). Every accumulator field must
/// decrypt within `[0, max]`; `sk` must match `pk`. Returns the request and
/// the tally.
#[allow(clippy::too_many_arguments)]
pub fn build_results_request(
    state_root: &[u8; 32],
    pk: &Point,
    key_siblings: &[[u8; 32]],
    acc: &Ballot,
    acc_siblings: &[[u8; 32]],
    sk: &U256,
    max: u64,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(ResultsRequest, [u64; NUM_FIELDS]), Error> {
    if Point::generator().mul(sk) != *pk || *pk == Point::IDENTITY {
        return Err(Error::Input(
            "secret key does not match the election key".into(),
        ));
    }
    let mut results = [0u64; NUM_FIELDS];
    let mut cp_proofs = Vec::with_capacity(NUM_FIELDS);
    for (i, ct) in acc.0.iter().enumerate() {
        let m = decrypt(sk, ct, max)
            .ok_or_else(|| Error::Input(format!("field {i} does not decrypt within [0, {max}]")))?;
        let p = prove_decryption(sk, pk, ct, m, rng);
        if !verify_decryption(pk, ct, m, &p) {
            return Err(Error::Input(format!(
                "field {i}: decryption proof does not verify"
            )));
        }
        results[i] = m;
        cp_proofs.push(CpProofJson {
            a1x: le(&p.a1.x),
            a1y: le(&p.a1.y),
            a2x: le(&p.a2.x),
            a2y: le(&p.a2.y),
            z: hex::encode(u256_to_le(&p.z)),
        });
    }
    let req = ResultsRequest {
        state_root: hex::encode(state_root),
        enc_key_x: le(&pk.x),
        enc_key_y: le(&pk.y),
        key_siblings: siblings(key_siblings)?,
        accumulator: acc.coords().iter().map(le).collect(),
        acc_siblings: siblings(acc_siblings)?,
        results: results.to_vec(),
        cp_proofs,
    };
    Ok((req, results))
}
