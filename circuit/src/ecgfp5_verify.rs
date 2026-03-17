//! Ecgfp5-native ballot helpers for the davinci-stark path.
//!
//! This module verifies re-encryption over encoded ecgfp5 ciphertexts and
//! checks result-accumulator hashes and homomorphic sums for the ecgfp5 state
//! payload.

use ecgfp5::curve::Point;
use ecgfp5::field::GFp5;
use ecgfp5::scalar::Scalar;

use crate::hash;
use crate::types::{
    Ecgfp5Ballot, Ecgfp5Ciphertext, Ecgfp5PointRaw, Ecgfp5ReencEntry, FAIL_REENC, FrRaw,
};

fn raw_to_bytes(raw: &Ecgfp5PointRaw) -> [u8; 40] {
    let mut out = [0u8; 40];
    for (i, limb) in raw.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    out
}

fn point_from_raw(raw: &Ecgfp5PointRaw) -> Option<Point> {
    let bytes = raw_to_bytes(raw);
    let (w, ok) = GFp5::decode(&bytes);
    if ok != u64::MAX {
        return None;
    }
    let (p, ok) = Point::decode(w);
    if ok != u64::MAX {
        return None;
    }
    Some(p)
}

fn scalar_from_raw(raw: &Ecgfp5PointRaw) -> Scalar {
    let bytes = raw_to_bytes(raw);
    Scalar::decode_reduce(&bytes)
}

fn point_to_raw(point: Point) -> Ecgfp5PointRaw {
    let enc = point.encode().encode();
    let mut out = [0u64; 5];
    for i in 0..5 {
        out[i] = u64::from_le_bytes(enc[i * 8..(i + 1) * 8].try_into().unwrap());
    }
    out
}

pub fn point_matches_projective_limbs(raw: &Ecgfp5PointRaw, limbs: &[u64; 20]) -> bool {
    let Some(point) = point_from_raw(raw) else {
        return false;
    };
    let mut expected = [0u64; 20];
    expected[0..5].copy_from_slice(&point.X.0.map(|x| x.to_u64()));
    expected[5..10].copy_from_slice(&point.Z.0.map(|x| x.to_u64()));
    expected[10..15].copy_from_slice(&point.U.0.map(|x| x.to_u64()));
    expected[15..20].copy_from_slice(&point.T.0.map(|x| x.to_u64()));
    &expected == limbs
}

fn ciphertext_add(a: &Ecgfp5Ciphertext, b: &Ecgfp5Ciphertext) -> Option<Ecgfp5Ciphertext> {
    let c1 = point_from_raw(&a.c1)? + point_from_raw(&b.c1)?;
    let c2 = point_from_raw(&a.c2)? + point_from_raw(&b.c2)?;
    Some(Ecgfp5Ciphertext {
        c1: point_to_raw(c1),
        c2: point_to_raw(c2),
    })
}

pub fn hash_enc_key(pub_key: &Ecgfp5PointRaw) -> FrRaw {
    let digest = hash::sha256_once(&raw_to_bytes(pub_key));
    let mut fr = [0u64; 4];
    for i in 0..4 {
        let off = (3 - i) * 8;
        fr[i] = u64::from_be_bytes(digest[off..off + 8].try_into().unwrap());
    }
    fr
}

pub fn ballot_leaf_hash(ballot: &Ecgfp5Ballot) -> FrRaw {
    let mut bytes = [0u8; 8 * 80];
    let mut off = 0usize;
    for ct in ballot {
        let c1 = raw_to_bytes(&ct.c1);
        let c2 = raw_to_bytes(&ct.c2);
        bytes[off..off + 40].copy_from_slice(&c1);
        off += 40;
        bytes[off..off + 40].copy_from_slice(&c2);
        off += 40;
    }
    let digest = hash::sha256_once(&bytes);
    let mut fr = [0u64; 4];
    for i in 0..4 {
        let start = (3 - i) * 8;
        fr[i] = u64::from_be_bytes(digest[start..start + 8].try_into().unwrap());
    }
    fr
}

pub fn ballot_add(a: &Ecgfp5Ballot, b: &Ecgfp5Ballot) -> Option<Ecgfp5Ballot> {
    let mut out = [Ecgfp5Ciphertext::default(); 8];
    for i in 0..8 {
        out[i] = ciphertext_add(&a[i], &b[i])?;
    }
    Some(out)
}

pub fn verify_reencryption(
    k: &Ecgfp5PointRaw,
    pub_key: &Ecgfp5PointRaw,
    original: &Ecgfp5Ballot,
    reencrypted: &Ecgfp5Ballot,
) -> bool {
    let k_scalar = scalar_from_raw(k);
    let Some(pub_key_point) = point_from_raw(pub_key) else {
        return false;
    };
    let delta1 = Point::mulgen(k_scalar);
    let delta2 = pub_key_point * k_scalar;

    for i in 0..8 {
        let Some(orig_c1) = point_from_raw(&original[i].c1) else {
            return false;
        };
        let Some(orig_c2) = point_from_raw(&original[i].c2) else {
            return false;
        };
        if point_to_raw(orig_c1 + delta1) != reencrypted[i].c1 {
            return false;
        }
        if point_to_raw(orig_c2 + delta2) != reencrypted[i].c2 {
            return false;
        }
    }
    true
}

pub fn verify_batch_from_parsed(
    reenc_pub_key: &Option<Ecgfp5PointRaw>,
    reenc_entries: &[Ecgfp5ReencEntry],
    fail_mask: &mut u32,
) -> bool {
    let Some(pub_key) = reenc_pub_key else {
        *fail_mask |= crate::types::FAIL_MISSING_BLOCK;
        return false;
    };
    for entry in reenc_entries {
        if !verify_reencryption(&entry.k, pub_key, &entry.original, &entry.reencrypted) {
            *fail_mask |= FAIL_REENC;
            return false;
        }
    }
    true
}
