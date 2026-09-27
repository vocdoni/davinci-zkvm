//! DA blob layout, KZG commitments/openings and the decoder, against go-sdk
//! `BuildTransitionBlobs` vectors.

mod common;

use common::*;
use davinci_zkvm_sdk::ballot::Ballot;
use davinci_zkvm_sdk::blob::*;
use davinci_zkvm_sdk::crypto::babyjubjub::Point;
use davinci_zkvm_sdk::crypto::elgamal::Ciphertext;
use davinci_zkvm_sdk::crypto::field::{fr_from_be, Fr};
use davinci_zkvm_sdk::limits::{MAX_BATCH_SIZE, TX_BLOB_CAP};
use proptest::prelude::*;
use serde_json::Value;

fn be_fr(h: &str) -> Fr {
    let mut b = [0u8; 32];
    hex::decode_to_slice(h.trim_start_matches("0x"), &mut b).unwrap();
    fr_from_be(&b).unwrap()
}

fn be_ballot(v: &Value) -> Ballot {
    let coords: Vec<Fr> = v.as_array().unwrap().iter().map(|h| be_fr(s(h))).collect();
    Ballot::from_coords(&coords.try_into().unwrap()).unwrap()
}

fn transition(v: &Value) -> TransitionData {
    TransitionData {
        vote_ids: v["vote_ids"].as_array().unwrap().iter().map(u64v).collect(),
        updates: v["updates"]
            .as_array()
            .unwrap()
            .iter()
            .map(|u| (u64v(&u["key"]), be_ballot(&u["ballot"])))
            .collect(),
        accumulator: be_ballot(&v["accumulator"]),
        num_fields: u64v(&v["nf"]) as u8,
    }
}

fn sorted(t: &TransitionData) -> TransitionData {
    let mut t = t.clone();
    t.vote_ids.sort_unstable();
    t.updates.sort_by_key(|(k, _)| *k);
    t
}

fn hexes(v: &Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| s(x).to_string())
        .collect()
}

#[test]
fn blobs_match_go_kzg4844() {
    let v = load("blob.json");
    let mut multi = false;
    for case in v.as_array().unwrap() {
        let t = transition(case);
        let c: Vec<String> = cells(&t).iter().map(hex::encode).collect();
        assert_eq!(c, hexes(&case["cells"]), "cells nf={}", t.num_fields);
        let pid = fr(&case["process_id"]);
        let root = hex32(&case["root_before"]);
        let tb = build_blobs(&t, &pid, &root).unwrap();
        let n = tb.blobs.len();
        multi |= n > 1;
        assert_eq!(
            n,
            blob_count(t.vote_ids.len(), t.updates.len(), t.num_fields)
        );
        assert_eq!(
            tb.commitments.iter().map(hex::encode).collect::<Vec<_>>(),
            hexes(&case["commitments"])
        );
        assert_eq!(
            tb.zs.iter().map(hex::encode).collect::<Vec<_>>(),
            hexes(&case["zs"])
        );
        assert_eq!(
            tb.ys.iter().map(hex::encode).collect::<Vec<_>>(),
            hexes(&case["ys"])
        );
        assert_eq!(
            tb.proofs.iter().map(hex::encode).collect::<Vec<_>>(),
            hexes(&case["proofs"])
        );
        assert_eq!(
            tb.versioned_hashes
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
            hexes(&case["versioned_hashes"])
        );
        assert_eq!(hex::encode(tb.digest), s(&case["digest"]));
        assert_eq!(tb.blobs, blobs_from_cells(&cells(&t)).unwrap());
        assert_eq!(decode_blobs(&tb.blobs, t.num_fields).unwrap(), sorted(&t));
        for (b, vh) in tb.blobs.iter().zip(&tb.versioned_hashes) {
            assert_eq!(verify_blob_commitment(b, vh).unwrap().len(), 48);
        }
    }
    assert!(multi, "no multi-blob vector");
}

#[test]
fn verify_blob_commitment_rejects_changes() {
    let v = load("blob.json");
    let t = transition(&v[0]);
    let tb = build_blobs(&t, &fr(&v[0]["process_id"]), &hex32(&v[0]["root_before"])).unwrap();
    let mut b = tb.blobs[0].clone();
    b[31] ^= 1;
    assert!(verify_blob_commitment(&b, &tb.versioned_hashes[0]).is_err());
    let mut vh = tb.versioned_hashes[0];
    vh[5] ^= 1;
    assert!(verify_blob_commitment(&tb.blobs[0], &vh).is_err());
    // A cell >= r_bls is not a valid blob at all.
    let mut b = tb.blobs[0].clone();
    b[..32].fill(0xff);
    assert!(verify_blob_commitment(&b, &tb.versioned_hashes[0]).is_err());
}

// Base transition for the rejection tests: nf 2, 3 vote ids, 2 updates.
fn base() -> (TransitionData, Vec<[u8; 32]>) {
    let g = Point::generator();
    let p = |k: u64| g.mul(&ark_ff::BigInt::from(k));
    let ct = |k: u64| Ciphertext {
        c1: p(k),
        c2: p(k + 1),
    };
    let mut b1 = Ballot::identity();
    b1.0[0] = ct(3);
    b1.0[1] = ct(5);
    let mut b2 = Ballot::identity();
    b2.0[0] = ct(7);
    b2.0[1] = ct(9);
    let mut acc = Ballot::identity();
    acc.0[0] = ct(11);
    let t = TransitionData {
        vote_ids: vec![1 << 63 | 5, 1 << 63 | 1, u64::MAX],
        updates: vec![(0x30, b1), (0x11, b2)],
        accumulator: acc,
        num_fields: 2,
    };
    let c = cells(&t);
    (t, c)
}

fn decode_cells(c: &[[u8; 32]], nf: u8) -> Result<TransitionData, davinci_zkvm_sdk::Error> {
    decode_blobs(&blobs_from_cells(c).unwrap(), nf)
}

#[test]
fn decode_rejects_malformed_blobs() {
    let (t, c) = base();
    assert_eq!(decode_cells(&c, 2).unwrap(), sorted(&t));
    // Wrong nf reads the stream differently and must not succeed silently.
    assert!(decode_cells(&c, 1).is_err());
    assert!(decode_cells(&c, 0).is_err());
    assert!(decode_cells(&c, 17).is_err());
    assert!(decode_blobs(&[], 2).is_err());

    // Truncated / oversized counts.
    let mut bad = c.clone();
    bad[0][31] = 200;
    assert!(decode_cells(&bad, 2).is_err());
    let mut bad = c.clone();
    bad[0] = [0u8; 32];
    bad[0][24..].copy_from_slice(&u64::MAX.to_be_bytes());
    assert!(decode_cells(&bad, 2).is_err());
    let upd_count = 1 + 3;
    let mut bad = c.clone();
    bad[upd_count][31] = 9;
    assert!(decode_cells(&bad, 2).is_err());
    // A count cell above 64 bits.
    let mut bad = c.clone();
    bad[0][0] = 1;
    assert!(decode_cells(&bad, 2).is_err());

    // First point cell of the first update: y >= p, then a y with no x.
    let first_point = upd_count + 2;
    let mut bad = c.clone();
    bad[first_point] =
        hex::decode("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001")
            .unwrap()
            .try_into()
            .unwrap();
    assert!(decode_cells(&bad, 2).is_err());
    let mut off_curve = None;
    for y in 2u64..60 {
        let mut cell = [0u8; 32];
        cell[24..].copy_from_slice(&y.to_be_bytes());
        if Point::decompress(&cell).is_err() {
            off_curve = Some(cell);
            break;
        }
    }
    let mut bad = c.clone();
    bad[first_point] = off_curve.unwrap();
    assert!(decode_cells(&bad, 2).is_err());
    let mut bad = c.clone();
    bad[first_point][0] |= 0x80;
    assert!(decode_cells(&bad, 2).is_err());

    // Trailing junk after the accumulator, in the same blob.
    let mut bad = c.clone();
    let mut junk = [0u8; 32];
    junk[31] = 1;
    bad.push(junk);
    assert!(decode_cells(&bad, 2).is_err());
    // A whole extra (zero) blob.
    let mut blobs = blobs_from_cells(&c).unwrap();
    blobs.push(blobs_from_cells(&[]).unwrap().remove(0));
    assert!(decode_blobs(&blobs, 2).is_err());

    // Order and namespace rules.
    let mut bad = c.clone();
    bad.swap(1, 2);
    assert!(decode_cells(&bad, 2).is_err());
    let mut t2 = t.clone();
    t2.vote_ids.push(12345);
    assert!(decode_cells(&cells(&t2), 2).is_err());
    let mut t2 = t.clone();
    t2.updates.push((0x05, Ballot::identity()));
    assert!(decode_cells(&cells(&t2), 2).is_err());
    let mut t2 = t.clone();
    t2.updates.push((0x30, Ballot::identity()));
    assert!(decode_cells(&cells(&t2), 2).is_err());
    let mut t2 = t.clone();
    t2.vote_ids.push(u64::MAX);
    assert!(decode_cells(&cells(&t2), 2).is_err());
}

#[test]
fn six_blob_cap_table() {
    // Same table as go-sdk MaxSingleTxBatch (no overwrites) and the six-blob cap.
    let big = 1 << 20;
    for (nf, none, all) in [
        (1u8, 1024, 1024),
        (2, 1024, 1024),
        (5, 1024, 722),
        (6, 909, 614),
        (8, 701, 472),
        (12, 481, 323),
        (16, 366, 245),
    ] {
        assert_eq!(
            max_votes_for_cap(nf, 0, big, TX_BLOB_CAP),
            none,
            "nf {nf} no overwrites"
        );
        assert_eq!(
            max_votes_for_cap(nf, usize::MAX, big, TX_BLOB_CAP),
            all,
            "nf {nf} all overwrites"
        );
    }
    // Small trees need fewer refreshes, so more votes fit.
    assert!(max_votes_for_cap(16, 0, 0, TX_BLOB_CAP) > 366);
    assert_eq!(max_votes_for_cap(2, 0, big, 32), MAX_BATCH_SIZE);
    assert_eq!(blob_count(0, 0, 1), 1);
    assert_eq!(blob_count(4094 - 2, 0, 1), 1);
    assert_eq!(blob_count(4095 - 2, 0, 1), 2);
}

fn pool() -> &'static Vec<Point> {
    static POOL: std::sync::OnceLock<Vec<Point>> = std::sync::OnceLock::new();
    POOL.get_or_init(|| {
        let g = Point::generator();
        (1..=48u64)
            .map(|k| g.mul(&ark_ff::BigInt::from(k * 7919 + 3)))
            .collect()
    })
}

prop_compose! {
    fn arb_ballot(nf: u8)(idx in prop::collection::vec(0usize..48, 32), neg in any::<u32>()) -> Ballot {
        let p = pool();
        let mut b = Ballot::identity();
        for (f, ct) in b.0.iter_mut().enumerate().take(nf as usize) {
            let pick = |i: usize| {
                let q = p[idx[i]];
                if neg >> (i % 32) & 1 == 1 { q.neg() } else { q }
            };
            *ct = Ciphertext { c1: pick(2 * f), c2: pick(2 * f + 1) };
        }
        b
    }
}

fn arb_transition() -> impl Strategy<Value = TransitionData> {
    (1u8..=16).prop_flat_map(|nf| {
        (
            prop::collection::btree_set((1u64 << 63)..=u64::MAX, 0..40),
            prop::collection::btree_map(0x10u64..(1 << 63), arb_ballot(nf), 0..30),
            arb_ballot(nf),
        )
            .prop_map(move |(vids, ups, acc)| TransitionData {
                vote_ids: vids.into_iter().collect(),
                updates: ups.into_iter().collect(),
                accumulator: acc,
                num_fields: nf,
            })
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn decode_inverts_encode(t in arb_transition()) {
        let blobs = blobs_from_cells(&cells(&t)).unwrap();
        prop_assert_eq!(blobs.len(), blob_count(t.vote_ids.len(), t.updates.len(), t.num_fields));
        prop_assert_eq!(decode_blobs(&blobs, t.num_fields).unwrap(), t);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(6))]
    #[test]
    fn decode_inverts_build_blobs(t in arb_transition()) {
        let tb = build_blobs(&t, &Fr::from(77u64), &[9u8; 32]).unwrap();
        prop_assert_eq!(decode_blobs(&tb.blobs, t.num_fields).unwrap(), t);
    }
}
