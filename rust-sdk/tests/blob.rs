//! DA blob layout, KZG commitments/openings and the decoder, against go-sdk
//! `BuildTransitionBlobs` vectors.

mod common;

use common::*;
use davinci_zkvm_sdk::ballot::Ballot;
use davinci_zkvm_sdk::blob::*;
use davinci_zkvm_sdk::crypto::babyjubjub::Point;
use davinci_zkvm_sdk::crypto::elgamal::Ciphertext;
use davinci_zkvm_sdk::crypto::field::{fr_from_be, Fr};
use davinci_zkvm_sdk::limits::{
    BALLOT_MAX, BALLOT_MIN, MAX_BATCH_SIZE, MAX_REFRESH, TX_BLOB_CAP, VOTE_ID_MIN,
};
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
    let mut residues = [false; 4];
    for case in v.as_array().unwrap() {
        let t = transition(case);
        residues[(t.vote_ids.len() + t.updates.len()) % 4] = true;
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
    assert_eq!(residues, [true; 4], "V + U must cover every residue mod 4");
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

// Identity-ballot transition with `v` vote ids and `u` updates.
fn plain(v: u64, u: u64, nf: u8) -> TransitionData {
    TransitionData {
        vote_ids: (0..v).map(|i| VOTE_ID_MIN + i).collect(),
        updates: (0..u)
            .map(|i| (BALLOT_MIN + i, Ballot::identity()))
            .collect(),
        num_fields: nf,
    }
}

#[test]
fn integer_cells_pack_four_per_cell() {
    // One vote id, three keys: one integer cell, first element on top.
    let t = TransitionData {
        vote_ids: vec![VOTE_ID_MIN | 1],
        updates: vec![
            (BALLOT_MAX, Ballot::identity()),
            (0x11, Ballot::identity()),
            (0x10, Ballot::identity()),
        ],
        num_fields: 1,
    };
    let c = cells(&t);
    assert_eq!(c.len(), 1 + 1 + 3 * 2);
    assert_eq!(
        hex::encode(c[0]),
        "0000000000000000000000000000000000000000000000010000000000000003"
    );
    assert_eq!(
        hex::encode(c[1]),
        "000000000000000020000000000000040000000000000008ffffffffffffffff"
    );
    // Every slot at its maximum stays below 2^252.
    let t = TransitionData {
        vote_ids: vec![u64::MAX],
        updates: vec![
            (BALLOT_MAX - 2, Ballot::identity()),
            (BALLOT_MAX - 1, Ballot::identity()),
            (BALLOT_MAX, Ballot::identity()),
        ],
        num_fields: 1,
    };
    assert_eq!(
        hex::encode(cells(&t)[1]),
        "0fffffffffffffffffffffffffffffff7fffffffffffffff7fffffffffffffff"
    );
    assert_eq!(
        decode_blobs(&blobs_from_cells(&cells(&t)).unwrap(), 1).unwrap(),
        t
    );
}

#[test]
fn vote_ids_pack_without_their_top_bit() {
    // The guest masks the id, so an id below 2^63 (which it rejects
    // elsewhere) packs like the same id with the top bit set.
    let mut low = plain(1, 1, 1);
    low.vote_ids[0] = 5;
    let mut high = plain(1, 1, 1);
    high.vote_ids[0] = VOTE_ID_MIN | 5;
    assert_eq!(cells(&low), cells(&high));
}

#[test]
fn layout_boundaries_round_trip() {
    // V and U at the integer-cell edges, at 1 and 16 fields.
    for nf in [1u8, 16] {
        for u in [0u64, 1, 3, 4, 5] {
            for v in [0u64, 1, 3, 4, 5].into_iter().filter(|v| *v <= u) {
                let t = plain(v, u, nf);
                let want = 1 + (v + u).div_ceil(4) + 2 * nf as u64 * u;
                assert_eq!(cells(&t).len() as u64, want, "v {v} u {u} nf {nf}");
                let blobs = blobs_from_cells(&cells(&t)).unwrap();
                assert_eq!(decode_blobs(&blobs, nf).unwrap(), t, "v {v} u {u} nf {nf}");
            }
        }
    }
    // T = 4096 fills one blob; T = 4097 puts one cell in a second.
    for (v, u, n) in [(126, 126, 1), (1, 127, 2)] {
        let t = plain(v, u, 16);
        assert_eq!(cells(&t).len(), 4095 + n);
        assert_eq!(blob_count(v as usize, u as usize, 16), n);
        let tb = build_blobs(&t, &Fr::from(3u64), &[5u8; 32]).unwrap();
        assert_eq!(tb.blobs.len(), n);
        assert_eq!(decode_blobs(&tb.blobs, 16).unwrap(), t);
    }
    // The largest batch with the most refreshes.
    let (v, u) = (MAX_BATCH_SIZE as u64, (MAX_BATCH_SIZE + MAX_REFRESH) as u64);
    let t = plain(v, u, 1);
    let blobs = blobs_from_cells(&cells(&t)).unwrap();
    assert_eq!(blobs.len(), 2);
    assert_eq!(decode_blobs(&blobs, 1).unwrap(), t);
    assert_eq!(blob_count(v as usize, u as usize, 16), 25);
}

// Base transition for the rejection tests: nf 2, 2 vote ids, 3 updates, so
// the integer section is two cells and the second has three unused slots.
fn base() -> (TransitionData, Vec<[u8; 32]>) {
    let g = Point::generator();
    let p = |k: u64| g.mul(&ark_ff::BigInt::from(k));
    let ct = |k: u64| Ciphertext {
        c1: p(k),
        c2: p(k + 1),
    };
    let ballot = |k: u64| {
        let mut b = Ballot::identity();
        b.0[0] = ct(k);
        b.0[1] = ct(k + 2);
        b
    };
    let t = TransitionData {
        vote_ids: vec![u64::MAX, VOTE_ID_MIN | 5],
        updates: vec![
            (0x30, ballot(3)),
            (0x11, ballot(7)),
            (BALLOT_MAX, ballot(11)),
        ],
        num_fields: 2,
    };
    let c = cells(&t);
    (t, c)
}

fn decode_cells(c: &[[u8; 32]], nf: u8) -> Result<TransitionData, davinci_zkvm_sdk::Error> {
    decode_blobs(&blobs_from_cells(c).unwrap(), nf)
}

fn header_cell(n_vids: u64, n_updates: u64) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[16..24].copy_from_slice(&n_vids.to_be_bytes());
    h[24..].copy_from_slice(&n_updates.to_be_bytes());
    h
}

#[test]
fn decode_rejects_malformed_blobs() {
    let (t, c) = base();
    assert_eq!(c.len(), 1 + 2 + 3 * 4);
    assert_eq!(decode_cells(&c, 2).unwrap(), sorted(&t));
    // Wrong nf reads the stream differently and must not succeed silently.
    assert!(decode_cells(&c, 1).is_err());
    assert!(decode_cells(&c, 0).is_err());
    assert!(decode_cells(&c, 17).is_err());
    assert!(decode_blobs(&[], 2).is_err());

    // Header: the version field and every bit above the counts are zero.
    for byte in [0usize, 15] {
        let mut bad = c.clone();
        bad[0][byte] = 1;
        assert!(decode_cells(&bad, 2).is_err(), "header byte {byte}");
    }
    // More vote ids than updates, too many vote ids, too many updates.
    for (v, u) in [(4, 3), (MAX_BATCH_SIZE as u64 + 1, 1100), (1, 3073)] {
        let mut bad = c.clone();
        bad[0] = header_cell(v, u);
        assert!(decode_cells(&bad, 2).is_err(), "counts {v} / {u}");
    }
    // A count the blobs cannot hold, and a whole extra (zero) blob.
    let mut bad = c.clone();
    bad[0] = header_cell(2, 2000);
    assert!(decode_cells(&bad, 2).is_err());
    let mut blobs = blobs_from_cells(&c).unwrap();
    blobs.push(blobs_from_cells(&[]).unwrap().remove(0));
    assert!(decode_blobs(&blobs, 2).is_err());

    // Integer cells: at 2^252, and a non-zero unused slot of the last one.
    let mut bad = c.clone();
    bad[1][0] |= 0x10;
    assert!(decode_cells(&bad, 2).is_err());
    let mut bad = c.clone();
    bad[2][31] = 1;
    assert!(decode_cells(&bad, 2).is_err());

    // Order and namespace rules.
    let mut t2 = t.clone();
    t2.vote_ids.push(u64::MAX);
    assert!(decode_cells(&cells(&t2), 2).is_err());
    let mut t2 = t.clone();
    t2.updates.push((0x05, Ballot::identity()));
    assert!(decode_cells(&cells(&t2), 2).is_err());
    let mut t2 = t.clone();
    t2.updates.push((0x30, Ballot::identity()));
    assert!(decode_cells(&cells(&t2), 2).is_err());

    // First point cell of the first update: y >= p, then a y with no x,
    // then bit 255.
    let first_point = 3;
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

    // Trailing junk after the last ballot, in the same blob.
    let mut bad = c.clone();
    let mut junk = [0u8; 32];
    junk[31] = 1;
    bad.push(junk);
    assert!(decode_cells(&bad, 2).is_err());
}

#[test]
fn six_blob_cap_table() {
    // Same table as go-sdk MaxSingleTxBatch (no overwrites) and the six-blob cap.
    let big = 1 << 20;
    for (nf, none, all) in [
        (1u8, 1024, 1024),
        (2, 1024, 1024),
        (5, 1024, 792),
        (6, 992, 664),
        (8, 750, 501),
        (12, 504, 336),
        (16, 379, 253),
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
    assert!(max_votes_for_cap(16, 0, 0, TX_BLOB_CAP) > 379);
    assert_eq!(max_votes_for_cap(2, 0, big, 32), MAX_BATCH_SIZE);
    assert_eq!(blob_count(0, 0, 1), 1);
    assert_eq!(blob_count(126, 126, 16), 1);
    assert_eq!(blob_count(1, 127, 16), 2);
    assert_eq!(blob_count(512, 1024, 16), 9);
    assert_eq!(blob_count(1024, 2048, 16), 17);
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

// At most as many vote ids as updates, as in every guest-accepted batch.
fn arb_transition() -> impl Strategy<Value = TransitionData> {
    (1u8..=16, 0usize..30).prop_flat_map(|(nf, u)| {
        (
            prop::collection::btree_set((1u64 << 63)..=u64::MAX, 0..=u),
            prop::collection::btree_map(0x10u64..(1 << 63), arb_ballot(nf), u),
        )
            .prop_map(move |(vids, ups)| TransitionData {
                vote_ids: vids.into_iter().collect(),
                updates: ups.into_iter().collect(),
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
