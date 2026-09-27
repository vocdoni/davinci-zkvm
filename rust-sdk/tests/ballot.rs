//! Ballots, ballot mode, leaf hashes, the re-encryption chain, vote ids,
//! inputs hash and Groth16 verification against the Go vectors.

mod common;

use common::*;
use davinci_zkvm_sdk::ballot::*;
use davinci_zkvm_sdk::crypto::field::{fr_from_be, fr_to_be, Fr};
use davinci_zkvm_sdk::groth16::BallotVerifier;
use davinci_zkvm_sdk::limits::*;
use davinci_zkvm_sdk::reenc::{reencrypt_ballot, ReencChain};
use davinci_zkvm_sdk::types::SnarkJsProof;
use serde_json::Value;

fn mode(v: &Value) -> BallotMode {
    serde_json::from_value(v.clone()).unwrap()
}

#[test]
fn limits_and_refresh_target() {
    assert_eq!(
        (
            MAX_BATCH_SIZE,
            MAX_REFRESH,
            NUM_FIELDS,
            SMT_LEVELS,
            MAX_BLOBS
        ),
        (1024, 2048, 16, 64, 32)
    );
    assert_eq!(
        (REFRESH_MIN, REFRESH_TAU, REFRESH_KAPPA, TX_BLOB_CAP),
        (16, 2, 1, 6)
    );
    assert_eq!((BALLOT_MIN, VOTE_ID_MIN), (0x10, 1 << 63));
    assert_eq!(refresh_target(1, 0), 16);
    assert_eq!(refresh_target(100, 10), 100);
    assert_eq!(refresh_target(100, 60), 120);
    assert_eq!(refresh_target(1024, 1024), 2048);
    assert_eq!(refresh_target(5000, 5000), 2048);
    // go-sdk RefreshTarget(n, w, occ)
    assert_eq!(required_refresh(10, 0, 0), 0);
    assert_eq!(required_refresh(10, 2, 5), 3);
    assert_eq!(required_refresh(10, 2, 1000), 16);
    assert_eq!(required_refresh(10, 20, 5), 0);
}

#[test]
fn ballot_mode_packing() {
    let v = load("ballot_mode.json");
    for m in v.as_array().unwrap() {
        let bm = mode(m);
        let packed = bm.pack().unwrap();
        assert_eq!(packed, fr(&m["packed"]));
        assert_eq!(BallotMode::unpack(&packed).unwrap(), bm);
    }
    let base = mode(&v[2]);
    assert!(BallotMode {
        group_size: base.num_fields + 1,
        ..base
    }
    .pack()
    .is_err());
    assert!(BallotMode {
        max_value: 1 << 48,
        ..base
    }
    .pack()
    .is_err());
    assert!(BallotMode {
        min_value_sum: 1 << 63,
        ..base
    }
    .pack()
    .is_err());
    let mut high = fr_to_be(&base.pack().unwrap());
    high[0] |= 0x01; // bit 248
    assert!(BallotMode::unpack(&fr_from_be(&high).unwrap()).is_err());
}

#[test]
fn ballot_encryption_matches_go() {
    let v = load("elgamal.json");
    let pk = point(&v["pk"]);
    for b in v["ballots"].as_array().unwrap() {
        let nf = u64v(&b["nf"]) as u8;
        let fields: Vec<u64> = b["fields"].as_array().unwrap().iter().map(u64v).collect();
        let got = encrypt_ballot(&pk, &fields, &fr(&b["k"]), nf);
        assert_eq!(got, ballot(&b["ballot"]), "nf = {nf}");
        assert!(got.is_padded_ok(nf));
        if nf < 16 {
            assert!(!got.is_padded_ok(nf - 1));
        }
    }
}

#[test]
fn leaf_hashes_match_go() {
    let v = load("hashes.json");
    for l in v["ballot_leaves"].as_array().unwrap() {
        assert_eq!(
            hex::encode(ballot_leaf_hash(&ballot(&l["ballot"]))),
            s(&l["hash"])
        );
    }
    assert_eq!(
        hex::encode(enc_key_hash(&point(&v["enc_key"]["pk"]))),
        s(&v["enc_key"]["hash"])
    );
    assert_eq!(
        hex::encode(ballot_leaf_hash(&Ballot::identity())),
        s(&v["identity_ballot"])
    );
    let d = [7u8; 32];
    let mut r = d;
    r.reverse();
    assert_eq!(leaf_value_bytes(&d), r);
}

#[test]
fn ballot_vk_hash_matches_go() {
    let v = load("hashes.json");
    let embedded = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/assets/ballot_proof_vkey.json"
    ))
    .unwrap();
    let ver = BallotVerifier::from_snarkjs_json(&embedded).unwrap();
    assert_eq!(hex::encode(ver.vk_hash()), s(&v["ballot_vk_leaf"]));
    let v1 = load("real_proof_v1.json");
    let ver1 = BallotVerifier::from_snarkjs_json(&v1["vk"].to_string()).unwrap();
    assert_eq!(hex::encode(ver1.vk_hash()), s(&v["ballot_vk_leaf_v1"]));
}

#[test]
fn genesis_config_leaves_match_go() {
    let v = load("genesis.json");
    let embedded = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/assets/ballot_proof_vkey.json"
    ))
    .unwrap();
    let vk_hash = BallotVerifier::from_snarkjs_json(&embedded)
        .unwrap()
        .vk_hash();
    let id_hash = ballot_leaf_hash(&Ballot::identity());
    for g in v.as_array().unwrap() {
        let leaves = &g["leaves"];
        let packed = mode(&g["ballot_mode"]).pack().unwrap();
        let mut le = fr_to_be(&packed);
        le.reverse();
        assert_eq!(hex::encode(le), s(&leaves["0x02"]));
        assert_eq!(
            hex::encode(leaf_value_bytes(&enc_key_hash(&point(&g["enc_key"])))),
            s(&leaves["0x03"])
        );
        assert_eq!(hex::encode(leaf_value_bytes(&id_hash)), s(&leaves["0x04"]));
        assert_eq!(hex::encode(leaf_value_bytes(&vk_hash)), s(&leaves["0x07"]));
        assert_eq!(hex::encode(vk_hash), s(&g["ballot_vk_hash"]));
    }
}

#[test]
fn reenc_chain_golden_vector() {
    let v = load("reenc.json");
    let mut seed = [0u8; 32];
    seed[31] = 1;
    // old_root integer 2: the raw (little-endian) root bytes are [2, 0, ...].
    let mut root = [0u8; 32];
    root[0] = 2;
    let mut chain = ReencChain::new(&seed, &root);
    for g in v["golden"].as_array().unwrap() {
        assert_eq!(
            hex::encode(davinci_zkvm_sdk::crypto::field::u256_to_be(
                &chain.next_scalar()
            )),
            s(g)
        );
    }
}

#[test]
fn reencrypt_ballots_match_go() {
    let v = load("reenc.json");
    for c in v["cases"].as_array().unwrap() {
        let seed = hex32(&c["seed"]);
        let root = hex32(&c["old_root"]);
        let pk = point(&c["pk"]);
        let nf = u64v(&c["nf"]) as u8;
        let mut probe = ReencChain::new(&seed, &root);
        for sc in c["scalars"].as_array().unwrap() {
            assert_eq!(probe.next_scalar(), u256(sc));
        }
        let mut chain = ReencChain::new(&seed, &root);
        let olds = c["ballots"].as_array().unwrap();
        let news = c["reencrypted"].as_array().unwrap();
        for (o, n) in olds.iter().zip(news) {
            let got = reencrypt_ballot(&ballot(o), &pk, nf, &mut chain);
            assert_eq!(got, ballot(n), "nf = {nf}");
            assert!(got.is_padded_ok(nf));
        }
    }
}

#[test]
fn inputs_hash_and_vote_id_match_go() {
    let v = load("ballots.json");
    for b in v.as_array().unwrap() {
        let pid = fr(&b["process_id"]);
        let address = address_to_fr(&hex20(&b["address"]));
        let k = fr(&b["k"]);
        let vid = vote_id(&pid, &address, &k);
        assert_eq!(vid, u64v(&b["vote_id"]));
        let bm = mode(&b["mode"]);
        let pk = point(&b["pk"]);
        let fields: Vec<u64> = b["fields"].as_array().unwrap().iter().map(u64v).collect();
        let bal = encrypt_ballot(&pk, &fields, &k, bm.num_fields);
        assert_eq!(bal, ballot(&b["ballot"]));
        let h = inputs_hash(&pid, &bm, &pk, &address, vid, &bal, &fr(&b["weight"])).unwrap();
        assert_eq!(h, fr(&b["inputs_hash"]));
        // The same 71 inputs the circuit hashes.
        let ins = frs(&b["inputs"]);
        assert_eq!(ins.len(), 71);
        assert_eq!(
            davinci_zkvm_sdk::crypto::poseidon::multi_poseidon(&ins).unwrap(),
            h
        );
    }
}

fn real_proof(name: &str) -> (Value, BallotVerifier, SnarkJsProof, [Fr; 3]) {
    let v = load(name);
    let ver = BallotVerifier::from_snarkjs_json(&v["vk"].to_string()).unwrap();
    let proof: SnarkJsProof = serde_json::from_value(v["proof"].clone()).unwrap();
    let pubs: [Fr; 3] = frs(&v["public_signals"]).try_into().unwrap();
    (v, ver, proof, pubs)
}

#[test]
fn real_proof_verifies_with_embedded_vk() {
    let (v, ver, proof, pubs) = real_proof("real_proof.json");
    let embedded = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/assets/ballot_proof_vkey.json"
    ))
    .unwrap();
    assert_eq!(
        ver.vk_hash(),
        BallotVerifier::from_snarkjs_json(&embedded)
            .unwrap()
            .vk_hash()
    );
    assert_eq!(proof.curve, "bn128"); // defaulted: rapidsnark omits it
    assert!(ver.verify(&proof, &pubs));
    for i in 0..3 {
        let mut bad = pubs;
        bad[i] += Fr::from(1u64);
        assert!(!ver.verify(&proof, &bad), "public input {i} changed");
    }
    let mut bad = proof.clone();
    bad.pi_a[0] = "1".into();
    assert!(!ver.verify(&bad, &pubs));
    let mut bad = proof.clone();
    bad.protocol = "plonk".into();
    assert!(!ver.verify(&bad, &pubs));
    let mut bad = proof.clone();
    bad.pi_c[2] = "0".into(); // identity C
    assert!(!ver.verify(&bad, &pubs));
    // The public signals are exactly what the SDK recomputes.
    let b = &v["ballot"];
    let pid = fr(&b["process_id"]);
    let address = address_to_fr(&hex20(&b["address"]));
    let vid = vote_id(&pid, &address, &fr(&b["k"]));
    let bm = mode(&b["mode"]);
    let pk = point(&b["pk"]);
    let h = inputs_hash(
        &pid,
        &bm,
        &pk,
        &address,
        vid,
        &ballot(&b["ballot"]),
        &fr(&b["weight"]),
    )
    .unwrap();
    assert_eq!(pubs, [address, Fr::from(vid), h]);
}

#[test]
fn real_proof_v1_verifies_only_with_its_vk() {
    let (_, ver, proof, pubs) = real_proof("real_proof_v1.json");
    assert!(ver.verify(&proof, &pubs));
    let embedded = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/assets/ballot_proof_vkey.json"
    ))
    .unwrap();
    assert!(!BallotVerifier::from_snarkjs_json(&embedded)
        .unwrap()
        .verify(&proof, &pubs));
}

#[test]
fn verifier_rejects_bad_vks() {
    let (v, ..) = real_proof("real_proof.json");
    let mut vk = v["vk"].clone();
    vk["IC"].as_array_mut().unwrap().pop();
    assert!(BallotVerifier::from_snarkjs_json(&vk.to_string()).is_err());
    let mut vk = v["vk"].clone();
    vk["vk_alpha_1"][0] = "5".into();
    assert!(BallotVerifier::from_snarkjs_json(&vk.to_string()).is_err());
    assert!(BallotVerifier::from_snarkjs_json("{}").is_err());
}

#[test]
fn ballot_arithmetic_and_serde() {
    let v = load("elgamal.json");
    let b = ballot(&v["ballots"][1]["ballot"]);
    assert_eq!(b.add(&Ballot::identity()), b);
    assert_eq!(b.add(&b).sub(&b), b);
    assert_eq!(b.sub(&b), Ballot::identity());
    let json = serde_json::to_string(&b).unwrap();
    assert_eq!(serde_json::from_str::<Ballot>(&json).unwrap(), b);
    // Off-curve coordinates do not deserialize.
    let mut val: Value = serde_json::from_str(&json).unwrap();
    val[0]["c1"]["y"] = "0x0000000000000000000000000000000000000000000000000000000000000005".into();
    assert!(serde_json::from_value::<Ballot>(val).is_err());
}
