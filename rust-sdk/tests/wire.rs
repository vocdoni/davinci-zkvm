//! Wire formats: the SDK JSON against go-sdk output and the service's own
//! parsers (input-gen), the byte-order helpers, and recorded job publics.

mod common;

use common::*;
use davinci_zkvm_input_gen as ig;
use davinci_zkvm_sdk::ballot::Ballot;
use davinci_zkvm_sdk::crypto::babyjubjub::Point;
use davinci_zkvm_sdk::crypto::chaum_pedersen::{verify_decryption, DecryptionProof};
use davinci_zkvm_sdk::crypto::elgamal::{encrypt, keygen};
use davinci_zkvm_sdk::crypto::field::{fr_from_le, fr_to_u256, u256_from_le, Fr};
use davinci_zkvm_sdk::publics::*;
use davinci_zkvm_sdk::release::*;
use davinci_zkvm_sdk::results::build_results_request;
use davinci_zkvm_sdk::types::enc::*;
use davinci_zkvm_sdk::types::*;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde_json::Value;

fn limbs(x: &Fr) -> [u64; 4] {
    fr_to_u256(x).0
}

#[test]
fn prove_request_matches_go_json() {
    let go = load("wire_prove.json");
    let req: ProveRequest = serde_json::from_value(go.clone()).unwrap();
    let ours = serde_json::to_value(&req).unwrap();
    assert_eq!(ours, go, "SDK re-encoding differs from go-sdk JSON");

    // The GROTH16B block exactly as the service builds it.
    let vk: ig::SnarkJsVk = serde_json::from_value(ours["vk"].clone()).unwrap();
    let proofs: Vec<ig::SnarkJsProof> = serde_json::from_value(ours["proofs"].clone()).unwrap();
    let sigs: Vec<ig::EcdsaSig> = serde_json::from_value(ours["sigs"].clone()).unwrap();
    let pubs: Vec<Vec<String>> = serde_json::from_value(ours["public_inputs"].clone()).unwrap();
    let bin = ig::generate_input(&vk, &proofs, &pubs, &sigs).unwrap();
    assert!(!bin.is_empty());
    assert_eq!(sigs[0].signature_v, req.sigs[0].signature_v);

    // Every other field parses with the service's hex rules.
    let st = req.state.as_ref().unwrap();
    for h in [&st.process_id, &st.old_state_root, &st.new_state_root] {
        ig::hex32_to_smt_fr(h).unwrap();
    }
    let entries = st
        .vote_id_smt
        .iter()
        .chain(&st.ballot_smt)
        .chain(&st.refresh_smt)
        .chain(&st.process_smt);
    for e in entries.chain(st.results_smt.iter()) {
        for h in [
            &e.old_root,
            &e.new_root,
            &e.old_key,
            &e.old_value,
            &e.new_key,
            &e.new_value,
        ] {
            ig::hex32_to_smt_fr(h).unwrap();
        }
        for s in &e.siblings {
            ig::hex32_to_smt_fr(s).unwrap();
        }
    }
    let bp = st.ballot_proofs.as_ref().unwrap();
    for c in bp
        .old_results
        .iter()
        .chain(bp.voter_ballots.iter().flatten())
        .chain(bp.refreshed_ballots.iter().flatten())
    {
        ig::be_hex32_to_fr_le(c).unwrap();
    }
    for c in req.census_proofs.as_ref().unwrap() {
        ig::census_proof_from_hex(&c.root, &c.leaf, c.index, &c.siblings).unwrap();
    }
    let csp = &req.csp_data.as_ref().unwrap().proofs[0];
    ig::address_hex_to_fr_le(&csp.voter_address).unwrap();
    ig::be_hex32_to_fr_le(&csp.weight).unwrap();
    let re = req.reencryption.as_ref().unwrap();
    for h in [&re.encryption_key_x, &re.encryption_key_y, &re.seed] {
        ig::be_hex32_to_fr_le(h).unwrap();
    }
    let kzg = req.kzg.as_ref().unwrap();
    for c in &kzg.commitments {
        assert_eq!(hex::decode(c.trim_start_matches("0x")).unwrap().len(), 48);
    }
}

#[test]
fn debug_redacts_the_reencryption_seed() {
    let req: ProveRequest = serde_json::from_value(load("wire_prove.json")).unwrap();
    let re = req.reencryption.clone().unwrap();
    let seed = re.seed.trim_start_matches("0x").to_string();
    let dbg = format!("{req:?}");
    assert!(!dbg.contains(&seed), "seed leaked in Debug");
    assert!(dbg.contains("<redacted>"));
    assert!(dbg.contains(&re.encryption_key_x));
    assert!(!format!("{re:#?}").contains(&seed));
}

#[test]
fn optional_blocks_are_omitted_not_null() {
    let go = load("wire_prove.json");
    let mut req: ProveRequest = serde_json::from_value(go).unwrap();
    req.census_proofs = None;
    req.csp_data = None;
    req.kzg = None;
    req.output = None;
    let st = req.state.as_mut().unwrap();
    st.refresh_smt.clear();
    st.results_smt = None;
    let v = serde_json::to_value(&req).unwrap();
    for k in ["census_proofs", "csp_data", "kzg", "output"] {
        assert!(v.get(k).is_none(), "{k} emitted");
    }
    assert!(v["state"].get("refresh_smt").is_none());
    assert!(v["state"].get("results_smt").is_none());
    // Go's nil slices (null) are accepted on input.
    let mut go = load("wire_prove.json");
    go["state"]["refresh_smt"] = Value::Null;
    go["state"]["ballot_proofs"]["overwritten_ballots"] = Value::Null;
    let r: ProveRequest = serde_json::from_value(go).unwrap();
    assert!(r.state.unwrap().refresh_smt.is_empty());
}

#[test]
fn encodings_agree_with_the_service_parsers() {
    // SMT key: u64 LE in the low 8 bytes.
    assert_eq!(
        ig::hex32_to_smt_fr(&key_hex(0x10)).unwrap(),
        [0x10, 0, 0, 0]
    );
    assert_eq!(
        ig::hex32_to_smt_fr(&key_hex(u64::MAX)).unwrap(),
        [u64::MAX, 0, 0, 0]
    );
    // Digest leaf value = int_be(digest), what the guest's digest_to_fr yields.
    let digest: [u8; 32] = core::array::from_fn(|i| i as u8 + 1);
    let want = [
        u64::from_be_bytes(digest[24..32].try_into().unwrap()),
        u64::from_be_bytes(digest[16..24].try_into().unwrap()),
        u64::from_be_bytes(digest[8..16].try_into().unwrap()),
        u64::from_be_bytes(digest[0..8].try_into().unwrap()),
    ];
    assert_eq!(ig::hex32_to_smt_fr(&leaf_value_hex(&digest)).unwrap(), want);
    // STATETX (LE) and KZG (BE) must carry the same pid and root integers.
    let pid = Fr::from(0x1234_5678_9abc_def0u64) * Fr::from(u64::MAX);
    assert_eq!(
        ig::hex32_to_smt_fr(&fr_le_hex(&pid)).unwrap(),
        ig::be_hex32_to_fr_le(&fr_be_hex(&pid)).unwrap()
    );
    assert_eq!(
        ig::be_hex32_to_fr_le(&fr_be_hex(&pid)).unwrap(),
        limbs(&pid)
    );
    let root: [u8; 32] = core::array::from_fn(|i| (i * 7 + 3) as u8);
    assert_eq!(
        ig::hex32_to_smt_fr(&le_hex(&root)).unwrap(),
        ig::be_hex32_to_fr_le(&root_be_hex(&root)).unwrap()
    );
    // Ballot coordinates are BE.
    let g = Point::generator();
    let pj = point_json(&g);
    assert_eq!(ig::be_hex32_to_fr_le(&pj.x).unwrap(), limbs(&g.x));
    assert_eq!(
        ballot_be_hex(&Ballot::identity())[1],
        be_hex(&{
            let mut b = [0u8; 32];
            b[31] = 1;
            b
        })
    );
}

#[test]
fn batch_publics_from_recorded_job() {
    let regs = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/publics_batch.bin"
    ))
    .unwrap();
    let p = BatchPublics::parse(&regs).unwrap();
    assert!(p.ok && p.passed());
    assert_eq!(p.fail_mask, 0);
    assert_eq!(
        (p.voters, p.overwrites, p.n_blobs, p.occupied_before),
        (3, 3, 1, 24)
    );
    assert_eq!((p.nproofs, p.n_public, p.log_n), (3, 3, 1));
    let reg = |i: usize| u32::from_le_bytes(regs[4 * i..4 * i + 4].try_into().unwrap());
    assert_eq!(
        (p.nproofs, p.n_public, p.log_n),
        (reg(43), reg(44), reg(45))
    );
    assert_ne!(p.root_before, p.root_after);
    // Register r lives at bytes 4r..4r+4 (go-sdk Output* indices).
    assert_eq!(p.root_before[..], regs[8..40]);
    assert_eq!(p.root_after[..], regs[40..72]);
    assert_eq!(p.census_root[..], regs[80..112]);
    assert_eq!(p.blobs_digest[..], regs[112..144]);

    let snark = load("snark_batch.json");
    let pv = hex::decode(s(&snark["public_values"]).trim_start_matches("0x")).unwrap();
    assert_eq!(pv.len(), 512);
    assert_eq!(BatchPublics::from_public_values(&pv).unwrap(), p);
    assert_eq!(
        s(&snark["program_vk"]),
        format!("0x{}", hex::encode(BATCH_PROGRAM_VK))
    );
    assert_eq!(
        s(&snark["root_c_vadcop_final"]),
        format!("0x{}", hex::encode(ROOT_C_VADCOP_FINAL))
    );

    let mut bad = pv.clone();
    bad[4] = 1; // high half of word 0
    assert!(BatchPublics::from_public_values(&bad).is_err());
    assert!(BatchPublics::parse(&regs[..100]).is_err());
    assert!(BatchPublics::parse(&regs[..183]).is_err());
    assert!(BatchPublics::from_public_values(&pv[..300]).is_err());

    assert!(fail_bits(0).is_empty());
    assert_eq!(
        fail_bits(1 << 17 | 1 << 24 | 1 << 31),
        vec!["reencryption", "refresh", "parse_error"]
    );
    assert_eq!(fail_bits(1 << 5), vec!["unknown"]);
    assert_eq!(results_fail_bits(1 << 4 | 1 << 2), vec!["incl_key", "cp"]);
}

#[test]
fn results_request_and_publics_from_gpu_job() {
    let fixture = load("results_request.json");
    let req: ResultsRequest = serde_json::from_value(fixture.clone()).unwrap();
    assert_eq!(serde_json::to_value(&req).unwrap(), fixture);
    let rj: ig::results::ResultsJson = serde_json::from_value(fixture).unwrap();
    assert_eq!(
        ig::results::build_results_input(&rj).unwrap().len(),
        ig::results::RESULTS_FRAME_LEN
    );

    // The SDK accepts the proofs the results guest accepted.
    let le = |h: &str| fr_from_le(&hex32(&Value::String(h.to_string()))).unwrap();
    let pk = Point {
        x: le(&req.enc_key_x),
        y: le(&req.enc_key_y),
    };
    let coords: Vec<Fr> = req.accumulator.iter().map(|h| le(h)).collect();
    let acc = Ballot::from_coords(&coords.try_into().unwrap()).unwrap();
    for (i, cp) in req.cp_proofs.iter().enumerate() {
        let p = DecryptionProof {
            a1: Point {
                x: le(&cp.a1x),
                y: le(&cp.a1y),
            },
            a2: Point {
                x: le(&cp.a2x),
                y: le(&cp.a2y),
            },
            z: u256_from_le(&hex32(&Value::String(cp.z.clone()))),
        };
        assert!(
            verify_decryption(&pk, &acc.0[i], req.results[i], &p),
            "cp {i}"
        );
        assert!(!verify_decryption(&pk, &acc.0[i], req.results[i] + 1, &p));
    }

    let regs = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/results_publics_gpu.bin"
    ))
    .unwrap();
    let emu = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/results_publics_emu.bin"
    ))
    .unwrap();
    let p = ResultsPublics::parse(&regs).unwrap();
    assert_eq!(p, ResultsPublics::parse(&emu).unwrap());
    assert!(p.passed());
    assert_eq!(p.cp_fail_index, u32::MAX);
    assert_eq!(hex::encode(p.state_root), req.state_root);
    assert_eq!(p.results.to_vec(), req.results);
    assert!(ResultsPublics::parse(&regs[..168]).is_err());
}

#[test]
fn build_results_request_roundtrip() {
    let mut rng = ChaCha20Rng::seed_from_u64(11);
    let (sk, pk) = keygen(&mut rng);
    let mut acc = Ballot::identity();
    let tally = [5u64, 0, 17, 1000];
    for (i, m) in tally.iter().enumerate() {
        let k1 = keygen(&mut rng).0;
        let k2 = keygen(&mut rng).0;
        acc.0[i] = encrypt(&pk, m / 2, &k1).add(&encrypt(&pk, m - m / 2, &k2));
    }
    let root = [7u8; 32];
    let sibs = vec![[1u8; 32], [2u8; 32]];
    let (req, results) =
        build_results_request(&root, &pk, &sibs, &acc, &sibs, &sk, 10_000, &mut rng).unwrap();
    assert_eq!(&results[..4], &tally);
    assert!(results[4..].iter().all(|r| *r == 0));
    assert_eq!(req.key_siblings.len(), 64);
    assert_eq!(req.key_siblings[1], hex::encode([2u8; 32]));
    assert_eq!(req.key_siblings[2], hex::encode([0u8; 32]));
    assert_eq!(req.state_root, hex::encode(root));
    assert!(!req.state_root.starts_with("0x"));
    let rj: ig::results::ResultsJson =
        serde_json::from_value(serde_json::to_value(&req).unwrap()).unwrap();
    assert_eq!(
        ig::results::build_results_input(&rj).unwrap().len(),
        ig::results::RESULTS_FRAME_LEN
    );
    // z is reduced below l, as the results guest requires.
    for cp in &req.cp_proofs {
        let z = u256_from_le(&hex32(&Value::String(cp.z.clone())));
        assert!(z < davinci_zkvm_sdk::crypto::babyjubjub::SUBGROUP_ORDER);
    }

    // Wrong key, out-of-range plaintext, too many siblings.
    let (sk2, _) = keygen(&mut rng);
    assert!(build_results_request(&root, &pk, &sibs, &acc, &sibs, &sk2, 10_000, &mut rng).is_err());
    assert!(build_results_request(&root, &pk, &sibs, &acc, &sibs, &sk, 999, &mut rng).is_err());
    let long = vec![[0u8; 32]; 65];
    assert!(build_results_request(&root, &pk, &long, &acc, &sibs, &sk, 10_000, &mut rng).is_err());
}

#[test]
fn release_pins() {
    assert_eq!(
        hex::encode(BATCH_PROGRAM_VK),
        "44ccdf5eb9cdf759d9ca784b76c50604cc458b2d7b9861b4bc4941ddf961f8a7"
    );
    assert_eq!(
        hex::encode(RESULTS_PROGRAM_VK),
        "ab98764a015f2685aad112cafee1c4721adac098a6fe5989a4e87b6b9eab71fb"
    );
    assert_eq!(
        hex::encode(ROOT_C_VADCOP_FINAL),
        "05006517b6ccde5da4d890587ba62845b5af8a307c00e87d4b9d05099b16dc80"
    );
    let embedded = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/assets/ballot_proof_vkey.json"
    ))
    .unwrap();
    assert_eq!(ballot_vk_json(), embedded);
    // go-sdk/chain/release.go pins the same batch and results vks.
    let go = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../go-sdk/chain/release.go"
    ))
    .unwrap();
    assert!(go.contains(&hex::encode(BATCH_PROGRAM_VK)));
    assert!(go.contains(&hex::encode(RESULTS_PROGRAM_VK)));
}

#[test]
fn job_ids_are_path_safe() {
    assert!(JobId::parse("74322da3-b48f-41c7-92f5-f5ca86bebec9").is_ok());
    for bad in ["", "../health", "a/b", "a?b", "a b", &"a".repeat(65)] {
        assert!(JobId::parse(bad).is_err(), "{bad:?}");
    }
    assert!(serde_json::from_str::<JobId>("\"../x\"").is_err());
}
