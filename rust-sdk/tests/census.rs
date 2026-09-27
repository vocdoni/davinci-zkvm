//! lean-IMT, census leaves, slot keys, CSP attestations and vote-id
//! signatures against lean-imt-go / go-ethereum vectors.

mod common;

use common::*;
use davinci_zkvm_sdk::census::*;
use davinci_zkvm_sdk::crypto::field::Fr;
use k256::ecdsa::SigningKey;

#[test]
fn lean_imt_roots_and_proofs_match_go() {
    let v = load("leanimt.json");
    let leaves = frs(&v["leaves"]);
    let mut tree = LeanImt::new();
    assert_eq!(tree.root(), Fr::from(0u64));
    assert!(tree.proof(0).is_err());
    let mut checked = 0;
    for t in v["trees"].as_array().unwrap() {
        let size = u64v(&t["size"]) as usize;
        tree.insert(leaves[size - 1]);
        assert_eq!(tree.len(), size);
        assert_eq!(tree.root(), fr(&t["root"]), "size {size}");
        let bulk = LeanImt::from_leaves(leaves[..size].to_vec());
        assert_eq!(bulk.root(), fr(&t["root"]), "from_leaves size {size}");
        let Some(proofs) = t.get("proofs").and_then(|p| p.as_array()) else {
            continue;
        };
        for p in proofs {
            let idx = u64v(&p["index"]) as usize;
            let got = tree.proof(idx).unwrap();
            assert_eq!(bulk.proof(idx).unwrap(), got);
            let want = CensusProof {
                root: fr(&t["root"]),
                leaf: fr(&p["leaf"]),
                path_bits: u64v(&p["path_bits"]),
                siblings: frs(&p["siblings"]),
            };
            assert_eq!(got, want, "size {size} index {idx}");
            assert!(verify_census_proof(&got));
            assert_eq!(slot_key_merkle(&got).unwrap(), u64v(&p["slot"]));
            checked += 1;
        }
        assert!(tree.proof(size).is_err());
    }
    assert_eq!(checked, 1 + 2 + 3 + 5 + 8 + 13 + 33);
}

#[test]
fn from_leaves_equals_insert_loop() {
    let sizes: Vec<usize> = (0..=40).chain([1000, 4097]).collect();
    let all: Vec<Fr> = (0..4097u64).map(|i| Fr::from(i * 31 + 7)).collect();
    for n in sizes {
        let mut tree = LeanImt::new();
        for l in &all[..n] {
            tree.insert(*l);
        }
        let bulk = LeanImt::from_leaves(all[..n].to_vec());
        assert_eq!(bulk.root(), tree.root(), "size {n}");
        assert_eq!(
            (bulk.len(), bulk.depth()),
            (tree.len(), tree.depth()),
            "size {n}"
        );
        let sample: Vec<usize> = if n <= 40 {
            (0..n).collect()
        } else {
            vec![0, 1, n / 2, n - 2, n - 1]
        };
        for i in sample {
            let p = bulk.proof(i).unwrap();
            assert_eq!(p, tree.proof(i).unwrap(), "size {n} index {i}");
            assert!(verify_census_proof(&p));
        }
        assert!(bulk.proof(n).is_err());
    }
    // Inserting after a bulk build continues the same tree.
    let mut bulk = LeanImt::from_leaves(all[..13].to_vec());
    bulk.insert(all[13]);
    assert_eq!(bulk.root(), LeanImt::from_leaves(all[..14].to_vec()).root());
}

#[test]
fn census_proof_guest_rules() {
    let mut tree = LeanImt::new();
    for i in 0..13u64 {
        tree.insert(Fr::from(i + 100));
    }
    let p = tree.proof(6).unwrap();
    assert!(verify_census_proof(&p));
    // Path bits above the proof length.
    let high = CensusProof {
        path_bits: p.path_bits | (1 << p.siblings.len()),
        ..p.clone()
    };
    assert!(!verify_census_proof(&high));
    assert!(slot_key_merkle(&high).is_err());
    // Wrong leaf, sibling or root.
    assert!(!verify_census_proof(&CensusProof {
        leaf: p.leaf + Fr::from(1u64),
        ..p.clone()
    }));
    let mut sib = p.clone();
    sib.siblings[0] += Fr::from(1u64);
    assert!(!verify_census_proof(&sib));
    // More than 61 siblings, even when the walk would reach the root.
    let mut node = Fr::from(5u64);
    let mut siblings = Vec::new();
    for i in 0..62u64 {
        let s = Fr::from(i);
        node = davinci_zkvm_sdk::crypto::poseidon::poseidon(&[node, s]).unwrap();
        siblings.push(s);
    }
    let deep = CensusProof {
        root: node,
        leaf: Fr::from(5u64),
        path_bits: 0,
        siblings,
    };
    assert!(!verify_census_proof(&deep));
    assert!(slot_key_merkle(&deep).is_err());
    let mut ok61 = deep.clone();
    ok61.siblings.pop();
    ok61.root = {
        let mut n = Fr::from(5u64);
        for s in &ok61.siblings {
            n = davinci_zkvm_sdk::crypto::poseidon::poseidon(&[n, *s]).unwrap();
        }
        n
    };
    assert!(verify_census_proof(&ok61));
    assert_eq!(slot_key_merkle(&ok61).unwrap(), 0x10 + (1u64 << 61));
}

#[test]
fn census_leaves_and_slots_match_go() {
    let v = load("census.json");
    for l in v["leaves"].as_array().unwrap() {
        let w: u128 = s(&l["weight"]).parse().unwrap();
        let leaf = census_leaf(&hex20(&l["address"]), w).unwrap();
        assert_eq!(leaf, fr(&l["leaf"]));
        assert_eq!(census_leaf_weight(&leaf), w);
    }
    assert!(census_leaf(&[0xff; 20], 1u128 << 88).is_err());
    assert!(census_leaf(&[0; 20], u128::MAX).is_err());
    for sv in v["slots"].as_array().unwrap() {
        let depth = u64v(&sv["depth"]) as usize;
        let p = CensusProof {
            root: Fr::from(0u64),
            leaf: Fr::from(0u64),
            path_bits: u64v(&sv["path_bits"]),
            siblings: vec![Fr::from(0u64); depth],
        };
        assert_eq!(slot_key_merkle(&p).unwrap(), u64v(&sv["slot"]));
    }
    assert_eq!(slot_key_csp(0).unwrap(), 0x10);
    assert_eq!(
        slot_key_csp(0x7fff_ffff_ffff_ffef).unwrap(),
        0x7fff_ffff_ffff_ffff
    );
    assert!(slot_key_csp(0x7fff_ffff_ffff_fff0).is_err());
    assert!(slot_key_csp(u64::MAX).is_err());
}

#[test]
fn csp_signatures_match_geth() {
    let v = load("census.json");
    let sk = SigningKey::from_slice(&hex32(&v["csp_key"])).unwrap();
    let csp_addr = hex20(&v["csp_address"]);
    assert_eq!(eth_address(sk.verifying_key()), csp_addr);
    for c in v["csp"].as_array().unwrap() {
        let pid = fr(&c["process_id"]);
        let addr = hex20(&c["address"]);
        let w: u128 = s(&c["weight"]).parse().unwrap();
        let idx = u64v(&c["index"]);
        assert_eq!(
            hex::encode(csp_message_hash(&pid, &addr, w, idx)),
            s(&c["hash"])
        );
        let p = csp_sign(&sk, &pid, &addr, w, idx);
        assert_eq!(hex::encode(p.r), s(&c["r"]));
        assert_eq!(hex::encode(p.s), s(&c["s"]));
        assert_eq!(p.recid as u64, u64v(&c["recid"]));
        assert_eq!(csp_recover(&pid, &p).unwrap(), csp_addr);
        assert_eq!(slot_key_csp(idx).unwrap(), u64v(&c["slot"]));
        // Any signed field changes the recovered key.
        let other = CspProof {
            index: idx + 1,
            ..p.clone()
        };
        assert_ne!(csp_recover(&pid, &other).ok(), Some(csp_addr));
        assert!(csp_recover(
            &pid,
            &CspProof {
                recid: 2,
                ..p.clone()
            }
        )
        .is_err());
    }
}

const SECP_N: &str = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

fn high_s(s: &[u8; 32]) -> [u8; 32] {
    // n - s, big-endian.
    let n = hex::decode(SECP_N).unwrap();
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = n[i] as i16 - s[i] as i16 - borrow;
        borrow = (d < 0) as i16;
        out[i] = (d + 256 * borrow) as u8;
    }
    out
}

#[test]
fn vote_id_signatures_match_geth() {
    let v = load("voteid_sig.json");
    let sk = SigningKey::from_slice(&hex32(&v["key"])).unwrap();
    let addr = hex20(&v["address"]);
    for c in v["sigs"].as_array().unwrap() {
        let vid = u64v(&c["vote_id"]);
        let sig = vote_id_sign(&sk, vid);
        assert_eq!(hex::encode(sig.r), s(&c["r"]));
        assert_eq!(hex::encode(sig.s), s(&c["s"]));
        assert_eq!(sig.v as u64, u64v(&c["v"]));
        assert_eq!(vote_id_recover(vid, &sig).unwrap(), addr);
        assert_eq!(
            vote_id_recover(
                vid,
                &EcdsaSignature {
                    v: sig.v + 27,
                    ..sig
                }
            )
            .unwrap(),
            addr
        );
        assert_ne!(vote_id_recover(vid ^ 1, &sig).ok(), Some(addr));
        for v in [2u8, 3, 26, 29, 255] {
            assert!(
                vote_id_recover(vid, &EcdsaSignature { v, ..sig }).is_err(),
                "v = {v}"
            );
        }
        // The malleated twin (n - s, flipped parity) recovers the same key but is refused.
        let twin = EcdsaSignature {
            s: high_s(&sig.s),
            v: sig.v ^ 1,
            ..sig
        };
        assert!(vote_id_recover(vid, &twin).is_err());
        assert!(vote_id_recover(vid, &EcdsaSignature { r: [0; 32], ..sig }).is_err());
    }
}
