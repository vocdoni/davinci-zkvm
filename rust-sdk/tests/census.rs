//! Keccak lean-IMT, census leaves, slot keys, CSP attestations and vote-id
//! signatures against lean-imt-go / go-ethereum vectors.

mod common;

use common::*;
use davinci_zkvm_sdk::census::*;
use davinci_zkvm_sdk::crypto::field::fr_to_be;
use k256::ecdsa::SigningKey;

/// BN254 scalar field modulus, big-endian.
const BN254_R: Node = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

fn node(v: &serde_json::Value) -> Node {
    node_from_hex(s(v)).unwrap()
}

fn nodes(v: &serde_json::Value) -> Vec<Node> {
    v.as_array().unwrap().iter().map(node).collect()
}

/// Leaf `i` of a test tree: below 2^248 like every census leaf.
fn test_leaf(i: u64) -> Node {
    let mut n = [0u8; 32];
    n[24..].copy_from_slice(&(i * 31 + 7).to_be_bytes());
    n
}

#[test]
fn keccak_node_matches_solidity() {
    // cast keccak $(cast abi-encode "f(uint256,uint256)" 1 2)
    let (mut one, mut two) = ([0u8; 32], [0u8; 32]);
    one[31] = 1;
    two[31] = 2;
    assert_eq!(
        node_to_hex(&hash2(&one, &two)),
        "0xe90b7bceb6e7df5418fb78d8ee546e97c83a08bbccc01a0644d599ccd2a7c2e0"
    );
    assert_eq!(
        node_to_hex(&hash2(&[0; 32], &[0; 32])),
        "0xad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5"
    );
}

#[test]
fn node_hex_is_strict() {
    let n = node_from_hex(&format!("0x{}", "ab".repeat(32))).unwrap();
    assert_eq!(n, [0xab; 32]);
    assert_eq!(node_from_hex(&format!("0x{}", "AB".repeat(32))).unwrap(), n);
    assert_eq!(node_to_hex(&n), format!("0x{}", "ab".repeat(32)));
    for bad in [
        "ab".repeat(32),                  // no prefix
        format!("0x{}", "ab".repeat(31)), // short
        format!("0x0{}", "ab".repeat(32)),
        format!("0X{}", "ab".repeat(32)),
        format!("0x{}zz", "ab".repeat(31)),
        "1234".into(), // decimal
        "".into(),
    ] {
        assert!(node_from_hex(&bad).is_err(), "{bad}");
    }
}

#[test]
fn lean_imt_roots_and_proofs_match_go() {
    let v = load("leanimt.json");
    let leaves = nodes(&v["leaves"]);
    let mut tree = LeanImt::new();
    assert_eq!(tree.root(), [0u8; 32]);
    assert!(tree.proof(0).is_err());
    let (mut checked, mut above) = (0, 0);
    for t in v["trees"].as_array().unwrap() {
        let size = u64v(&t["size"]) as usize;
        while tree.len() < size {
            tree.insert(leaves[tree.len()]);
        }
        let root = node(&t["root"]);
        assert_eq!(tree.root(), root, "size {size}");
        if size == 1 {
            assert_eq!(root, leaves[0], "single-member root is the leaf");
        }
        // Compared as big-endian integers.
        above += usize::from(root >= BN254_R);
        let bulk = LeanImt::from_leaves(leaves[..size].to_vec());
        assert_eq!(bulk.root(), root, "from_leaves size {size}");
        let Some(proofs) = t.get("proofs").and_then(|p| p.as_array()) else {
            continue;
        };
        for p in proofs {
            let idx = u64v(&p["index"]) as usize;
            let got = tree.proof(idx).unwrap();
            assert_eq!(bulk.proof(idx).unwrap(), got);
            let want = CensusProof {
                root,
                leaf: node(&p["leaf"]),
                path_bits: u64v(&p["path_bits"]),
                siblings: nodes(&p["siblings"]),
            };
            assert_eq!(got, want, "size {size} index {idx}");
            assert!(verify_census_proof(&got));
            checked += 1;
        }
        assert!(tree.proof(size).is_err());
    }
    assert_eq!(checked, 1 + 2 + 3 + 5 + 8 + 13 + 33 + 5);
    // Roots above the BN254 modulus must round-trip untouched.
    assert!(above > 20, "only {above} roots above the modulus");
}

#[test]
fn from_leaves_equals_insert_loop() {
    let sizes: Vec<usize> = (0..=40).chain([1000, 4097]).collect();
    let all: Vec<Node> = (0..4097u64).map(test_leaf).collect();
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
        tree.insert(test_leaf(i + 100));
    }
    let p = tree.proof(6).unwrap();
    assert!(verify_census_proof(&p));
    // Path bits above the proof length.
    let high = CensusProof {
        path_bits: p.path_bits | (1 << p.siblings.len()),
        ..p.clone()
    };
    assert!(!verify_census_proof(&high));
    // Wrong leaf, sibling or root.
    let mut leaf = p.clone();
    leaf.leaf[31] ^= 1;
    assert!(!verify_census_proof(&leaf));
    let mut sib = p.clone();
    sib.siblings[0][31] ^= 1;
    assert!(!verify_census_proof(&sib));
    let mut root = p.clone();
    root.root[0] ^= 0x80;
    assert!(!verify_census_proof(&root));
    // An internal node presented as a leaf at a shorter path: it reaches the
    // root, but it is not below 2^248 (the guest's check 3A.6).
    let mut n = [0u8; 32];
    n[0] = 0xff;
    let short = CensusProof {
        root: hash2(&n, &test_leaf(1)),
        leaf: n,
        path_bits: 0,
        siblings: vec![test_leaf(1)],
    };
    assert!(!verify_census_proof(&short));
    let mut ok = short.clone();
    ok.leaf[0] = 0;
    ok.root = hash2(&ok.leaf, &test_leaf(1));
    assert!(verify_census_proof(&ok));
    // More than 61 siblings, even when the walk would reach the root.
    let mut node = test_leaf(5);
    let mut siblings = Vec::new();
    for i in 0..62u64 {
        let s = test_leaf(i);
        node = hash2(&node, &s);
        siblings.push(s);
    }
    let deep = CensusProof {
        root: node,
        leaf: test_leaf(5),
        path_bits: 0,
        siblings,
    };
    assert!(!verify_census_proof(&deep));
    let mut ok61 = deep.clone();
    ok61.siblings.pop();
    ok61.root = ok61.siblings.iter().fold(test_leaf(5), |n, s| hash2(&n, s));
    assert!(verify_census_proof(&ok61));
}

#[test]
fn census_leaves_and_slots_match_go() {
    let v = load("census.json");
    for l in v["leaves"].as_array().unwrap() {
        let w: u128 = s(&l["weight"]).parse().unwrap();
        let leaf = census_leaf(&hex20(&l["address"]), w).unwrap();
        assert_eq!(leaf, fr_to_be(&fr(&l["leaf"])));
        assert_eq!(leaf[0], 0, "below 2^248");
        assert_eq!(census_leaf_weight(&leaf), w);
        assert_eq!(census_leaf_address(&leaf), hex20(&l["address"]));
        // Bits above 247 are not part of the address the guest binds.
        let mut junk = leaf;
        junk[0] = 1;
        assert_eq!(census_leaf_address(&junk), hex20(&l["address"]));
    }
    assert!(census_leaf(&[0xff; 20], 1u128 << 88).is_err());
    assert!(census_leaf(&[0; 20], u128::MAX).is_err());
    assert_eq!(slot_key_csp(0).unwrap(), 0x10);
    assert_eq!(
        slot_key_csp(0x7fff_ffff_ffff_ffef).unwrap(),
        0x7fff_ffff_ffff_ffff
    );
    assert!(slot_key_csp(0x7fff_ffff_ffff_fff0).is_err());
    assert!(slot_key_csp(u64::MAX).is_err());
}

#[test]
fn address_slots_match_go() {
    let v = load("slot.json");
    assert_eq!(s(&v["tag"]).as_bytes(), SLOT_TAG);
    let slots = v["slots"].as_array().unwrap();
    assert_eq!(slots.len(), 20);
    for c in slots {
        let slot = slot_key_address(&hex20(&c["address"]));
        assert_eq!(slot, u64v(&c["slot"]), "{}", s(&c["address"]));
        assert!((0x10..=0x7fff_ffff_ffff_ffff).contains(&slot));
    }
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
