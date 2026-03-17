#![allow(dead_code)]

use davinci_stark::{
    prove_full_ballot,
    trace::{BallotInputs, BallotMode},
};
use ecgfp5::{curve::Point, scalar::Scalar};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;

use davinci_zkvm_input_gen::{
    CspBlockData, CspEntryData, EcdsaSig, Ecgfp5BallotProofData, Ecgfp5CiphertextData,
    Ecgfp5ReencEntryData, SmtEntry, StateData, generate_stark_input, stark_types::StarkProofBundle,
    write_csp_block, write_reenc_block_g5, write_state_block,
};

#[path = "../src/bn254_fr.rs"]
mod bn254_fr;
#[path = "../src/ecgfp5_verify.rs"]
mod ecgfp5_verify;
#[path = "../src/binding.rs"]
mod guest_binding;
#[path = "../src/davinci_stark.rs"]
mod guest_davinci_stark;
#[path = "../src/ecgfp5_verify.rs"]
mod guest_ecgfp5_verify;
#[path = "../src/results.rs"]
mod guest_results;
#[path = "../src/hash.rs"]
mod hash;
#[path = "../src/io.rs"]
mod io;
#[path = "../src/types.rs"]
mod types;

fn zero_sig(vote_id: u64) -> EcdsaSig {
    EcdsaSig {
        public_key_x: format!("0x{:064x}", 0),
        public_key_y: format!("0x{:064x}", 0),
        signature_r: format!("0x{:064x}", 0),
        signature_s: format!("0x{:064x}", 0),
        vote_id,
        address: "0".to_string(),
        private_key: String::new(),
        signature_v: 0,
    }
}

fn sample_inputs() -> BallotInputs {
    let sk = Scalar([12345, 0, 0, 0, 0]);
    BallotInputs {
        k: Scalar([42, 0, 0, 0, 0]),
        fields: [
            Scalar([1, 0, 0, 0, 0]),
            Scalar([2, 0, 0, 0, 0]),
            Scalar([3, 0, 0, 0, 0]),
            Scalar([4, 0, 0, 0, 0]),
            Scalar([5, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
            Scalar([0, 0, 0, 0, 0]),
        ],
        pk: Point::mulgen(sk),
        process_id: [
            Goldilocks::from_u64(1001),
            Goldilocks::ZERO,
            Goldilocks::ZERO,
            Goldilocks::ZERO,
        ],
        address: [
            Goldilocks::from_u64(0xDEADBEEF),
            Goldilocks::ZERO,
            Goldilocks::ZERO,
            Goldilocks::ZERO,
        ],
        weight: Goldilocks::from_u64(1),
        packed_ballot_mode: BallotMode {
            num_fields: 5,
            group_size: 1,
            unique_values: 0,
            cost_from_weight: 0,
            cost_exponent: 2,
            max_value: 16,
            min_value: 0,
            max_value_sum: 1125,
            min_value_sum: 5,
        }
        .pack(),
    }
}

fn point_raw(p: Point) -> [u64; 5] {
    let enc = p.encode().encode();
    let mut out = [0u64; 5];
    for i in 0..5 {
        out[i] = u64::from_le_bytes(enc[i * 8..(i + 1) * 8].try_into().unwrap());
    }
    out
}

fn bundle_ciphertexts(
    bundle: &davinci_zkvm_input_gen::stark_types::StarkPublicValues,
) -> [types::Ecgfp5Ciphertext; 8] {
    let mut encs = [[0u64; 5]; 16];
    let base = 33;
    for i in 0..16 {
        encs[i].copy_from_slice(&bundle.inputs_preimage[base + i * 5..base + (i + 1) * 5]);
    }
    let mut out = [types::Ecgfp5Ciphertext::default(); 8];
    for i in 0..8 {
        out[i] = types::Ecgfp5Ciphertext {
            c1: encs[i * 2],
            c2: encs[i * 2 + 1],
        };
    }
    out
}

fn zero_ballot() -> [types::Ecgfp5Ciphertext; 8] {
    [types::Ecgfp5Ciphertext::default(); 8]
}

fn packed_mode_raw() -> [u64; 4] {
    let packed = sample_inputs().packed_ballot_mode;
    [
        packed[0].as_canonical_u64(),
        packed[1].as_canonical_u64(),
        packed[2].as_canonical_u64(),
        packed[3].as_canonical_u64(),
    ]
}

fn process_proofs(pub_key: [u64; 5], process_id: [u64; 4]) -> Vec<SmtEntry> {
    vec![
        SmtEntry {
            old_root: [0; 4],
            new_root: [0; 4],
            old_key: [0; 4],
            old_value: [0; 4],
            is_old0: false,
            new_key: [0; 4],
            new_value: process_id,
            fnc0: false,
            fnc1: false,
            siblings: vec![],
        },
        SmtEntry {
            old_root: [0; 4],
            new_root: [0; 4],
            old_key: [0; 4],
            old_value: [0; 4],
            is_old0: false,
            new_key: [0; 4],
            new_value: packed_mode_raw(),
            fnc0: false,
            fnc1: false,
            siblings: vec![],
        },
        SmtEntry {
            old_root: [0; 4],
            new_root: [0; 4],
            old_key: [0; 4],
            old_value: [0; 4],
            is_old0: false,
            new_key: [0; 4],
            new_value: guest_ecgfp5_verify::hash_enc_key(&pub_key),
            fnc0: false,
            fnc1: false,
            siblings: vec![],
        },
        SmtEntry {
            old_root: [0; 4],
            new_root: [0; 4],
            old_key: [0; 4],
            old_value: [0; 4],
            is_old0: false,
            new_key: [0; 4],
            new_value: [4, 0, 0, 0],
            fnc0: false,
            fnc1: false,
            siblings: vec![],
        },
    ]
}

fn append_matching_csp_block(bytes: &mut Vec<u8>, bundles: &[StarkProofBundle]) {
    bytes.extend(
        write_csp_block(&CspBlockData {
            csp_pub_key_x: [0; 4],
            csp_pub_key_y: [0; 4],
            entries: bundles
                .iter()
                .map(|bundle| CspEntryData {
                    r: [0; 4],
                    s: [0; 4],
                    voter_address: bundle.public_values.address,
                    weight: [bundle.public_values.inputs_preimage[113], 0, 0, 0],
                    index: 0,
                })
                .collect(),
        })
        .unwrap(),
    );
}

#[test]
fn parses_and_verifies_dstark_state_and_ecgfp5_blocks() {
    let (ballot_proof, _) = prove_full_ballot(&sample_inputs());
    let raw = ballot_proof
        .public_values
        .iter()
        .flat_map(|v| v.as_canonical_u64().to_le_bytes())
        .collect::<Vec<_>>();
    let public_values =
        davinci_zkvm_input_gen::stark_types::StarkPublicValues::decode(&raw).unwrap();
    let bundle = StarkProofBundle {
        proof_bytes: postcard::to_allocvec(&ballot_proof.proof).unwrap(),
        public_values,
    };

    let bundles = [bundle.clone(), bundle.clone()];
    let sigs = vec![
        zero_sig(bundle.public_values.vote_id),
        zero_sig(bundle.public_values.vote_id),
    ];
    let mut bytes = generate_stark_input(&bundles, &sigs).unwrap();

    let original = bundle_ciphertexts(&bundle.public_values);
    let reenc_k = [7u64, 0, 0, 0, 0];
    let delta1 = Point::mulgen(Scalar(reenc_k));
    let delta2 = sample_inputs().pk * Scalar(reenc_k);
    let mut reencrypted = [types::Ecgfp5Ciphertext::default(); 8];
    for i in 0..8 {
        let (p1, _) = Point::decode(
            ecgfp5::field::GFp5::decode(&{
                let mut b = [0u8; 40];
                for j in 0..5 {
                    b[j * 8..(j + 1) * 8].copy_from_slice(&original[i].c1[j].to_le_bytes());
                }
                b
            })
            .0,
        );
        let (p2, _) = Point::decode(
            ecgfp5::field::GFp5::decode(&{
                let mut b = [0u8; 40];
                for j in 0..5 {
                    b[j * 8..(j + 1) * 8].copy_from_slice(&original[i].c2[j].to_le_bytes());
                }
                b
            })
            .0,
        );
        reencrypted[i] = types::Ecgfp5Ciphertext {
            c1: point_raw(p1 + delta1),
            c2: point_raw(p2 + delta2),
        };
    }

    let zero = zero_ballot();
    let zero_hash = guest_ecgfp5_verify::ballot_leaf_hash(&zero);
    let new_hash = guest_ecgfp5_verify::ballot_leaf_hash(&reencrypted);
    let state = StateData {
        n_voters: 1,
        n_overwritten: 0,
        process_id: [0, 0, 0, 0],
        old_state_root: [0, 0, 0, 0],
        new_state_root: [0, 0, 0, 0],
        vote_id_chain: vec![],
        ballot_chain: vec![SmtEntry {
            old_root: [0; 4],
            new_root: [0; 4],
            old_key: [0; 4],
            old_value: [0; 4],
            is_old0: true,
            new_key: [1, 0, 0, 0],
            new_value: new_hash,
            fnc0: true,
            fnc1: false,
            siblings: vec![],
        }],
        results_add: Some(SmtEntry {
            old_root: [0; 4],
            new_root: [0; 4],
            old_key: [0; 4],
            old_value: zero_hash,
            is_old0: false,
            new_key: [4, 0, 0, 0],
            new_value: new_hash,
            fnc0: false,
            fnc1: true,
            siblings: vec![],
        }),
        results_sub: None,
        process_proofs: vec![],
        ecgfp5_ballot_proof_data: Some(Ecgfp5BallotProofData {
            old_results_add: [Ecgfp5CiphertextData::default(); 8],
            old_results_sub: [Ecgfp5CiphertextData::default(); 8],
            voter_ballots: vec![reencrypted.map(|ct| Ecgfp5CiphertextData {
                c1: ct.c1,
                c2: ct.c2,
            })],
            overwritten_ballots: vec![],
        }),
    };
    bytes.extend(write_state_block(&state).unwrap());
    bytes.extend(
        write_reenc_block_g5(
            point_raw(sample_inputs().pk),
            &[Ecgfp5ReencEntryData {
                k: reenc_k,
                original: original.map(|ct| Ecgfp5CiphertextData {
                    c1: ct.c1,
                    c2: ct.c2,
                }),
                reencrypted: reencrypted.map(|ct| Ecgfp5CiphertextData {
                    c1: ct.c1,
                    c2: ct.c2,
                }),
            }],
        )
        .unwrap(),
    );

    let mut fail_mask = 0u32;
    let parsed = io::parse_input(&bytes, &mut fail_mask);
    assert_eq!(fail_mask, 0, "parse failed: {fail_mask:#x}");
    assert!(guest_davinci_stark::verify_batch(&parsed, &mut fail_mask));
    assert!(guest_ecgfp5_verify::verify_batch_from_parsed(
        &parsed.reenc_g5_pub_key,
        &parsed.reenc_g5_entries,
        &mut fail_mask
    ));
    assert!(guest_results::verify_results(
        parsed.state.as_ref().unwrap(),
        &mut fail_mask
    ));
    assert_eq!(fail_mask, 0, "verification failed: {fail_mask:#x}");
}

#[test]
fn rejects_mismatched_reenc_original_ciphertexts() {
    let (ballot_proof, _) = prove_full_ballot(&sample_inputs());
    let raw = ballot_proof
        .public_values
        .iter()
        .flat_map(|v| v.as_canonical_u64().to_le_bytes())
        .collect::<Vec<_>>();
    let public_values =
        davinci_zkvm_input_gen::stark_types::StarkPublicValues::decode(&raw).unwrap();
    let bundle = StarkProofBundle {
        proof_bytes: postcard::to_allocvec(&ballot_proof.proof).unwrap(),
        public_values,
    };

    let bundles = [bundle.clone(), bundle.clone()];
    let sigs = vec![
        zero_sig(bundle.public_values.vote_id),
        zero_sig(bundle.public_values.vote_id),
    ];
    let mut bytes = generate_stark_input(&bundles, &sigs).unwrap();

    let original = bundle_ciphertexts(&bundle.public_values);
    let reenc_k = [7u64, 0, 0, 0, 0];
    let delta1 = Point::mulgen(Scalar(reenc_k));
    let delta2 = sample_inputs().pk * Scalar(reenc_k);
    let mut reencrypted = [types::Ecgfp5Ciphertext::default(); 8];
    for i in 0..8 {
        let (p1, _) = Point::decode(
            ecgfp5::field::GFp5::decode(&{
                let mut b = [0u8; 40];
                for j in 0..5 {
                    b[j * 8..(j + 1) * 8].copy_from_slice(&original[i].c1[j].to_le_bytes());
                }
                b
            })
            .0,
        );
        let (p2, _) = Point::decode(
            ecgfp5::field::GFp5::decode(&{
                let mut b = [0u8; 40];
                for j in 0..5 {
                    b[j * 8..(j + 1) * 8].copy_from_slice(&original[i].c2[j].to_le_bytes());
                }
                b
            })
            .0,
        );
        reencrypted[i] = types::Ecgfp5Ciphertext {
            c1: point_raw(p1 + delta1),
            c2: point_raw(p2 + delta2),
        };
    }

    let zero = zero_ballot();
    let zero_hash = guest_ecgfp5_verify::ballot_leaf_hash(&zero);
    let new_hash = guest_ecgfp5_verify::ballot_leaf_hash(&reencrypted);
    let state = StateData {
        n_voters: 2,
        n_overwritten: 0,
        process_id: [1001, 0, 0, 0],
        old_state_root: [0, 0, 0, 0],
        new_state_root: [0, 0, 0, 0],
        vote_id_chain: vec![],
        ballot_chain: vec![
            SmtEntry {
                old_root: [0; 4],
                new_root: [0; 4],
                old_key: [0; 4],
                old_value: [0; 4],
                is_old0: true,
                new_key: [1, 0, 0, 0],
                new_value: new_hash,
                fnc0: true,
                fnc1: false,
                siblings: vec![],
            },
            SmtEntry {
                old_root: [0; 4],
                new_root: [0; 4],
                old_key: [0; 4],
                old_value: [0; 4],
                is_old0: true,
                new_key: [2, 0, 0, 0],
                new_value: new_hash,
                fnc0: true,
                fnc1: false,
                siblings: vec![],
            },
        ],
        results_add: Some(SmtEntry {
            old_root: [0; 4],
            new_root: [0; 4],
            old_key: [0; 4],
            old_value: zero_hash,
            is_old0: false,
            new_key: [4, 0, 0, 0],
            new_value: new_hash,
            fnc0: false,
            fnc1: true,
            siblings: vec![],
        }),
        results_sub: None,
        process_proofs: process_proofs(point_raw(sample_inputs().pk), [1001, 0, 0, 0]),
        ecgfp5_ballot_proof_data: Some(Ecgfp5BallotProofData {
            old_results_add: [Ecgfp5CiphertextData::default(); 8],
            old_results_sub: [Ecgfp5CiphertextData::default(); 8],
            voter_ballots: vec![
                reencrypted.map(|ct| Ecgfp5CiphertextData {
                    c1: ct.c1,
                    c2: ct.c2,
                }),
                reencrypted.map(|ct| Ecgfp5CiphertextData {
                    c1: ct.c1,
                    c2: ct.c2,
                }),
            ],
            overwritten_ballots: vec![],
        }),
    };
    bytes.extend(write_state_block(&state).unwrap());
    append_matching_csp_block(&mut bytes, &bundles);
    let mut tampered_original = original;
    tampered_original[0].c1[0] ^= 1;
    bytes.extend(
        write_reenc_block_g5(
            point_raw(sample_inputs().pk),
            &[
                Ecgfp5ReencEntryData {
                    k: reenc_k,
                    original: tampered_original.map(|ct| Ecgfp5CiphertextData {
                        c1: ct.c1,
                        c2: ct.c2,
                    }),
                    reencrypted: reencrypted.map(|ct| Ecgfp5CiphertextData {
                        c1: ct.c1,
                        c2: ct.c2,
                    }),
                },
                Ecgfp5ReencEntryData {
                    k: reenc_k,
                    original: original.map(|ct| Ecgfp5CiphertextData {
                        c1: ct.c1,
                        c2: ct.c2,
                    }),
                    reencrypted: reencrypted.map(|ct| Ecgfp5CiphertextData {
                        c1: ct.c1,
                        c2: ct.c2,
                    }),
                },
            ],
        )
        .unwrap(),
    );

    let mut fail_mask = 0u32;
    let parsed = io::parse_input(&bytes, &mut fail_mask);
    assert_eq!(fail_mask, 0, "parse failed: {fail_mask:#x}");
    assert!(!guest_binding::verify_bindings(&parsed, 4, &mut fail_mask));
    assert_ne!(fail_mask & types::FAIL_BINDING, 0);
}

#[test]
fn rejects_mismatched_process_id_binding() {
    let (ballot_proof, _) = prove_full_ballot(&sample_inputs());
    let raw = ballot_proof
        .public_values
        .iter()
        .flat_map(|v| v.as_canonical_u64().to_le_bytes())
        .collect::<Vec<_>>();
    let public_values =
        davinci_zkvm_input_gen::stark_types::StarkPublicValues::decode(&raw).unwrap();
    let bundle = StarkProofBundle {
        proof_bytes: postcard::to_allocvec(&ballot_proof.proof).unwrap(),
        public_values,
    };

    let bundles = [bundle.clone(), bundle.clone()];
    let sigs = vec![
        zero_sig(bundle.public_values.vote_id),
        zero_sig(bundle.public_values.vote_id),
    ];
    let mut bytes = generate_stark_input(&bundles, &sigs).unwrap();

    let original = bundle_ciphertexts(&bundle.public_values);
    let state = StateData {
        n_voters: 2,
        n_overwritten: 0,
        process_id: [9999, 0, 0, 0],
        old_state_root: [0, 0, 0, 0],
        new_state_root: [0, 0, 0, 0],
        vote_id_chain: vec![],
        ballot_chain: vec![],
        results_add: None,
        results_sub: None,
        process_proofs: process_proofs(point_raw(sample_inputs().pk), [9999, 0, 0, 0]),
        ecgfp5_ballot_proof_data: Some(Ecgfp5BallotProofData {
            old_results_add: [Ecgfp5CiphertextData::default(); 8],
            old_results_sub: [Ecgfp5CiphertextData::default(); 8],
            voter_ballots: vec![
                original.map(|ct| Ecgfp5CiphertextData {
                    c1: ct.c1,
                    c2: ct.c2,
                }),
                original.map(|ct| Ecgfp5CiphertextData {
                    c1: ct.c1,
                    c2: ct.c2,
                }),
            ],
            overwritten_ballots: vec![],
        }),
    };
    bytes.extend(write_state_block(&state).unwrap());
    append_matching_csp_block(&mut bytes, &bundles);
    bytes.extend(
        write_reenc_block_g5(
            point_raw(sample_inputs().pk),
            &[
                Ecgfp5ReencEntryData {
                    k: [0u64; 5],
                    original: original.map(|ct| Ecgfp5CiphertextData {
                        c1: ct.c1,
                        c2: ct.c2,
                    }),
                    reencrypted: original.map(|ct| Ecgfp5CiphertextData {
                        c1: ct.c1,
                        c2: ct.c2,
                    }),
                },
                Ecgfp5ReencEntryData {
                    k: [0u64; 5],
                    original: original.map(|ct| Ecgfp5CiphertextData {
                        c1: ct.c1,
                        c2: ct.c2,
                    }),
                    reencrypted: original.map(|ct| Ecgfp5CiphertextData {
                        c1: ct.c1,
                        c2: ct.c2,
                    }),
                },
            ],
        )
        .unwrap(),
    );

    let mut fail_mask = 0u32;
    let parsed = io::parse_input(&bytes, &mut fail_mask);
    assert_eq!(fail_mask, 0, "parse failed: {fail_mask:#x}");
    assert!(!guest_binding::verify_bindings(&parsed, 4, &mut fail_mask));
    assert_ne!(fail_mask & types::FAIL_BINDING, 0);
}
