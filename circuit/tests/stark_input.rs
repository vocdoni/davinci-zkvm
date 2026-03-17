#![allow(dead_code)]

use davinci_stark::{
    prove_full_ballot,
    trace::{BallotInputs, BallotMode},
};
use ecgfp5::{curve::Point, scalar::Scalar};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;

use davinci_zkvm_input_gen::{generate_stark_input, stark_types::StarkProofBundle, EcdsaSig};

#[path = "../src/davinci_stark.rs"]
mod guest_davinci_stark;
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

#[test]
fn parses_and_verifies_dstark_block() {
    let (ballot_proof, _) = prove_full_ballot(&sample_inputs());
    let bundle = StarkProofBundle {
        proof_bytes: postcard::to_allocvec(&ballot_proof.proof).unwrap(),
        public_values: {
            let raw = ballot_proof
                .public_values
                .iter()
                .flat_map(|v| v.as_canonical_u64().to_le_bytes())
                .collect::<Vec<_>>();
            davinci_zkvm_input_gen::stark_types::StarkPublicValues::decode(&raw).unwrap()
        },
    };
    let sigs = vec![
        zero_sig(bundle.public_values.vote_id),
        zero_sig(bundle.public_values.vote_id),
    ];
    let bytes = generate_stark_input(&[bundle.clone(), bundle], &sigs).unwrap();

    let mut fail_mask = 0u32;
    let parsed = io::parse_input(&bytes, &mut fail_mask);
    assert_eq!(fail_mask, 0, "parse failed: {fail_mask:#x}");
    assert_eq!(parsed.stark_proofs.len(), 2);
    assert!(guest_davinci_stark::verify_batch(&parsed, &mut fail_mask));
    assert_eq!(fail_mask, 0, "verification failed: {fail_mask:#x}");
}

#[test]
fn parses_padded_proof_bytes_without_parse_failure() {
    let (ballot_proof, _) = prove_full_ballot(&sample_inputs());
    let mut proof_bytes = postcard::to_allocvec(&ballot_proof.proof).unwrap();
    proof_bytes.truncate(5);
    let bundle = StarkProofBundle {
        proof_bytes,
        public_values: {
            let raw = ballot_proof
                .public_values
                .iter()
                .flat_map(|v| v.as_canonical_u64().to_le_bytes())
                .collect::<Vec<_>>();
            davinci_zkvm_input_gen::stark_types::StarkPublicValues::decode(&raw).unwrap()
        },
    };
    let sigs = vec![
        zero_sig(bundle.public_values.vote_id),
        zero_sig(bundle.public_values.vote_id),
    ];
    let bytes = generate_stark_input(&[bundle.clone(), bundle], &sigs).unwrap();

    assert_eq!(bytes.len() % 8, 0);

    let mut fail_mask = 0u32;
    let parsed = io::parse_input(&bytes, &mut fail_mask);
    assert_eq!(fail_mask, 0, "parse failed: {fail_mask:#x}");
    assert_eq!(parsed.stark_proofs.len(), 2);
    assert_eq!(parsed.stark_proofs[0].proof_bytes.len(), 5);
}
