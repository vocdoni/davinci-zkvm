//! Public signals of a ballot whose padded fields are not the identity.

use davinci_zkvm_sdk::ballot::{encrypt_ballot, public_signals, BallotMode};
use davinci_zkvm_sdk::crypto::babyjubjub::Point;
use davinci_zkvm_sdk::crypto::field::{fr_to_u256, Fr};

fn mode(nf: u8) -> BallotMode {
    BallotMode {
        num_fields: nf,
        group_size: nf,
        unique_values: false,
        cost_exponent: 1,
        max_value: 7,
        min_value: 0,
        max_value_sum: 7 * nf as u64,
        min_value_sum: 0,
    }
}

// BUG: public_signals returns 71 signals for a ballot with a non-identity field at or above num_fields; the guest derives the identity there, so the signals match no batch (TS and the node refuse it).
#[test]
fn public_signals_refuses_non_identity_padding() {
    let pk = Point::generator().mul(&fr_to_u256(&Fr::from(123_456u64)));
    let (pid, address, weight) = (Fr::from(9u64), Fr::from(0x1122u64), Fr::from(3u64));
    for nf in [1u8, 3, 15] {
        let m = mode(nf);
        let honest = encrypt_ballot(&pk, &[1, 2, 3], &Fr::from(77u64), nf);
        assert!(honest.is_padded_ok(nf));
        public_signals(&pid, &m, &pk, &address, 1 << 63, &honest, &weight).unwrap();
        for f in [nf as usize, 15] {
            let mut bad = honest;
            bad.0[f] = honest.0[0];
            assert!(
                public_signals(&pid, &m, &pk, &address, 1 << 63, &bad, &weight).is_err(),
                "nf = {nf}: field {f} not the identity"
            );
        }
    }
    // num_fields = 16 has no padding: any ballot of the mode passes.
    let full = encrypt_ballot(&pk, &[1; 16], &Fr::from(78u64), 16);
    public_signals(&pid, &mode(16), &pk, &address, 1 << 63, &full, &weight).unwrap();
}
