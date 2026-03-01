#![no_main]
ziskos::entrypoint!(main);

mod babyjubjub;
mod bn254;
mod census;
mod consistency;
mod ecdsa;
mod groth16;
mod hash;
mod io;
mod poseidon;
mod smt;
mod types;

use ziskos::{read_input_slice, set_output};

fn main() {
    let input = read_input_slice();
    let mut fail_mask: u32 = 0;

    let parsed   = io::parse_input(input, &mut fail_mask);
    let batch_ok = groth16::verify_batch(&parsed, &mut fail_mask);
    let ecdsa_ok = ecdsa::verify_batch(&parsed, &mut fail_mask);
    let smt_ok   = smt::verify_batch(&parsed, &mut fail_mask);

    // State-transition block verification (STATETX).
    let (state_ok, old_root_lo, old_root_hi, new_root_lo, new_root_hi, voters, overwritten) =
        smt::verify_state(&parsed, &mut fail_mask);

    // Consistency: voteID + ballot namespace and binding checks.
    let consistency_ok = consistency::verify_consistency(&parsed, &mut fail_mask);

    // Census lean-IMT Poseidon proof verification.
    let census_ok = census::verify_batch(&parsed, &mut fail_mask);

    // Re-encryption verification (BabyJubJub ElGamal).
    let reenc_ok = babyjubjub::verify_batch_from_parsed(
        &parsed.reenc_pub_key,
        &parsed.reenc_entries,
        &mut fail_mask,
    );

    // overall_ok: all mandatory verifications pass.
    // smt_ok semantics: 1 = valid, 0 = invalid, 2 = absent (legacy SMTBLK not provided).
    // The legacy SMTBLK and the full STATETX block are independent; absence of SMTBLK
    // is normal when using STATETX. state_ok covers STATETX validity.
    let overall_ok = fail_mask == 0
        && batch_ok
        && ecdsa_ok
        && (smt_ok == 1 || smt_ok == 2)
        && state_ok
        && consistency_ok
        && census_ok
        && reenc_ok;

    set_output(0, overall_ok as u32);
    set_output(1, fail_mask);
    set_output(2, parsed.log_n as u32);
    set_output(3, parsed.nproofs as u32);
    set_output(4, parsed.n_public as u32);
    set_output(5, input.len() as u32);
    set_output(6, parsed.bytes_consumed as u32);
    set_output(7, batch_ok as u32);
    set_output(8, ecdsa_ok as u32);
    set_output(9, smt_ok);
    set_output(10, old_root_lo as u32);
    set_output(11, old_root_hi as u32);
    set_output(12, new_root_lo as u32);
    set_output(13, new_root_hi as u32);
    set_output(14, voters as u32);
    set_output(15, overwritten as u32);
}
