#![no_main]
ziskos::entrypoint!(main);

mod binding;
mod bls_fr;
mod bn254_fr;
mod census;
mod consistency;
mod csp;
mod davinci_stark;
mod ecdsa;
mod ecgfp5_verify;
mod hash;
mod io;
mod kzg;
mod poseidon;
mod results;
mod smt;
mod types;

use crate::types::{CENSUS_ORIGIN_CSP, FrRaw, ZERO_FR};
use ziskos::io::{read_input_slice, write};

#[inline(always)]
fn set_fr_output(outputs: &mut [u32; 46], base: usize, v: &FrRaw) {
    for i in 0..4 {
        outputs[base + i * 2] = (v[i] & 0xFFFF_FFFF) as u32;
        outputs[base + i * 2 + 1] = (v[i] >> 32) as u32;
    }
}

fn main() {
    let input = read_input_slice();
    let mut fail_mask: u32 = 0;
    let parsed = io::parse_input(&input, &mut fail_mask);

    let batch_ok = davinci_stark::verify_batch(&parsed, &mut fail_mask);
    let auth_ok = ecdsa::verify_batch(&parsed, &mut fail_mask);

    let census_origin: u64 = parsed
        .state
        .as_ref()
        .and_then(|s| s.process_proofs.get(3))
        .map(|p| p.new_value[0])
        .unwrap_or(0);

    let (eligibility_ok, census_root) = if census_origin == CENSUS_ORIGIN_CSP {
        match &parsed.csp_block {
            Some(csp) => {
                let process_id = parsed
                    .state
                    .as_ref()
                    .map(|s| s.process_id)
                    .unwrap_or(ZERO_FR);
                csp::verify_csp(csp, &process_id, &mut fail_mask)
            }
            None => {
                fail_mask |= crate::types::FAIL_MISSING_BLOCK;
                (false, ZERO_FR)
            }
        }
    } else {
        let ok = census::verify_batch(&parsed, &mut fail_mask);
        let root = parsed
            .census_proofs
            .first()
            .map(|cp| cp.root)
            .unwrap_or(ZERO_FR);
        (ok, root)
    };

    let consistency_ok = consistency::verify_consistency(&parsed, &mut fail_mask);
    let (state_ok, old_root, new_root, voters, overwritten) =
        smt::verify_state(&parsed, &mut fail_mask);

    let reenc_ok = ecgfp5_verify::verify_batch_from_parsed(
        &parsed.reenc_g5_pub_key,
        &parsed.reenc_g5_entries,
        &mut fail_mask,
    );

    let results_ok = match &parsed.state {
        Some(state) => results::verify_results(state, &mut fail_mask),
        None => false,
    };

    let (kzg_ok, kzg_commitment) = kzg::verify_kzg(&parsed.kzg, &mut fail_mask);

    let binding_ok = binding::verify_bindings(&parsed, census_origin, &mut fail_mask);

    let overall_ok = fail_mask == 0
        && batch_ok
        && auth_ok
        && eligibility_ok
        && consistency_ok
        && state_ok
        && reenc_ok
        && results_ok
        && kzg_ok
        && binding_ok;

    let mut outputs = [0u32; 46];
    outputs[0] = overall_ok as u32;
    outputs[1] = fail_mask;
    set_fr_output(&mut outputs, 2, &old_root);
    set_fr_output(&mut outputs, 10, &new_root);
    outputs[18] = voters as u32;
    outputs[19] = overwritten as u32;
    set_fr_output(&mut outputs, 20, &census_root);

    let limb_u32s = kzg::commitment_to_limb_u32s(&kzg_commitment);
    for (l, limb) in limb_u32s.iter().enumerate() {
        for (w, &word) in limb.iter().enumerate() {
            outputs[28 + l * 4 + w] = word;
        }
    }

    outputs[40] = batch_ok as u32;
    outputs[41] = auth_ok as u32;
    outputs[43] = parsed.nproofs as u32;
    outputs[44] = parsed.n_public as u32;
    outputs[45] = parsed.log_n as u32;

    let bytes = outputs
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect::<Vec<_>>();
    write(&bytes);
}
