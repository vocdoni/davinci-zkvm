//! Cross-block binding checks for the active davinci-stark/ecgfp5 path.
//!
//! These checks ensure the surrounding zkVM state-transition blocks describe
//! the same ballot statement that the embedded `davinci-stark` proofs verify.

use crate::ecgfp5_verify;
use crate::io::ParsedInput;
use crate::types::{CENSUS_ORIGIN_CSP, Ecgfp5Ballot, Ecgfp5Ciphertext, FAIL_BINDING, FrRaw};

fn extract_address_from_census_leaf(leaf: &FrRaw) -> FrRaw {
    [
        (leaf[1] >> 24) | (leaf[2] << 40),
        (leaf[2] >> 24) | (leaf[3] << 40),
        leaf[3] >> 24,
        0,
    ]
}

fn extract_weight_from_census_leaf(leaf: &FrRaw) -> Option<u64> {
    if (leaf[1] & 0x00FF_FFFF) != 0 {
        return None;
    }
    Some(leaf[0])
}

fn fr_to_u64(fr: &FrRaw) -> Option<u64> {
    if fr[1] == 0 && fr[2] == 0 && fr[3] == 0 {
        Some(fr[0])
    } else {
        None
    }
}

fn proof_ciphertexts(parsed: &ParsedInput, index: usize) -> Option<Ecgfp5Ballot> {
    let pv = &parsed
        .stark_proofs
        .get(index)?
        .public_values
        .inputs_preimage;
    let mut out = [Ecgfp5Ciphertext::default(); 8];
    let base = 33;
    for i in 0..8 {
        out[i]
            .c1
            .copy_from_slice(&pv[base + i * 10..base + i * 10 + 5]);
        out[i]
            .c2
            .copy_from_slice(&pv[base + i * 10 + 5..base + i * 10 + 10]);
    }
    Some(out)
}

fn proof_process_id(parsed: &ParsedInput, index: usize) -> Option<FrRaw> {
    let pv = &parsed
        .stark_proofs
        .get(index)?
        .public_values
        .inputs_preimage;
    Some([pv[0], pv[1], pv[2], pv[3]])
}

fn proof_packed_ballot_mode(parsed: &ParsedInput, index: usize) -> Option<FrRaw> {
    let pv = &parsed
        .stark_proofs
        .get(index)?
        .public_values
        .inputs_preimage;
    Some([pv[4], pv[5], pv[6], pv[7]])
}

fn proof_public_key_projective(parsed: &ParsedInput, index: usize) -> Option<[u64; 20]> {
    let pv = &parsed
        .stark_proofs
        .get(index)?
        .public_values
        .inputs_preimage;
    let mut out = [0u64; 20];
    out.copy_from_slice(&pv[8..28]);
    Some(out)
}

fn proof_weight(parsed: &ParsedInput, index: usize) -> Option<u64> {
    Some(
        parsed
            .stark_proofs
            .get(index)?
            .public_values
            .inputs_preimage[113],
    )
}

pub fn verify_bindings(parsed: &ParsedInput, census_origin: u64, fail_mask: &mut u32) -> bool {
    let Some(state) = &parsed.state else {
        *fail_mask |= crate::types::FAIL_MISSING_BLOCK;
        return false;
    };

    let n = state.n_voters;
    let mut ok = true;

    if parsed.stark_proofs.len() != n
        || parsed.reenc_g5_entries.len() != n
        || state.voter_ballots_g5.len() != n
    {
        *fail_mask |= FAIL_BINDING;
        return false;
    }

    if let (Some(kzg_block), true) = (&parsed.kzg, true) {
        if kzg_block.process_id != state.process_id {
            *fail_mask |= FAIL_BINDING;
            ok = false;
        }
        if kzg_block.root_hash_before != state.old_state_root {
            *fail_mask |= FAIL_BINDING;
            ok = false;
        }
    }

    if state.process_proofs.len() == 4 {
        if let Some(pub_key) = &parsed.reenc_g5_pub_key {
            let enc_key_hash = ecgfp5_verify::hash_enc_key(pub_key);
            if enc_key_hash != state.process_proofs[2].new_value {
                *fail_mask |= FAIL_BINDING;
                ok = false;
            }
        } else {
            *fail_mask |= FAIL_BINDING;
            ok = false;
        }
    }

    let eligibility_count = if census_origin == CENSUS_ORIGIN_CSP {
        parsed
            .csp_block
            .as_ref()
            .map(|c| c.entries.len())
            .unwrap_or(0)
    } else {
        parsed.census_proofs.len()
    };
    if eligibility_count != n {
        *fail_mask |= FAIL_BINDING;
        ok = false;
    }

    for i in 0..n {
        let Some(proof_process) = proof_process_id(parsed, i) else {
            *fail_mask |= FAIL_BINDING;
            return false;
        };
        if proof_process != state.process_id {
            *fail_mask |= FAIL_BINDING;
            ok = false;
        }

        if state.process_proofs.len() == 4 {
            let Some(proof_mode) = proof_packed_ballot_mode(parsed, i) else {
                *fail_mask |= FAIL_BINDING;
                return false;
            };
            if proof_mode != state.process_proofs[1].new_value {
                *fail_mask |= FAIL_BINDING;
                ok = false;
            }
        }

        if let Some(pub_key) = &parsed.reenc_g5_pub_key {
            let Some(projective) = proof_public_key_projective(parsed, i) else {
                *fail_mask |= FAIL_BINDING;
                return false;
            };
            if !ecgfp5_verify::point_matches_projective_limbs(pub_key, &projective) {
                *fail_mask |= FAIL_BINDING;
                ok = false;
            }
        }

        let Some(proof_ballot) = proof_ciphertexts(parsed, i) else {
            *fail_mask |= FAIL_BINDING;
            return false;
        };
        if parsed.reenc_g5_entries[i].original != proof_ballot {
            *fail_mask |= FAIL_BINDING;
            ok = false;
        }
        if parsed.reenc_g5_entries[i].reencrypted != state.voter_ballots_g5[i] {
            *fail_mask |= FAIL_BINDING;
            ok = false;
        }

        if census_origin == CENSUS_ORIGIN_CSP {
            let Some(csp) = &parsed.csp_block else {
                *fail_mask |= FAIL_BINDING;
                return false;
            };
            let csp_addr = &csp.entries[i].voter_address;
            let Some(proof_addr) = parsed.voter_address(i) else {
                *fail_mask |= FAIL_BINDING;
                return false;
            };
            if csp_addr[0] != proof_addr[0]
                || csp_addr[1] != proof_addr[1]
                || (csp_addr[2] & 0xFFFF_FFFF) != (proof_addr[2] & 0xFFFF_FFFF)
            {
                *fail_mask |= FAIL_BINDING;
                ok = false;
            }
            let Some(csp_weight) = fr_to_u64(&csp.entries[i].weight) else {
                *fail_mask |= FAIL_BINDING;
                ok = false;
                continue;
            };
            if Some(csp_weight) != proof_weight(parsed, i) {
                *fail_mask |= FAIL_BINDING;
                ok = false;
            }
        } else {
            let leaf_addr = extract_address_from_census_leaf(&parsed.census_proofs[i].leaf);
            let Some(proof_addr) = parsed.voter_address(i) else {
                *fail_mask |= FAIL_BINDING;
                return false;
            };
            if leaf_addr[0] != proof_addr[0]
                || leaf_addr[1] != proof_addr[1]
                || (leaf_addr[2] & 0xFFFF_FFFF) != (proof_addr[2] & 0xFFFF_FFFF)
            {
                *fail_mask |= FAIL_BINDING;
                ok = false;
            }
            if extract_weight_from_census_leaf(&parsed.census_proofs[i].leaf)
                != proof_weight(parsed, i)
            {
                *fail_mask |= FAIL_BINDING;
                ok = false;
            }
        }
    }

    ok
}
