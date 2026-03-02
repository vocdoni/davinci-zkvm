//! POST /prove — submit a batch of Groth16 proofs for ZisK proving

use crate::api::AppState;
use crate::types::{ProveRequest, SmtEntryJson};
use anyhow::{bail, Context};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use davinci_zkvm_input_gen::{census_proof_from_hex, generate_input, write_census_block, write_csp_block, write_kzg_block, write_reenc_block, write_state_block, be_hex32_to_fr_le, address_hex_to_fr_le, BjjCiphertextData, CspBlockData, CspEntryData, KzgData, ReencEntryData, SmtEntry, StateData};
use tracing::{debug, error, info, warn};

pub async fn submit_prove(
    State(state): State<AppState>,
    Json(req): Json<ProveRequest>,
) -> impl IntoResponse {
    // Validate request
    let num_proofs = req.proofs.len();
    if num_proofs == 0 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "proofs array is empty"}))).into_response();
    }
    if req.public_inputs.len() != num_proofs {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("public_inputs length ({}) must match proofs length ({})", req.public_inputs.len(), num_proofs)})),
        ).into_response();
    }

    // ── Log request summary ────────────────────────────────────────────────
    info!("Received prove request: {} ballot proof(s)", num_proofs);

    if let Some(st) = &req.state {
        info!(
            process_id = %st.process_id,
            old_root   = %st.old_state_root,
            new_root   = %st.new_state_root,
            voters     = st.voters_count,
            overwrites = st.overwritten_count,
            vote_id_smt_entries = st.vote_id_smt.len(),
            ballot_smt_entries  = st.ballot_smt.len(),
            process_smt_entries = st.process_smt.len(),
            has_results_add     = st.results_add_smt.is_some(),
            has_results_sub     = st.results_sub_smt.is_some(),
            "State-transition block"
        );
    } else {
        warn!("No state block in request");
    }

    if !req.census_proofs.is_empty() {
        let root = req.census_proofs.first().map(|p| p.root.as_str()).unwrap_or("?");
        debug!(count = req.census_proofs.len(), census_root = %root, "Census proofs");
    }

    if let Some(r) = &req.reencryption {
        debug!(
            entries     = r.entries.len(),
            enc_key_x   = %r.encryption_key_x,
            "Re-encryption block"
        );
    }

    if let Some(k) = &req.kzg {
        debug!(
            process_id       = %k.process_id,
            root_hash_before = %k.root_hash_before,
            commitment       = %k.commitment,
            y_claimed        = %k.y_claimed,
            blob_bytes       = k.blob.len() / 2,   // hex len / 2
            "KZG barycentric-evaluation block"
        );
    }

    debug!(
        sigs          = req.sigs.len(),
        queue_len     = state.prover.queue_len(),
        "Request accepted; generating ZisK input"
    );

    // Generate ZisK binary input (CPU-bound — runs in blocking thread pool)
    let vk = req.vk.clone();
    let proofs = req.proofs.clone();
    let public_inputs = req.public_inputs.clone();
    let sigs = req.sigs.clone();
    let state_json = req.state.clone();
    let census_json = req.census_proofs.clone();
    let csp_json = req.csp_data.clone();
    let reenc_json = req.reencryption.clone();
    let kzg_json = req.kzg.clone();
    let input_bytes = match tokio::task::spawn_blocking(move || {
        let mut bytes = generate_input(&vk, &proofs, &public_inputs, &sigs)?;

        // Append full STATETX state-transition block.
        if let Some(st) = state_json {
            let sd = StateData {
                n_voters: st.voters_count,
                n_overwritten: st.overwritten_count,
                process_id: davinci_zkvm_input_gen::hex32_to_smt_fr(&st.process_id)?,
                old_state_root: davinci_zkvm_input_gen::hex32_to_smt_fr(&st.old_state_root)?,
                new_state_root: davinci_zkvm_input_gen::hex32_to_smt_fr(&st.new_state_root)?,
                vote_id_chain: smt_entries_from_json(&st.vote_id_smt)?,
                ballot_chain: smt_entries_from_json(&st.ballot_smt)?,
                results_add: st.results_add_smt.as_ref().map(|e| smt_entry_from_json(e)).transpose()?,
                results_sub: st.results_sub_smt.as_ref().map(|e| smt_entry_from_json(e)).transpose()?,
                process_proofs: smt_entries_from_json(&st.process_smt)?,
                ballot_proof_data: None, // TODO: populate from request when ballot proof data is included
            };
            bytes.extend(write_state_block(&sd)?);
        }

        // Append census block.
        if !census_json.is_empty() {
            let proofs = census_json.iter()
                .map(|cp| census_proof_from_hex(&cp.root, &cp.leaf, cp.index, &cp.siblings))
                .collect::<anyhow::Result<Vec<_>>>()?;
            bytes.extend(write_census_block(&proofs)?);
        }

        // Append CSP ECDSA census block.
        if let Some(csp) = csp_json {
            let csp_pub_key_x = be_hex32_to_fr_le(&csp.csp_pub_key_x)?;
            let csp_pub_key_y = be_hex32_to_fr_le(&csp.csp_pub_key_y)?;
            let entries = csp.proofs.iter().map(|p| {
                Ok(CspEntryData {
                    r: be_hex32_to_fr_le(&p.r)?,
                    s: be_hex32_to_fr_le(&p.s)?,
                    voter_address: address_hex_to_fr_le(&p.voter_address)?,
                    weight: be_hex32_to_fr_le(&p.weight)?,
                    index: p.index,
                })
            }).collect::<anyhow::Result<Vec<_>>>()?;
            bytes.extend(write_csp_block(&CspBlockData { csp_pub_key_x, csp_pub_key_y, entries })?);
        }

        // Append re-encryption block.
        if let Some(r) = reenc_json {
            let pub_key_x = davinci_zkvm_input_gen::hex32_to_smt_fr(&r.encryption_key_x)?;
            let pub_key_y = davinci_zkvm_input_gen::hex32_to_smt_fr(&r.encryption_key_y)?;
            let mut entries = Vec::with_capacity(r.entries.len());
            for e in &r.entries {
                let k = davinci_zkvm_input_gen::hex32_to_smt_fr(&e.k)?;
                let parse_ct = |ct: &crate::types::BjjCiphertextJson| -> anyhow::Result<BjjCiphertextData> {
                    Ok(BjjCiphertextData {
                        c1x: davinci_zkvm_input_gen::hex32_to_smt_fr(&ct.c1.x)?,
                        c1y: davinci_zkvm_input_gen::hex32_to_smt_fr(&ct.c1.y)?,
                        c2x: davinci_zkvm_input_gen::hex32_to_smt_fr(&ct.c2.x)?,
                        c2y: davinci_zkvm_input_gen::hex32_to_smt_fr(&ct.c2.y)?,
                    })
                };
                let mut original_arr = Vec::with_capacity(8);
                for (j, ct) in e.original.iter().enumerate() {
                    original_arr.push(parse_ct(ct).with_context(|| format!("reenc original[{}]", j))?);
                }
                let original: [BjjCiphertextData; 8] = original_arr.try_into()
                    .map_err(|_| anyhow::anyhow!("expected 8 original ciphertexts"))?;
                let mut reenc_arr = Vec::with_capacity(8);
                for (j, ct) in e.reencrypted.iter().enumerate() {
                    reenc_arr.push(parse_ct(ct).with_context(|| format!("reenc reencrypted[{}]", j))?);
                }
                let reencrypted: [BjjCiphertextData; 8] = reenc_arr.try_into()
                    .map_err(|_| anyhow::anyhow!("expected 8 reencrypted ciphertexts"))?;
                entries.push(ReencEntryData { k, original, reencrypted });
            }
            bytes.extend(write_reenc_block(pub_key_x, pub_key_y, &entries)?);
        }

        // Append KZG blob barycentric evaluation block.
        if let Some(k) = kzg_json {
            let commitment_hex = k.commitment.trim_start_matches("0x");
            let commitment_bytes = hex::decode(commitment_hex)
                .with_context(|| "invalid commitment hex")?;
            if commitment_bytes.len() != 48 {
                bail!("commitment must be 48 bytes, got {}", commitment_bytes.len());
            }
            let y_claimed_hex = k.y_claimed.trim_start_matches("0x");
            let y_claimed_bytes = hex::decode(y_claimed_hex)
                .with_context(|| "invalid y_claimed hex")?;
            if y_claimed_bytes.len() != 32 {
                bail!("y_claimed must be 32 bytes, got {}", y_claimed_bytes.len());
            }
            let blob_hex = k.blob.trim_start_matches("0x");
            let blob_bytes = hex::decode(blob_hex)
                .with_context(|| "invalid blob hex")?;

            let mut commitment = [0u8; 48];
            commitment.copy_from_slice(&commitment_bytes);
            let mut y_claimed = [0u8; 32];
            y_claimed.copy_from_slice(&y_claimed_bytes);

            bytes.extend(write_kzg_block(&KzgData {
                process_id:       be_hex32_to_fr_le(&k.process_id)?,
                root_hash_before: be_hex32_to_fr_le(&k.root_hash_before)?,
                commitment,
                y_claimed,
                blob: blob_bytes,
            })?);
        }

        anyhow::Ok(bytes)
    }).await {
        Ok(Ok(bytes)) => {
            debug!("Input generation succeeded: {} bytes", bytes.len());
            bytes
        }
        Ok(Err(e)) => {
            error!("Input generation failed: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("input generation failed: {}", e)})),
            ).into_response();
        }
        Err(e) => {
            error!("Task panic: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "internal error"}))).into_response();
        }
    };

    // Submit to prover queue
    let proof_output_dir = state.config.proof_output_dir.clone();
    match state.prover.submit(input_bytes, &proof_output_dir).await {
        Ok(job_id) => {
            info!("Job {} queued: {} ballot proof(s), queue_position={}", job_id, num_proofs, state.prover.queue_len());
            (
                StatusCode::ACCEPTED,
                Json(serde_json::json!({
                    "job_id": job_id,
                    "status": "queued",
                })),
            ).into_response()
        }
        Err(e) => {
            error!("Failed to queue job: {}", e);
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": format!("failed to queue job: {}", e)})),
            ).into_response()
        }
    }
}

fn smt_entry_from_json(e: &SmtEntryJson) -> anyhow::Result<SmtEntry> {
    let siblings = e.siblings.iter()
        .map(|s| davinci_zkvm_input_gen::hex32_to_smt_fr(s))
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(SmtEntry {
        old_root:  davinci_zkvm_input_gen::hex32_to_smt_fr(&e.old_root)?,
        new_root:  davinci_zkvm_input_gen::hex32_to_smt_fr(&e.new_root)?,
        old_key:   davinci_zkvm_input_gen::hex32_to_smt_fr(&e.old_key)?,
        old_value: davinci_zkvm_input_gen::hex32_to_smt_fr(&e.old_value)?,
        is_old0:   e.is_old0 != 0,
        new_key:   davinci_zkvm_input_gen::hex32_to_smt_fr(&e.new_key)?,
        new_value: davinci_zkvm_input_gen::hex32_to_smt_fr(&e.new_value)?,
        fnc0:      e.fnc0 != 0,
        fnc1:      e.fnc1 != 0,
        siblings,
    })
}

fn smt_entries_from_json(entries: &[SmtEntryJson]) -> anyhow::Result<Vec<SmtEntry>> {
    entries.iter().map(smt_entry_from_json).collect()
}
