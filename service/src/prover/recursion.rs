//! Helpers for the recursive aggregation pipeline: reading vadcop STARK
//! blobs out of completed jobs' `proof.bin` files and assembling aggregator
//! guest inputs. The wire format lives in `input-gen`'s `aggregator` module;
//! this is just the filesystem glue.

use anyhow::{Context, Result};
use davinci_zkvm_input_gen::aggregator::{vadcop_blob_from_proof_bin, VadcopBlob};
use std::path::Path;

/// Hex-encode a program vk (4 u64 words, big-endian) as 0x-prefixed hex.
pub fn vk_hex(vk: &[u64; 4]) -> String {
    let mut b = Vec::with_capacity(32);
    for w in vk {
        b.extend_from_slice(&w.to_be_bytes());
    }
    format!("0x{}", hex::encode(b))
}

/// Parse a 0x-prefixed big-endian 32-byte hex vk into 4 u64 words.
pub fn parse_vk_hex(s: &str) -> Result<[u64; 4]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let b = hex::decode(s).context("bad vk hex")?;
    anyhow::ensure!(b.len() == 32, "vk must be 32 bytes, got {}", b.len());
    let mut vk = [0u64; 4];
    for i in 0..4 {
        vk[i] = u64::from_be_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
    }
    Ok(vk)
}

/// Load and decode the vadcop STARK blob from a job directory's `proof.bin`.
/// Fails if the proof body is a PLONK SNARK (job was not proven with
/// `output: stark`).
pub fn load_job_blob(job_dir: &Path) -> Result<VadcopBlob> {
    let path = job_dir.join("proof.bin");
    let bytes =
        std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    vadcop_blob_from_proof_bin(&bytes)
        .with_context(|| format!("decode {}", path.display()))
}

/// Post-process a completed STARK job: write `publics.bin` (the guest's
/// committed u32 registers as raw LE bytes) and `stark.json` with the
/// program_vk / zisk_vk needed for external vk binding.
pub async fn write_stark_artifacts(job_dir: &Path) -> Result<()> {
    let dir = job_dir.to_path_buf();
    let blob = tokio::task::spawn_blocking(move || load_job_blob(&dir)).await??;

    let mut publics = Vec::with_capacity(64 * 4);
    for w in &blob.publics {
        publics.extend_from_slice(&w.to_le_bytes());
    }
    tokio::fs::write(job_dir.join("publics.bin"), &publics).await?;

    let meta = serde_json::json!({
        "program_vk": vk_hex(&blob.program_vk),
        "zisk_vk": vk_hex(&blob.zisk_vk),
    });
    tokio::fs::write(
        job_dir.join("stark.json"),
        serde_json::to_vec_pretty(&meta)?,
    )
    .await?;
    Ok(())
}
