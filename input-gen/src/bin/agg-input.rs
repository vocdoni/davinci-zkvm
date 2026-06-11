//! Build a circuit-aggregator guest input from a chain config and one or
//! more vote-batch `proof.bin` files (Vadcop STARK bodies).
//!
//! Usage:
//!   agg-input --config config.json --output input.bin \
//!       [--prev fold_proof.bin] [--fold-vk 0xHEX64] \
//!       batch1_proof.bin [batch2_proof.bin ...]
//!
//! batch_vk is taken from the first batch proof (all batches must agree).
//! fold_vk defaults to zero for genesis folds; pass --fold-vk (the
//! aggregator's own program_vk, big-endian hex) when chaining with --prev.

use anyhow::{bail, Context, Result};
use davinci_zkvm_input_gen::aggregator::{
    build_fold_input, parse_agg_digest, vadcop_blob_from_proof_bin, ChainConfig, VadcopBlob,
};

fn vk_hex(vk: &[u64; 4]) -> String {
    let mut b = Vec::with_capacity(32);
    for w in vk {
        b.extend_from_slice(&w.to_be_bytes());
    }
    format!("0x{}", hex::encode(b))
}

fn parse_vk_hex(s: &str) -> Result<[u64; 4]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let b = hex::decode(s).context("bad vk hex")?;
    if b.len() != 32 {
        bail!("vk must be 32 bytes, got {}", b.len());
    }
    let mut vk = [0u64; 4];
    for i in 0..4 {
        vk[i] = u64::from_be_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
    }
    Ok(vk)
}

fn load_blob(path: &str) -> Result<VadcopBlob> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path))?;
    vadcop_blob_from_proof_bin(&bytes).with_context(|| format!("decode {}", path))
}

fn print_digest(path: &str) -> Result<()> {
    let blob = load_blob(path)?;
    let mut bytes = Vec::with_capacity(64 * 4);
    for w in &blob.publics {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    let d = parse_agg_digest(&bytes)?;
    println!("program_vk: {}", vk_hex(&blob.program_vk));
    println!("mode: {}  step_count: {}  voters: {}  overwrites: {}",
        d.mode, d.step_count, d.total_voters, d.total_overwrites);
    let hex32 = |w: &[u32; 8]| {
        let mut b = Vec::with_capacity(32);
        for x in w {
            b.extend_from_slice(&x.to_le_bytes());
        }
        format!("0x{}", hex::encode(b))
    };
    println!("config_commitment (LE): {}", hex32(&d.config_commitment));
    println!("state_root (LE):        {}", hex32(&d.state_root));
    println!("batch_vk: {}", vk_hex(&d.batch_vk));
    println!("fold_vk:  {}", vk_hex(&d.fold_vk));
    println!("results: {:?}", d.results);
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() == 2 && args[0] == "--digest" {
        return print_digest(&args[1]);
    }
    let mut config_path = None;
    let mut output_path = None;
    let mut prev_path = None;
    let mut fold_vk_arg = None;
    let mut batch_paths = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => { config_path = Some(args[i + 1].clone()); i += 2; }
            "--output" => { output_path = Some(args[i + 1].clone()); i += 2; }
            "--prev" => { prev_path = Some(args[i + 1].clone()); i += 2; }
            "--fold-vk" => { fold_vk_arg = Some(args[i + 1].clone()); i += 2; }
            p => { batch_paths.push(p.to_string()); i += 1; }
        }
    }

    let config_path = config_path.context("--config is required")?;
    let output_path = output_path.context("--output is required")?;
    if batch_paths.is_empty() {
        bail!("at least one batch proof.bin is required");
    }

    let config: ChainConfig = serde_json::from_str(
        &std::fs::read_to_string(&config_path)
            .with_context(|| format!("read {}", config_path))?,
    )
    .context("parse chain config json")?;

    let batches: Vec<VadcopBlob> = batch_paths
        .iter()
        .map(|p| load_blob(p))
        .collect::<Result<_>>()?;
    let batch_vk = batches[0].program_vk;
    for (i, b) in batches.iter().enumerate() {
        if b.program_vk != batch_vk {
            bail!("batch {} program_vk differs from batch 0", i);
        }
    }

    let prev = prev_path.as_deref().map(load_blob).transpose()?;
    let fold_vk = match (&fold_vk_arg, &prev) {
        (Some(s), _) => parse_vk_hex(s)?,
        (None, Some(p)) => p.program_vk,
        (None, None) => [0u64; 4],
    };

    let batch_blobs: Vec<Vec<u8>> = batches.iter().map(|b| b.bytes.clone()).collect();
    let input = build_fold_input(
        &config,
        batch_vk,
        fold_vk,
        prev.as_ref().map(|p| p.bytes.as_slice()),
        &batch_blobs,
    )?;
    std::fs::write(&output_path, &input).with_context(|| format!("write {}", output_path))?;

    println!("batch_vk: {}", vk_hex(&batch_vk));
    println!("fold_vk:  {}", vk_hex(&fold_vk));
    if let Some(p) = &batches[0].publics.get(..2) {
        println!("batch0 publics: ok={} fail_mask={:#x}", p[0], p[1]);
    }
    println!("{} bytes ({} batches, prev={}) -> {}",
        input.len(), batches.len(), prev.is_some(), output_path);
    Ok(())
}
