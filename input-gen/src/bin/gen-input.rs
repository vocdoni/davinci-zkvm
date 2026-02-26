//! CLI tool: generate ZisK binary input from snarkjs Groth16 proofs directory.
//!
//! Usage: gen-input --proofs-dir <dir> --output <out.bin> [--nproofs <N>]
//!
//! Expected directory structure:
//!   <proofs-dir>/verification_key.json  — snarkjs verification key
//!   <proofs-dir>/proof_1.json           — Groth16 proof (1-indexed)
//!   <proofs-dir>/public_1.json          — public inputs
//!   ...

use anyhow::Result;
use davinci_zkvm_input_gen::{generate_input, load_proofs_from_dir, load_signatures_from_dir, SnarkJsVk};
use std::path::PathBuf;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mut proofs_dir: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut nproofs: usize = 128;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--proofs-dir" => { i += 1; proofs_dir = Some(PathBuf::from(&args[i])); }
            "--output" => { i += 1; output = Some(PathBuf::from(&args[i])); }
            "--nproofs" => { i += 1; nproofs = args[i].parse()?; }
            _ => anyhow::bail!("unknown argument: {}", args[i]),
        }
        i += 1;
    }

    let proofs_dir = proofs_dir.ok_or_else(|| anyhow::anyhow!("--proofs-dir required"))?;
    let output = output.ok_or_else(|| anyhow::anyhow!("--output required"))?;

    // Load VK from verification_key.json in the proofs directory
    let vk_path = proofs_dir.join("verification_key.json");
    let vk: SnarkJsVk = serde_json::from_str(&std::fs::read_to_string(&vk_path)
        .map_err(|e| anyhow::anyhow!("reading {:?}: {}", vk_path, e))?)?;

    eprintln!("Loading {} proofs from {:?}", nproofs, proofs_dir);
    let (proofs, public_inputs) = load_proofs_from_dir(&proofs_dir, nproofs)?;
    let sigs = load_signatures_from_dir(&proofs_dir, nproofs)?;
    if !sigs.is_empty() {
        eprintln!("Loaded {} ECDSA signatures", sigs.len());
    }

    eprintln!("Generating binary input...");
    let bytes = generate_input(&vk, &proofs, &public_inputs, &sigs)?;
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&output, &bytes)?;
    eprintln!("Written {} bytes to {:?}", bytes.len(), output);
    Ok(())
}
