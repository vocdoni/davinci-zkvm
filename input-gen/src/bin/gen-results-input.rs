//! CLI tool: build the circuit-results guest input from a results request.
//!
//! Usage: gen-results-input --request <request.json> --output <input.bin>
//!
//! The request is the `POST /results` JSON body. The output is the raw guest
//! frame, without the `read_slice` length prefix (like gen-input).

use anyhow::{bail, Context, Result};
use davinci_zkvm_input_gen::results::{build_results_input, ResultsJson};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut request = None;
    let mut output = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--request" => request = it.next().cloned(),
            "--output" => output = it.next().cloned(),
            _ => bail!("unknown argument: {}", a),
        }
    }
    let request = request.context("--request <file> is required")?;
    let output = output.context("--output <file> is required")?;

    let req: ResultsJson = serde_json::from_str(
        &std::fs::read_to_string(&request).with_context(|| format!("read {}", request))?,
    )
    .context("parse results request json")?;
    let bytes = build_results_input(&req)?;
    std::fs::write(&output, &bytes).with_context(|| format!("write {}", output))?;
    eprintln!("Written {} bytes to {}", bytes.len(), output);
    Ok(())
}
