//! Configuration loaded from environment variables.

use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Config {
    /// HTTP listen address (default: 0.0.0.0:8080)
    pub listen_addr: String,
    /// Path to ZisK proving key directory (default: /proving-key)
    pub proving_key_path: PathBuf,
    /// Path to the compiled circuit ELF (default: /app/circuit.elf)
    pub circuit_elf_path: PathBuf,
    /// Path to cargo-zisk binary (default: cargo-zisk)
    pub cargo_zisk_bin: String,
    /// Directory for proof output files (default: /tmp/proofs)
    pub proof_output_dir: PathBuf,
    /// Maximum number of jobs in the queue (default: 100)
    pub max_queue_size: usize,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            listen_addr: env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string()),
            proving_key_path: env::var("PROVING_KEY_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/proving-key")),
            circuit_elf_path: env::var("CIRCUIT_ELF_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/app/circuit.elf")),
            cargo_zisk_bin: env::var("CARGO_ZISK_BIN").unwrap_or_else(|_| "cargo-zisk".to_string()),
            proof_output_dir: env::var("PROOF_OUTPUT_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/tmp/proofs")),
            max_queue_size: env::var("MAX_QUEUE_SIZE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(100),
        }
    }
}
