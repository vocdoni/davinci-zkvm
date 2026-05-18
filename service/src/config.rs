//! Service configuration loaded from environment variables.
//!
//! All defaults match the layout produced by `docker compose --profile cuda
//! up` (the proving keys are mounted under `/proving-key` and
//! `/proving-key-plonk`, the circuit ELF lives at `/app/circuit.elf`, and
//! jobs land under `/proofs`). Outside Docker, override every path via
//! environment variables.

use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Config {
    /// HTTP listen address (default `0.0.0.0:8080`).
    pub listen_addr: String,
    /// Path to the ZisK STARK proving key directory (default `/proving-key`).
    pub proving_key_path: PathBuf,
    /// Path to the ZisK PLONK proving key directory (default
    /// `/proving-key-plonk`). The service always wraps the STARK proof into a
    /// PLONK SNARK suitable for on-chain verification, so this is mandatory.
    pub proving_key_plonk_path: PathBuf,
    /// Path to the compiled circuit ELF (default `/app/circuit.elf`).
    pub circuit_elf_path: PathBuf,
    /// `cargo-zisk` binary to invoke (default `cargo-zisk`).
    pub cargo_zisk_bin: String,
    /// Directory for per-job proof output (default `/tmp/proofs`).
    pub proof_output_dir: PathBuf,
    /// Maximum number of jobs queued at once (default 100).
    pub max_queue_size: usize,
    /// Number of MPI processes for proving (default 1, MPI disabled).
    pub zisk_mpi_procs: usize,
    /// Threads per MPI process (0 = let MPI choose, default 0).
    pub zisk_mpi_threads: usize,
    /// MPI bind policy passed to `mpirun --bind-to` (default `none`).
    pub zisk_mpi_bind_to: String,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            listen_addr: env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string()),
            proving_key_path: env::var("PROVING_KEY_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/proving-key")),
            proving_key_plonk_path: env::var("PROVING_KEY_PLONK_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/proving-key-plonk")),
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
            zisk_mpi_procs: env::var("ZISK_MPI_PROCS")
                .ok()
                .and_then(|s| s.parse().ok())
                .filter(|n| *n >= 1)
                .unwrap_or(1),
            zisk_mpi_threads: env::var("ZISK_MPI_THREADS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            zisk_mpi_bind_to: env::var("ZISK_MPI_BIND_TO").unwrap_or_else(|_| "none".to_string()),
        }
    }
}
