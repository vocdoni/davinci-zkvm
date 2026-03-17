//! Configuration loaded from environment variables.

use std::env;
use std::path::PathBuf;
use std::process::Command;

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
    /// Reported cargo-zisk version string for health/debug endpoints
    pub cargo_zisk_version: String,
    /// Directory for proof output files (default: /tmp/proofs)
    pub proof_output_dir: PathBuf,
    /// Maximum number of jobs in the queue (default: 100)
    pub max_queue_size: usize,
    /// Number of MPI processes for proving (default: 1 = disabled)
    pub zisk_mpi_procs: usize,
    /// Threads per MPI process (0 = don't override, default: 0)
    pub zisk_mpi_threads: usize,
    /// MPI bind policy passed to mpirun --bind-to (default: none)
    pub zisk_mpi_bind_to: String,
    /// Enable recursive aggregation/final proof generation.
    pub zisk_aggregation: bool,
    /// Verify generated proofs before marking the job as done.
    pub zisk_verify_proofs: bool,
    /// Force the prebuilt emulator path instead of the ASM toolchain.
    pub zisk_use_emulator: bool,
    /// Enable ballot proof aggregation mode.
    ///
    /// When enabled, individual ballot STARK proof bytes are stripped from the
    /// guest input so the ZisK guest skips STARK verification. The service
    /// produces a lightweight ZisK proof covering only ECDSA, census, SMT, and
    /// binding checks. The ballot STARK proofs are assumed to be verified
    /// externally via Plonky3-recursion aggregation.
    pub ballot_aggregation: bool,
}

impl Config {
    pub fn from_env() -> Self {
        let cargo_zisk_bin =
            env::var("CARGO_ZISK_BIN").unwrap_or_else(|_| "cargo-zisk".to_string());
        Self {
            listen_addr: env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string()),
            proving_key_path: env::var("PROVING_KEY_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/proving-key")),
            circuit_elf_path: env::var("CIRCUIT_ELF_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/app/circuit.elf")),
            cargo_zisk_version: cargo_zisk_version(&cargo_zisk_bin),
            cargo_zisk_bin,
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
            zisk_aggregation: env::var("ZISK_AGGREGATION")
                .ok()
                .map(|s| parse_bool_env(&s))
                .unwrap_or(false),
            zisk_verify_proofs: env::var("ZISK_VERIFY_PROOFS")
                .ok()
                .map(|s| parse_bool_env(&s))
                .unwrap_or(false),
            zisk_use_emulator: env::var("ZISK_USE_EMULATOR")
                .ok()
                .map(|s| parse_bool_env(&s))
                .unwrap_or(false),
            ballot_aggregation: env::var("BALLOT_AGGREGATION")
                .ok()
                .map(|s| parse_bool_env(&s))
                .unwrap_or(false),
        }
    }
}

fn parse_bool_env(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn cargo_zisk_version(bin: &str) -> String {
    match Command::new(bin).arg("--version").output() {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            format!("{bin} --version failed: {}", stderr.trim())
        }
        Err(err) => format!("{bin} unavailable: {err}"),
    }
}
