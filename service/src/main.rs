//! davinci-zkvm: ZisK proof service for batched DAVINCI ballot verification
//!
//! Starts an HTTP server that accepts POST /prove requests, queues proving jobs,
//! and serves the resulting ZisK proofs. The active production ballot path is
//! `davinci-stark` plus ecgfp5 state-transition data.

mod api;
mod config;
mod prover;
mod types;

use crate::api::{router, AppState};
use crate::prover::ProverHandle;
use config::Config;
use std::sync::Arc;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize structured logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "davinci_zkvm=info,tower_http=info".into()),
        )
        .init();

    let config = Config::from_env();

    // Validate required paths exist
    if !config.proving_key_path.exists() {
        anyhow::bail!(
            "Proving key not found at {:?}. \
             Set PROVING_KEY_PATH env var or mount the key at /proving-key. \
             Run 'make setup' to download it.",
            config.proving_key_path
        );
    }
    let required_setup = config
        .proving_key_path
        .join("zisk/vadcop_final_compressed/vadcop_final_compressed.starkinfo.json");
    if !required_setup.exists() {
        anyhow::bail!(
            "Incompatible ZisK proving key at {:?}: missing {:?}. \
             The current ZisK runtime requires the compressed VADCOP final setup. \
             Re-run 'make setup' (or './install.sh' with FORCE_SETUP_DOWNLOAD=1) and rebuild/restart the service/container.",
            config.proving_key_path,
            required_setup
        );
    }
    if !config.circuit_elf_path.exists() {
        anyhow::bail!(
            "Circuit ELF not found at {:?}. Set CIRCUIT_ELF_PATH env var.",
            config.circuit_elf_path
        );
    }

    // Create proof output directory
    tokio::fs::create_dir_all(&config.proof_output_dir).await?;

    info!("davinci-zkvm v{}", env!("CARGO_PKG_VERSION"));
    info!("  proving key:   {:?}", config.proving_key_path);
    info!("  circuit ELF:   {:?}", config.circuit_elf_path);
    info!("  cargo-zisk:    {}", config.cargo_zisk_bin);
    info!("  zisk version:  {}", config.cargo_zisk_version);
    info!(
        "  zisk mpi:      procs={}, threads={}, bind-to={}",
        config.zisk_mpi_procs, config.zisk_mpi_threads, config.zisk_mpi_bind_to
    );
    info!(
        "  zisk prove:    useEmulator={}, aggregation={}, verifyProofs={}",
        config.zisk_use_emulator, config.zisk_aggregation, config.zisk_verify_proofs
    );
    info!(
        "  ballot aggregation: {}",
        if config.ballot_aggregation { "enabled (STARK proofs stripped from guest input)" } else { "disabled" }
    );
    info!("  proof output:  {:?}", config.proof_output_dir);
    info!("  listen:        {}", config.listen_addr);

    let prover = Arc::new(ProverHandle::new(config.clone()));
    let state = AppState {
        config: config.clone(),
        prover,
    };
    let app = router(state);

    let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;
    info!("Listening on http://{}", config.listen_addr);
    axum::serve(listener, app).await?;

    Ok(())
}
