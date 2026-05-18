//! davinci-zkvm prover service.
//!
//! Exposes an HTTP API that accepts batched DAVINCI state-transition prove
//! requests, runs ZisK underneath, and returns an on-chain-verifiable PLONK
//! SNARK ready to feed to the `ZiskVerifier.verifySnarkProof` contract.
//!
//! See the package docs for the full HTTP surface; the short version is:
//! `POST /prove` to queue a job, `GET /jobs/:id` to poll, `GET
//! /jobs/:id/snark` to download the Solidity-ready payload.

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
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "davinci_zkvm=info,tower_http=info".into()),
        )
        .init();

    let config = Config::from_env();

    // Both proving keys must be on disk before we start accepting requests;
    // there is no way to recover from a missing key mid-job.
    if !config.proving_key_path.exists() {
        anyhow::bail!(
            "ZisK STARK proving key not found at {:?}. \
             Mount the directory at /proving-key, or set PROVING_KEY_PATH.",
            config.proving_key_path
        );
    }
    if !config.proving_key_plonk_path.exists() {
        anyhow::bail!(
            "ZisK PLONK proving key not found at {:?}. \
             Mount the directory at /proving-key-plonk, or set PROVING_KEY_PLONK_PATH. \
             The PLONK key is required: the service always wraps the STARK into a \
             SNARK suitable for on-chain verification.",
            config.proving_key_plonk_path
        );
    }
    if !config.circuit_elf_path.exists() {
        anyhow::bail!(
            "Circuit ELF not found at {:?}. Set CIRCUIT_ELF_PATH.",
            config.circuit_elf_path
        );
    }

    tokio::fs::create_dir_all(&config.proof_output_dir).await?;

    info!("davinci-zkvm v{}", env!("CARGO_PKG_VERSION"));
    info!("  stark key:    {:?}", config.proving_key_path);
    info!("  plonk key:    {:?}", config.proving_key_plonk_path);
    info!("  circuit ELF:  {:?}", config.circuit_elf_path);
    info!("  cargo-zisk:   {}", config.cargo_zisk_bin);
    info!(
        "  zisk mpi:     procs={}, threads={}, bind-to={}",
        config.zisk_mpi_procs, config.zisk_mpi_threads, config.zisk_mpi_bind_to
    );
    info!("  proof output: {:?}", config.proof_output_dir);
    info!("  listen:       {}", config.listen_addr);

    let prover = Arc::new(ProverHandle::new(config.clone()));
    let state = AppState { config: config.clone(), prover };
    let app = router(state);

    let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;
    info!("Listening on http://{}", config.listen_addr);
    axum::serve(listener, app).await?;

    Ok(())
}
