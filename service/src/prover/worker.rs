//! Background worker that runs ZisK proves one job at a time.
//!
//! A single ZisK prove saturates the GPU (it allocates ~30 GB of VRAM and
//! pins all available CUDA streams), so jobs are processed strictly in
//! submission order from an in-memory MPSC channel. The HTTP layer never
//! blocks on proving — it only enqueues — which keeps the API responsive
//! even when a long batch is in flight.

use crate::config::Config;
use crate::types::{Job, JobStatus};
use chrono::Utc;
use dashmap::DashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::process::Command;
use tracing::{error, info, warn};
use uuid::Uuid;

/// Handle held by the HTTP layer; submits new jobs and exposes their status.
pub struct ProverHandle {
    pub jobs: Arc<DashMap<Uuid, Job>>,
    sender: tokio::sync::mpsc::Sender<ProveTask>,
}

struct ProveTask {
    job_id: Uuid,
    input_path: PathBuf,
    output_dir: PathBuf,
}

impl ProverHandle {
    /// Spawn the background prove worker and return a handle to it.
    pub fn new(config: Config) -> Self {
        let jobs: Arc<DashMap<Uuid, Job>> = Arc::new(DashMap::new());
        let (sender, receiver) =
            tokio::sync::mpsc::channel::<ProveTask>(config.max_queue_size);

        let worker_jobs = jobs.clone();
        tokio::spawn(worker_loop(config, receiver, worker_jobs));

        Self { jobs, sender }
    }

    /// Queue a new proof job. The input payload is written to disk under a
    /// per-job directory so the prover subprocess can mmap it directly.
    ///
    /// Returns the job ID once the request is accepted, or an error if the
    /// in-memory queue is full.
    pub async fn submit(
        &self,
        input_bytes: Vec<u8>,
        proof_output_dir: &PathBuf,
    ) -> anyhow::Result<Uuid> {
        let job_id = Uuid::new_v4();
        self.jobs.insert(job_id, Job::new(job_id));

        let job_dir = proof_output_dir.join(job_id.to_string());
        tokio::fs::create_dir_all(&job_dir).await?;

        let input_path = job_dir.join("input.bin");
        tokio::fs::write(&input_path, &encode_zisk_input(&input_bytes)).await?;

        let task = ProveTask {
            job_id,
            input_path,
            output_dir: job_dir,
        };
        self.sender
            .try_send(task)
            .map_err(|e| anyhow::anyhow!("queue is full or closed: {}", e))?;
        Ok(job_id)
    }

    /// Number of jobs currently waiting for the worker (not yet started).
    pub fn queue_len(&self) -> usize {
        self.jobs.iter().filter(|e| e.status == JobStatus::Queued).count()
    }
}

/// Wrap raw payload bytes in the framing `ziskos::io::read_input_slice()`
/// expects: an 8-byte little-endian length prefix, then the payload, then
/// zero-padding up to the next 8-byte boundary.
fn encode_zisk_input(payload: &[u8]) -> Vec<u8> {
    let aligned_len = (payload.len() + 7) & !7;
    let mut out = Vec::with_capacity(8 + aligned_len);
    out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    out.extend_from_slice(payload);
    out.resize(8 + aligned_len, 0);
    out
}

async fn worker_loop(
    config: Config,
    mut receiver: tokio::sync::mpsc::Receiver<ProveTask>,
    jobs: Arc<DashMap<Uuid, Job>>,
) {
    info!("Prover worker started");
    while let Some(task) = receiver.recv().await {
        let job_id = task.job_id;
        info!("Starting proof for job {}", job_id);

        // Mark job as running
        if let Some(mut job) = jobs.get_mut(&job_id) {
            job.status = JobStatus::Running;
            job.started_at = Some(Utc::now());
        }

        let start = Instant::now();
        let result = run_prove_with_retry(&config, &task).await;
        let elapsed_ms = start.elapsed().as_millis() as u64;

        if let Some(mut job) = jobs.get_mut(&job_id) {
            job.finished_at = Some(Utc::now());
            job.elapsed_ms = Some(elapsed_ms);
            match result {
                Ok(()) => {
                    job.status = JobStatus::Done;
                    info!("Job {} completed in {}ms", job_id, elapsed_ms);
                }
                Err(e) => {
                    job.status = JobStatus::Failed;
                    job.error = Some(e.to_string());
                    error!("Job {} failed after {}ms: {}", job_id, elapsed_ms, e);
                }
            }
        }
    }
    info!("Prover worker stopped");
}

/// Maximum number of automatic retries when the prover hits a known
/// transient failure.
const MAX_PROVE_RETRIES: u32 = 3;
/// Delay between retries.
const PROVE_RETRY_DELAY_SECS: u64 = 5;

/// Detects prover failures that are known to be transient — same input and
/// the same machine, run it again and it succeeds — so the worker can absorb
/// them without escalating to the API caller.
///
/// Two flavours are covered:
///
/// 1. **CUDA cold-start.** ZisK uses OpenMPI internally; on the very first
///    `cargo-zisk prove` after the container starts, MPI's atexit handler
///    sometimes tears the CUDA context down ahead of the GPU destructor and
///    aborts with `cudaGetLastError: context is destroyed`. Subsequent
///    invocations within the same container never hit it.
/// 2. **Fiat–Shamir flake at large batch sizes.** Around 512 voters we have
///    occasionally seen ZisK return `Proof contribution challenge does not
///    match expected accumulated challenge` for an input that proves cleanly
///    on retry. The exact text is what we match on.
///
/// We deliberately do **not** match the bare `SIGABRT` keyword — it also
/// fires for witness-generation assertions which are deterministic and
/// retrying would just burn budget.
fn is_transient_prover_error(msg: &str) -> bool {
    msg.contains("context is destroyed")
        || msg.contains("cudaGetLastError")
        || msg.contains("MPI_ERRORS_ARE_FATAL")
        || msg.contains("Proof contribution challenge does not match")
}

/// Run `cargo-zisk prove`, transparently retrying [`MAX_PROVE_RETRIES`] times
/// on the transient prover errors listed in [`is_transient_prover_error`].
/// Output from retried attempts is hidden from the caller; the final error
/// is only surfaced if every attempt fails.
async fn run_prove_with_retry(config: &Config, task: &ProveTask) -> anyhow::Result<()> {
    let mut last_err = anyhow::anyhow!("prove never attempted");
    for attempt in 1..=MAX_PROVE_RETRIES + 1 {
        match run_prove(config, task).await {
            Ok(()) => return Ok(()),
            Err(e) if attempt <= MAX_PROVE_RETRIES && is_transient_prover_error(&e.to_string()) => {
                warn!(
                    "Job {} hit a transient prover error (attempt {}/{}); retrying in {}s",
                    task.job_id, attempt, MAX_PROVE_RETRIES, PROVE_RETRY_DELAY_SECS
                );
                last_err = e;
                tokio::time::sleep(tokio::time::Duration::from_secs(PROVE_RETRY_DELAY_SECS))
                    .await;
            }
            Err(e) => return Err(e),
        }
    }
    Err(last_err)
}

async fn run_prove(config: &Config, task: &ProveTask) -> anyhow::Result<()> {
    // Run the full ZisK prove pipeline (STARK → recursive aggregation →
    // recursivef → fflonk PLONK wrap). The output at `proof.bin` is a
    // bincode-encoded ZisK `Proof` whose body is the PLONK SNARK; the
    // intermediate VADCOP STARK is never written to disk.
    let proof_output_path = task.output_dir.join("proof.bin");
    let zisk_args: Vec<String> = vec![
        "prove".to_string(),
        "--elf".to_string(),
        config.circuit_elf_path.display().to_string(),
        "--inputs".to_string(),
        task.input_path.display().to_string(),
        "--proving-key".to_string(),
        config.proving_key_path.display().to_string(),
        "--proving-key-plonk".to_string(),
        config.proving_key_plonk_path.display().to_string(),
        "--output".to_string(),
        proof_output_path.display().to_string(),
        "--emulator".to_string(),
        "--gpu".to_string(),
        "--plonk".to_string(),
        "--verify-proofs".to_string(),
    ];

    let output = if config.zisk_mpi_procs > 1 {
        // Parallel proving mode as documented by ZisK:
        // mpirun --bind-to none -np P -x OMP_NUM_THREADS=T -x RAYON_NUM_THREADS=T cargo-zisk ...
        let mut cmd = Command::new("mpirun");
        cmd.arg("--bind-to")
            .arg(&config.zisk_mpi_bind_to)
            .arg("-np")
            .arg(config.zisk_mpi_procs.to_string());

        if config.zisk_mpi_threads > 0 {
            cmd.arg("-x")
                .arg(format!("OMP_NUM_THREADS={}", config.zisk_mpi_threads))
                .arg("-x")
                .arg(format!("RAYON_NUM_THREADS={}", config.zisk_mpi_threads));
        }

        cmd.arg(&config.cargo_zisk_bin);
        cmd.args(&zisk_args);
        cmd.output()
            .await
            .map_err(|e| anyhow::anyhow!("failed to spawn mpirun: {}", e))?
    } else {
        let mut cmd = Command::new(&config.cargo_zisk_bin);
        cmd.args(&zisk_args);
        cmd.output()
            .await
            .map_err(|e| anyhow::anyhow!("failed to spawn cargo-zisk: {}", e))?
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        anyhow::bail!("cargo-zisk prove failed (exit {}): {}\n{}", output.status, stderr, stdout);
    }

    // The raw `proof.bin` is a bincode-encoded ZisK `Proof` struct that is
    // not directly usable on-chain. Decode it once here, write the four
    // Solidity-ready byte strings to `snark.json`, and split the
    // `publicValues` blob out into `publics.bin` for callers that only want
    // the program's `commit_slice` output. These post-processing steps are
    // millisecond-scale; failing them does not invalidate the proof itself
    // (consumers can always fall back to `cargo-zisk verify` against
    // `proof.bin`), so we log and continue rather than failing the job.
    let proof_path = task.output_dir.join("proof.bin");
    match crate::prover::snark::parse_proof_bin(&proof_path) {
        Ok(snark) => {
            let snark_path = task.output_dir.join("snark.json");
            match serde_json::to_vec_pretty(&snark) {
                Ok(buf) => {
                    if let Err(e) = tokio::fs::write(&snark_path, &buf).await {
                        warn!("write snark.json: {}", e);
                    }
                }
                Err(e) => warn!("serialize snark.json: {}", e),
            }
            if let Some(stripped) = snark.public_values.strip_prefix("0x") {
                if let Ok(bytes) = hex::decode(stripped) {
                    let publics_path = task.output_dir.join("publics.bin");
                    if let Err(e) = tokio::fs::write(&publics_path, &bytes).await {
                        warn!("write publics.bin: {}", e);
                    }
                }
            }
        }
        Err(e) => warn!("parse proof.bin into SNARK payload: {}", e),
    }

    Ok(())
}
