//! Proof worker: background task that processes jobs sequentially.
//!
//! Only one proof job runs at a time because the ZisK prover uses all available
//! GPU/CPU resources. Jobs are held in a channel queue and processed in order.

use crate::config::Config;
use crate::types::{Job, JobStatus};
use dashmap::DashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::process::Command;
use tracing::{error, info, warn};
use uuid::Uuid;
use chrono::Utc;

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
    /// Create a new prover handle, spawning the background worker task.
    pub fn new(config: Config) -> Self {
        let jobs: Arc<DashMap<Uuid, Job>> = Arc::new(DashMap::new());
        let (sender, receiver) = tokio::sync::mpsc::channel::<ProveTask>(config.max_queue_size);

        let worker_jobs = jobs.clone();
        tokio::spawn(worker_loop(config, receiver, worker_jobs));

        Self { jobs, sender }
    }

    /// Submit a new proof job. Returns the job ID, or an error if the queue is full.
    pub async fn submit(&self, input_bytes: Vec<u8>, proof_output_dir: &PathBuf) -> anyhow::Result<Uuid> {
        let job_id = Uuid::new_v4();
        let job = Job::new(job_id);
        self.jobs.insert(job_id, job);

        // Write input bytes to a temp file for this job
        let job_dir = proof_output_dir.join(job_id.to_string());
        tokio::fs::create_dir_all(&job_dir).await?;
        let input_path = job_dir.join("input.bin");
        tokio::fs::write(&input_path, &input_bytes).await?;
        let output_dir = job_dir.clone();

        let task = ProveTask { job_id, input_path, output_dir };
        self.sender.try_send(task).map_err(|e| anyhow::anyhow!("queue is full or closed: {}", e))?;
        Ok(job_id)
    }

    /// Return the number of jobs currently queued (not yet started).
    pub fn queue_len(&self) -> usize {
        self.jobs.iter().filter(|e| e.status == JobStatus::Queued).count()
    }
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

/// Detects transient CUDA cold-start failures.
///
/// # Background
///
/// ZisK uses OpenMPI internally. On container cold-start, OpenMPI's atexit
/// handler calls `MPI_Finalize` (which destroys the CUDA context) before the
/// NTT_Goldilocks_GPU destructor runs. This causes a `cudaGetLastError: context
/// is destroyed (709)` abort on the **first** `cargo-zisk prove` invocation
/// after the container starts. Subsequent invocations succeed normally.
///
/// This is a ZisK/OpenMPI bug, not a problem with the input or the proving key.
/// We handle it transparently with up to `MAX_CUDA_RETRIES` automatic retries,
/// hiding the crash output from the API consumer.
fn is_transient_cuda_error(msg: &str) -> bool {
    msg.contains("context is destroyed")
        || msg.contains("cudaGetLastError")
        || msg.contains("SIGABRT")
        || msg.contains("MPI_ERRORS_ARE_FATAL")
}

/// Maximum number of automatic retries for transient CUDA cold-start errors.
const MAX_CUDA_RETRIES: u32 = 3;

/// Retry delay between CUDA cold-start retries.
const CUDA_RETRY_DELAY_SECS: u64 = 5;

/// Run prove, automatically retrying up to [`MAX_CUDA_RETRIES`] times on
/// transient CUDA cold-start errors. The crash output is suppressed on retried
/// attempts and is only surfaced if all retries are exhausted.
async fn run_prove_with_retry(config: &Config, task: &ProveTask) -> anyhow::Result<()> {
    let mut last_err = anyhow::anyhow!("prove never attempted");
    for attempt in 1..=MAX_CUDA_RETRIES + 1 {
        match run_prove(config, task).await {
            Ok(()) => return Ok(()),
            Err(e) if is_transient_cuda_error(&e.to_string()) && attempt <= MAX_CUDA_RETRIES => {
                warn!(
                    "Job {} hit transient CUDA cold-start error (attempt {}/{}), \
                     retrying in {}s",
                    task.job_id, attempt, MAX_CUDA_RETRIES, CUDA_RETRY_DELAY_SECS
                );
                last_err = e;
                tokio::time::sleep(tokio::time::Duration::from_secs(CUDA_RETRY_DELAY_SECS)).await;
            }
            Err(e) => return Err(e),
        }
    }
    Err(last_err)
}

async fn run_prove(config: &Config, task: &ProveTask) -> anyhow::Result<()> {
    // Produces a ZisK STARK proof (vadcop_final_proof.bin).
    //
    // NOTE: --final-snark is intentionally NOT passed here.
    //
    // ZisK's full pipeline ends with an optional FFlonk BN254 zkSNARK stage
    // ("recursivef" → final.zkey) that would produce a compact, on-chain-verifiable
    // proof.  However, the distributed v0.15.0 proving key does not include the
    // required `final/` artifacts (final.so, final.zkey, final.dat).  Passing
    // --final-snark with the current proving key causes proofman to silently
    // discard the error (the result of generate_fflonk_snark_proof is `let _`),
    // so the flag has no effect: it only wastes initialisation time.
    //
    // When Polygon releases the final-snark proving key artifacts, re-add:
    //   .arg("--final-snark")
    // and update the /proof download endpoint to serve the resulting JSON file
    // instead of vadcop_final_proof.bin.
    let output = Command::new(&config.cargo_zisk_bin)
        .arg("prove")
        .arg("--elf").arg(&config.circuit_elf_path)
        .arg("--input").arg(&task.input_path)
        .arg("--proving-key").arg(&config.proving_key_path)
        .arg("--output-dir").arg(&task.output_dir)
        .arg("--emulator")
        .arg("--aggregation")
        .arg("--verify-proofs")
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("failed to spawn cargo-zisk: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        anyhow::bail!("cargo-zisk prove failed (exit {}): {}\n{}", output.status, stderr, stdout);
    }
    Ok(())
}
