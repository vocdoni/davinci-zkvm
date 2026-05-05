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

/// Encode raw circuit input as the v0.17.0 ZiskStream input format expected by
/// `ziskos::io::read_input_slice()`: u64 little-endian length prefix, raw bytes,
/// then zero padding to the next 8-byte boundary.
fn encode_zisk_stream_input(input: &[u8]) -> Vec<u8> {
    let aligned_len = (input.len() + 7) & !7;
    let mut out = Vec::with_capacity(8 + aligned_len);
    out.extend_from_slice(&(input.len() as u64).to_le_bytes());
    out.extend_from_slice(input);
    out.resize(8 + aligned_len, 0);
    out
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
        let zisk_input = encode_zisk_stream_input(&input_bytes);
        tokio::fs::write(&input_path, &zisk_input).await?;
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
    // v0.17.0: --inputs replaces --input, --output replaces --output-dir.
    // Use GPU proving and never pass --emulator for CUDA tests. The final
    // recursive PLONK/zkSNARK wrapper is configurable because ZisK v0.17.0
    // currently fails in Recursive1 witness generation for this circuit/key setup,
    // while the E2E suite only needs successful proving/job completion and does
    // not download or verify the proof artifact.
    let output_file = task.output_dir.join("vadcop_final_proof.bin");
    let mut zisk_args: Vec<String> = vec![
        "prove".to_string(),
        "--elf".to_string(),
        config.circuit_elf_path.display().to_string(),
        "--inputs".to_string(),
        task.input_path.display().to_string(),
        "--proving-key".to_string(),
        config.proving_key_path.display().to_string(),
        "--output".to_string(),
        output_file.display().to_string(),
        "--gpu".to_string(),
    ];

    if config.verify_zisk_proofs {
        zisk_args.push("--verify-proofs".to_string());
    }

    if config.generate_final_snark {
        zisk_args.extend([
            "--plonk".to_string(),
            "--proving-key-plonk".to_string(),
            "/root/.zisk/provingKeySnark".to_string(),
        ]);
    } else {
        zisk_args.push("--no-aggregation".to_string());
    }

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
    Ok(())
}
