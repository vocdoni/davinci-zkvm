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
use tracing::{error, info};
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
        let result = run_prove(&config, &task).await;
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

async fn run_prove(config: &Config, task: &ProveTask) -> anyhow::Result<()> {
    let output = Command::new(&config.cargo_zisk_bin)
        .arg("prove")
        .arg("--elf").arg(&config.circuit_elf_path)
        .arg("--input").arg(&task.input_path)
        .arg("--proving-key").arg(&config.proving_key_path)
        .arg("--output-dir").arg(&task.output_dir)
        .arg("--emulator")
        .arg("--aggregation")
        .arg("--final-snark")
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
