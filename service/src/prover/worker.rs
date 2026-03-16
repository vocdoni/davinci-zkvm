//! Proof worker: background task that processes jobs sequentially.
//!
//! Only one proof job runs at a time because the ZisK prover uses all available
//! GPU/CPU resources. Jobs are held in a channel queue and processed in order.

use crate::config::Config;
use crate::types::{Job, JobStatus};
use chrono::Utc;
use dashmap::DashMap;
use davinci_zkvm_input_gen::MAX_BATCH_SIZE;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tracing::{error, info, warn};
use uuid::Uuid;

pub struct ProverHandle {
    pub jobs: Arc<DashMap<Uuid, Job>>,
    sender: tokio::sync::mpsc::Sender<ProveTask>,
}

struct ProveTask {
    job_id: Uuid,
    input_path: PathBuf,
    output_dir: PathBuf,
}

fn build_zisk_args(config: &Config, task: &ProveTask) -> Vec<String> {
    let mut args = vec![
        "prove".to_string(),
        "--elf".to_string(),
        config.circuit_elf_path.display().to_string(),
        "--inputs".to_string(),
        task.input_path.display().to_string(),
        "--proving-key".to_string(),
        config.proving_key_path.display().to_string(),
        "--output-dir".to_string(),
        task.output_dir.display().to_string(),
    ];
    if config.zisk_use_emulator {
        args.push("--emulator".to_string());
    }
    if config.zisk_aggregation {
        args.push("--aggregation".to_string());
        args.push("--compressed".to_string());
    }
    if config.zisk_verify_proofs {
        args.push("--verify-proofs".to_string());
    }
    args
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
    pub async fn submit(
        &self,
        input_bytes: Vec<u8>,
        proof_output_dir: &PathBuf,
    ) -> anyhow::Result<Uuid> {
        ensure_zisk_input_alignment(&input_bytes)?;

        let job_id = Uuid::new_v4();
        let job = Job::new(job_id);
        self.jobs.insert(job_id, job);

        // Write input bytes to a temp file for this job
        let job_dir = proof_output_dir.join(job_id.to_string());
        tokio::fs::create_dir_all(&job_dir).await?;
        let input_path = job_dir.join("input.bin");
        tokio::fs::write(&input_path, &input_bytes).await?;
        let output_dir = job_dir.clone();

        let task = ProveTask {
            job_id,
            input_path,
            output_dir,
        };
        self.sender
            .try_send(task)
            .map_err(|e| anyhow::anyhow!("queue is full or closed: {}", e))?;
        Ok(job_id)
    }

    /// Return the number of jobs currently queued (not yet started).
    pub fn queue_len(&self) -> usize {
        self.jobs
            .iter()
            .filter(|e| e.status == JobStatus::Queued)
            .count()
    }
}

fn ensure_zisk_input_alignment(input_bytes: &[u8]) -> anyhow::Result<()> {
    if input_bytes.len() % 8 != 0 {
        anyhow::bail!(
            "zkVM input size must be a multiple of 8 bytes, got {}",
            input_bytes.len()
        );
    }
    // The input is wrapped by wrap_for_zisk_vm(): [payload_len(u64) | payload | padding].
    // Validate the outer framing and then the guest header inside the payload.
    if input_bytes.len() < 8 {
        anyhow::bail!("zkVM input is too short to contain the ZisK framing header");
    }
    let payload_len = u64::from_le_bytes(input_bytes[0..8].try_into().unwrap()) as usize;
    if payload_len + 8 > input_bytes.len() {
        anyhow::bail!(
            "zkVM input framing declares payload_len={} but file is only {} bytes",
            payload_len,
            input_bytes.len()
        );
    }
    if payload_len < 32 {
        anyhow::bail!("zkVM payload is too short to contain the guest header");
    }
    let payload = &input_bytes[8..8 + payload_len];
    let magic = u64::from_le_bytes(payload[0..8].try_into().unwrap());
    let nproofs = u64::from_le_bytes(payload[16..24].try_into().unwrap()) as usize;
    let n_public = u64::from_le_bytes(payload[24..32].try_into().unwrap()) as usize;
    if magic != u64::from_le_bytes(*b"DSTARKB!") {
        anyhow::bail!(
            "zkVM input must start with the raw DSTARKB! guest block magic, got {:#x}",
            magic
        );
    }
    if nproofs == 0 || nproofs > MAX_BATCH_SIZE || !nproofs.is_power_of_two() {
        anyhow::bail!("zkVM input has invalid proof count in guest header: {}", nproofs);
    }
    if n_public != 123 {
        anyhow::bail!(
            "zkVM input has invalid public value count in guest header: {}",
            n_public
        );
    }
    Ok(())
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
    // proof.  However, the currently distributed proving key does not include the
    // required `final/` artifacts (final.so, final.zkey, final.dat).  Passing
    // --final-snark with the current proving key causes proofman to silently
    // discard the error (the result of generate_fflonk_snark_proof is `let _`),
    // so the flag has no effect: it only wastes initialisation time.
    //
    // When Polygon releases the final-snark proving key artifacts, re-add:
    //   .arg("--final-snark")
    // and update the /proof download endpoint to serve the resulting JSON file
    // instead of vadcop_final_proof.bin.
    let zisk_args = build_zisk_args(config, task);

    let stdout_path = task.output_dir.join("cargo-zisk.stdout.log");
    let stderr_path = task.output_dir.join("cargo-zisk.stderr.log");
    let stdout = std::fs::File::create(&stdout_path)
        .map_err(|e| anyhow::anyhow!("failed to create {:?}: {}", stdout_path, e))?;
    let stderr = std::fs::File::create(&stderr_path)
        .map_err(|e| anyhow::anyhow!("failed to create {:?}: {}", stderr_path, e))?;

    let status = if config.zisk_mpi_procs > 1 {
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
        cmd.stdout(stdout);
        cmd.stderr(stderr);
        cmd.status()
            .await
            .map_err(|e| anyhow::anyhow!("failed to spawn mpirun: {}", e))?
    } else {
        let mut cmd = Command::new(&config.cargo_zisk_bin);
        cmd.args(&zisk_args);
        cmd.stdout(stdout);
        cmd.stderr(stderr);
        cmd.status()
            .await
            .map_err(|e| anyhow::anyhow!("failed to spawn cargo-zisk: {}", e))?
    };

    if !status.success() {
        let stdout = read_log_file(&stdout_path).await;
        let stderr = read_log_file(&stderr_path).await;
        anyhow::bail!(
            "cargo-zisk prove failed (exit {}): {}\n{}",
            status,
            stderr,
            stdout
        );
    }
    Ok(())
}

async fn read_log_file(path: &PathBuf) -> String {
    let mut buf = String::new();
    match File::open(path).await {
        Ok(mut file) => {
            let _ = file.read_to_string(&mut buf).await;
            buf
        }
        Err(_) => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::build_zisk_args;
    use super::ensure_zisk_input_alignment;
    use super::read_log_file;
    use super::ProveTask;
    use crate::config::Config;
    use std::path::PathBuf;
    use tokio::process::Command;
    use uuid::Uuid;

    #[test]
    fn rejects_misaligned_zisk_input() {
        let err = ensure_zisk_input_alignment(&vec![0u8; 15]).unwrap_err();
        assert!(
            err.to_string().contains("multiple of 8 bytes"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn accepts_aligned_zisk_input() {
        // Build a valid wrapped input: [payload_len(u64) | DSTARKB! | log_n | nproofs | n_public | ...]
        let mut payload = Vec::new();
        payload.extend_from_slice(&u64::from_le_bytes(*b"DSTARKB!").to_le_bytes());
        payload.extend_from_slice(&4u64.to_le_bytes());
        payload.extend_from_slice(&2u64.to_le_bytes());
        payload.extend_from_slice(&123u64.to_le_bytes());
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&payload);
        ensure_zisk_input_alignment(&bytes).unwrap();
    }

    #[test]
    fn rejects_invalid_guest_magic() {
        // Wrapped input with wrong magic
        let mut payload = Vec::new();
        payload.extend_from_slice(&0u64.to_le_bytes());
        payload.extend_from_slice(&4u64.to_le_bytes());
        payload.extend_from_slice(&2u64.to_le_bytes());
        payload.extend_from_slice(&123u64.to_le_bytes());
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&payload);
        let err = ensure_zisk_input_alignment(&bytes).unwrap_err();
        assert!(
            err.to_string().contains("DSTARKB! guest block magic"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn prove_args_default_to_plain_non_recursive_proving() {
        let config = Config {
            listen_addr: "127.0.0.1:8080".to_string(),
            cargo_zisk_bin: "/usr/local/bin/cargo-zisk".to_string(),
            cargo_zisk_version: "test".to_string(),
            circuit_elf_path: PathBuf::from("/app/circuit.elf"),
            proving_key_path: PathBuf::from("/proving-key"),
            proof_output_dir: PathBuf::from("/proofs"),
            max_queue_size: 8,
            zisk_mpi_procs: 1,
            zisk_mpi_threads: 0,
            zisk_mpi_bind_to: "none".to_string(),
            zisk_aggregation: false,
            zisk_verify_proofs: false,
            zisk_use_emulator: false,
        };
        let task = ProveTask {
            job_id: Uuid::nil(),
            input_path: PathBuf::from("/proofs/input.bin"),
            output_dir: PathBuf::from("/proofs/job"),
        };

        let args = build_zisk_args(&config, &task);

        assert!(!args.iter().any(|arg| arg == "--aggregation"));
        assert!(!args.iter().any(|arg| arg == "--compressed"));
        assert!(!args.iter().any(|arg| arg == "--verify-proofs"));
        assert!(!args.iter().any(|arg| arg == "--emulator"));
    }

    #[test]
    fn prove_args_enable_recursive_modes_when_requested() {
        let config = Config {
            listen_addr: "127.0.0.1:8080".to_string(),
            cargo_zisk_bin: "/usr/local/bin/cargo-zisk".to_string(),
            cargo_zisk_version: "test".to_string(),
            circuit_elf_path: PathBuf::from("/app/circuit.elf"),
            proving_key_path: PathBuf::from("/proving-key"),
            proof_output_dir: PathBuf::from("/proofs"),
            max_queue_size: 8,
            zisk_mpi_procs: 1,
            zisk_mpi_threads: 0,
            zisk_mpi_bind_to: "none".to_string(),
            zisk_aggregation: true,
            zisk_verify_proofs: true,
            zisk_use_emulator: true,
        };
        let task = ProveTask {
            job_id: Uuid::nil(),
            input_path: PathBuf::from("/proofs/input.bin"),
            output_dir: PathBuf::from("/proofs/job"),
        };

        let args = build_zisk_args(&config, &task);

        assert!(args.iter().any(|arg| arg == "--aggregation"));
        assert!(args.iter().any(|arg| arg == "--compressed"));
        assert!(args.iter().any(|arg| arg == "--verify-proofs"));
        assert!(args.iter().any(|arg| arg == "--emulator"));
    }

    #[tokio::test]
    async fn status_based_capture_returns_with_detached_child() {
        let dir = tempfile::tempdir().unwrap();
        let stdout_path = dir.path().join("stdout.log");
        let stderr_path = dir.path().join("stderr.log");
        let stdout = std::fs::File::create(&stdout_path).unwrap();
        let stderr = std::fs::File::create(&stderr_path).unwrap();

        let status = Command::new("sh")
            .arg("-lc")
            .arg("echo parent; (sleep 2; echo child >&2) &")
            .stdout(stdout)
            .stderr(stderr)
            .status()
            .await
            .unwrap();

        assert!(status.success());
        let stdout_text = read_log_file(&stdout_path).await;
        assert!(stdout_text.contains("parent"));
    }
}
