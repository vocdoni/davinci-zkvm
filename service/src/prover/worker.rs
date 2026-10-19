//! Background worker that runs ZisK proves one job at a time.
//!
//! A single ZisK prove saturates the GPU (it allocates ~30 GB of VRAM and
//! pins all available CUDA streams), so jobs are processed strictly in
//! submission order from an in-memory MPSC channel. The HTTP layer never
//! blocks on proving — it only enqueues — which keeps the API responsive
//! even when a long batch is in flight.

use crate::config::Config;
use crate::types::{Job, JobKind, JobStatus};
use chrono::Utc;
use dashmap::DashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use uuid::Uuid;

/// Error text of a cancelled job (`DELETE /jobs/:id`).
pub const CANCELLED: &str = "cancelled";
/// How long a cancelled prover group gets between SIGTERM and SIGKILL.
const KILL_GRACE: Duration = Duration::from_secs(5);

/// Handle held by the HTTP layer; submits new jobs and exposes their status.
pub struct ProverHandle {
    pub jobs: Arc<DashMap<Uuid, Job>>,
    sender: tokio::sync::mpsc::Sender<ProveTask>,
    worker: tokio::task::JoinHandle<()>,
}

struct ProveTask {
    job_id: Uuid,
    input_path: PathBuf,
    output_dir: PathBuf,
    elf_path: PathBuf,
    plonk: bool,
    /// Ballot proofs in the batch (0 for fold/finalize jobs); decides
    /// whether the first attempt already runs with --minimal-memory.
    proof_count: usize,
    /// The job's cancel token (shared with its `Job`).
    cancel: CancellationToken,
}

impl ProverHandle {
    /// Spawn the background prove worker and return a handle to it.
    pub fn new(config: Config) -> Self {
        Self::spawn(config, |config, task| async move {
            run_prove_with_retry(&config, &task).await
        })
    }

    fn spawn<F, Fut>(config: Config, prove: F) -> Self
    where
        F: Fn(Config, ProveTask) -> Fut + Send + 'static,
        Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        let jobs: Arc<DashMap<Uuid, Job>> = Arc::new(DashMap::new());
        let (sender, receiver) = tokio::sync::mpsc::channel::<ProveTask>(config.max_queue_size);

        let worker_jobs = jobs.clone();
        let worker = tokio::spawn(worker_loop(config, receiver, worker_jobs, prove));

        Self {
            jobs,
            sender,
            worker,
        }
    }

    /// False once the worker task has ended (returned, panicked or aborted).
    pub fn worker_running(&self) -> bool {
        !self.worker.is_finished()
    }

    /// Queue a new proof job. The input payload is written to disk under a
    /// per-job directory so the prover subprocess can mmap it directly.
    ///
    /// Returns the job ID once the request is accepted, or an error if the
    /// in-memory queue is full.
    pub async fn submit(
        &self,
        input_bytes: Vec<u8>,
        proof_output_dir: &Path,
        kind: JobKind,
        elf_path: PathBuf,
        parent_job_ids: Vec<Uuid>,
        proof_count: usize,
    ) -> anyhow::Result<Uuid> {
        let job_id = Uuid::new_v4();
        let job = Job::new(job_id, kind, parent_job_ids);
        let cancel = job.cancel.clone();
        self.jobs.insert(job_id, job);

        // A rejected job must not stay Queued in the map (it inflates
        // queue_len forever) nor leave its witness on disk.
        let job_dir = proof_output_dir.join(job_id.to_string());
        let res = self
            .enqueue(
                input_bytes,
                &job_dir,
                kind,
                elf_path,
                job_id,
                proof_count,
                cancel,
            )
            .await;
        if res.is_err() {
            self.jobs.remove(&job_id);
            if let Err(e) = tokio::fs::remove_dir_all(&job_dir).await {
                if e.kind() != std::io::ErrorKind::NotFound {
                    error!("Job {}: could not remove rejected job dir: {}", job_id, e);
                }
            }
        }
        res.map(|()| job_id)
    }

    #[allow(clippy::too_many_arguments)]
    async fn enqueue(
        &self,
        input_bytes: Vec<u8>,
        job_dir: &Path,
        kind: JobKind,
        elf_path: PathBuf,
        job_id: Uuid,
        proof_count: usize,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        tokio::fs::create_dir_all(job_dir).await?;

        // The batch and results guests read one read_input_slice frame and
        // need the u64 length prefix; the aggregator guest parses
        // self-delimiting frames and takes the payload raw.
        let input_path = job_dir.join("input.bin");
        let encoded = match kind {
            JobKind::Batch | JobKind::BatchStark | JobKind::Results => {
                encode_zisk_input(&input_bytes)
            }
            JobKind::Fold | JobKind::Finalize => input_bytes,
        };
        tokio::fs::write(&input_path, &encoded).await?;

        let task = ProveTask {
            job_id,
            input_path,
            output_dir: job_dir.to_path_buf(),
            elf_path,
            plonk: kind.is_plonk(),
            proof_count,
            cancel,
        };
        self.sender
            .try_send(task)
            .map_err(|e| anyhow::anyhow!("queue is full or closed: {}", e))
    }

    /// Cancels a job: a queued one fails now and never starts, a running one
    /// once its prover process group is dead. A finished job is left as is.
    /// Returns the job after the change, `None` for an unknown id.
    pub async fn cancel(&self, id: Uuid, proof_output_dir: &Path) -> Option<Job> {
        let (job, queued) = {
            let mut job = self.jobs.get_mut(&id)?;
            let queued = job.status == JobStatus::Queued;
            match job.status {
                JobStatus::Queued => {
                    // Under the map lock: the worker checks the token under it
                    // too, so the job either starts or is skipped, never both.
                    job.cancel.cancel();
                    job.status = JobStatus::Failed;
                    job.error = Some(CANCELLED.to_string());
                    job.finished_at = Some(Utc::now());
                }
                JobStatus::Running => job.cancel.cancel(),
                JobStatus::Done | JobStatus::Failed => {}
            }
            (job.clone(), queued)
        };
        if queued {
            info!("Job {} cancelled while queued", id);
            remove_job_dir(&proof_output_dir.join(id.to_string()), id).await;
        } else if job.status == JobStatus::Running {
            info!("Job {} cancel requested while running", id);
        }
        Some(job)
    }

    /// Number of jobs currently waiting for the worker (not yet started).
    pub fn queue_len(&self) -> usize {
        self.jobs
            .iter()
            .filter(|e| e.status == JobStatus::Queued)
            .count()
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

async fn worker_loop<F, Fut>(
    config: Config,
    mut receiver: tokio::sync::mpsc::Receiver<ProveTask>,
    jobs: Arc<DashMap<Uuid, Job>>,
    prove: F,
) where
    F: Fn(Config, ProveTask) -> Fut,
    Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    info!("Prover worker started");
    while let Some(task) = receiver.recv().await {
        let job_id = task.job_id;
        let cancel = task.cancel.clone();
        let job_dir = config.proof_output_dir.join(job_id.to_string());

        // Mark job as running, unless it was cancelled while queued (checked
        // under the map lock `ProverHandle::cancel` fires it under).
        let skip = match jobs.get_mut(&job_id) {
            Some(mut job) if !cancel.is_cancelled() => {
                job.status = JobStatus::Running;
                job.started_at = Some(Utc::now());
                false
            }
            Some(_) => true,
            None => cancel.is_cancelled(),
        };
        if skip {
            info!("Skipping cancelled job {}", job_id);
            remove_job_dir(&job_dir, job_id).await;
            continue;
        }
        info!("Starting proof for job {}", job_id);

        // Each job runs in its own task so a panic fails that job only
        // instead of taking the worker, and with it the queue, down.
        let start = Instant::now();
        let result = match tokio::spawn(prove(config.clone(), task)).await {
            Ok(r) => r,
            Err(e) => Err(anyhow::anyhow!(
                "prover panicked: {}",
                join_error_message(e)
            )),
        };
        let elapsed_ms = start.elapsed().as_millis() as u64;
        let cancelled = cancel.is_cancelled();

        // The input is the private witness (seed, overwrite and refresh sets);
        // once the proof exists it must not linger on disk. A cancelled job
        // leaves nothing behind.
        if cancelled {
            remove_job_dir(&job_dir, job_id).await;
        } else if !config.keep_inputs {
            let input_path = job_dir.join("input.bin");
            if let Err(e) = tokio::fs::remove_file(&input_path).await {
                if e.kind() != std::io::ErrorKind::NotFound {
                    error!("Job {}: could not delete input.bin: {}", job_id, e);
                }
            }
        }

        if let Some(mut job) = jobs.get_mut(&job_id) {
            job.finished_at = Some(Utc::now());
            job.elapsed_ms = Some(elapsed_ms);
            match result {
                _ if cancelled => {
                    job.status = JobStatus::Failed;
                    job.error = Some(CANCELLED.to_string());
                    info!("Job {} cancelled after {}ms", job_id, elapsed_ms);
                }
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

async fn remove_job_dir(dir: &Path, job_id: Uuid) {
    if let Err(e) = tokio::fs::remove_dir_all(dir).await {
        if e.kind() != std::io::ErrorKind::NotFound {
            error!("Job {}: could not remove job dir: {}", job_id, e);
        }
    }
}

fn join_error_message(e: tokio::task::JoinError) -> String {
    if !e.is_panic() {
        return e.to_string();
    }
    let p = e.into_panic();
    if let Some(s) = p.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = p.downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string panic payload".to_string()
    }
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
/// 2. **Fiat–Shamir flake at large batch sizes.** At the larger batch sizes
///    we have occasionally seen ZisK return `Proof contribution challenge does not
///    match expected accumulated challenge` for an input that proves cleanly
///    on retry. The exact text is what we match on.
///
/// 3. **Recursion-stage witness flakes.** Rarely, the recursive stages
///    abort with `Failed assert in …` inside a circom verifier template
///    (`VerifyGlobalConstraints`, `VerifyFinalPol0`, `VerifyEvaluations0`)
///    or `Error generating witness for instance … of type VadcopFinal`.
///    Their input is ZisK's own freshly generated inner proofs, not user
///    data, and the same job proves cleanly on retry. (A *persistently*
///    failing `VerifyEvaluations0`/`VerifyFinalPol0` means a stale
///    proving key — retries will burn out and surface the error.)
/// 4. **Counter timeout.** `Counter timeout after 10 minutes … Cancelling`
///    is an internal ZisK synchronization stall, not an input problem.
/// 5. **OOM kill (`signal: 9`).** Large batches can be reaped by the
///    kernel under transient memory pressure; retrying when the pressure
///    has passed succeeds.
/// 6. **SNARK self-check.** `--verify-proof` occasionally rejects the fresh
///    PLONK wrap (`SNARK proof verification failed`) after a clean STARK; the
///    same input verifies on rerun.
/// 7. **Host crash (`signal: 11` SIGSEGV, `signal: 7` SIGBUS).** The
///    `cargo-zisk` process itself died in native code (CUDA, libc, MPI),
///    seen on a healthy host after hundreds of clean jobs. This is a
///    host-side crash of the prover, not a guest assertion: a deterministic
///    guest failure exits with an error code or a fail mask, never a
///    segfault. The same job proves on retry.
///
/// We deliberately do **not** match the bare `SIGABRT` keyword or generic
/// witness-generation failures — those also fire for deterministic guest
/// assertions where retrying would just burn budget.
fn is_transient_prover_error(msg: &str) -> bool {
    msg.contains("context is destroyed")
        || msg.contains("cudaGetLastError")
        || msg.contains("MPI_ERRORS_ARE_FATAL")
        || msg.contains("Proof contribution challenge does not match")
        || (msg.contains("Error generating witness") && msg.contains("VadcopFinal"))
        || msg.contains("Failed assert in template/function VerifyGlobalConstraints")
        || msg.contains("Failed assert in template/function VerifyFinalPol")
        || msg.contains("Failed assert in template/function VerifyEvaluations")
        || msg.contains("Counter timeout after")
        || msg.contains("signal: 9")
        || exit_signal(msg, "11")
        || exit_signal(msg, "7")
        || msg.contains("SNARK proof verification failed")
}

/// True if `msg` holds `signal: <num>` as a whole number, the form
/// `ExitStatus` prints (`signal: 11 (SIGSEGV) (core dumped)`), so `7` does
/// not match `signal: 70`.
fn exit_signal(msg: &str, num: &str) -> bool {
    let key = format!("signal: {num}");
    msg.match_indices(&key)
        .any(|(i, _)| !msg[i + key.len()..].starts_with(|c: char| c.is_ascii_digit()))
}

/// Run `cargo-zisk prove`, transparently retrying [`MAX_PROVE_RETRIES`] times
/// on the transient prover errors listed in [`is_transient_prover_error`].
/// Output from retried attempts is hidden from the caller; the final error
/// is only surfaced if every attempt fails.
async fn run_prove_with_retry(config: &Config, task: &ProveTask) -> anyhow::Result<()> {
    let mut last_err = anyhow::anyhow!("prove never attempted");
    for attempt in 1..=MAX_PROVE_RETRIES + 1 {
        if task.cancel.is_cancelled() {
            anyhow::bail!(CANCELLED);
        }
        // Retries escalate to --minimal-memory: it lowers peak memory and
        // proves the same statement, so it cannot weaken a result. The first
        // attempt stays fast unless the operator forces it. Large batches go
        // straight to --minimal-memory: without it a 1024-vote transition with
        // its refreshes needs ~54 GB of host RAM and gets OOM-killed on a
        // 64 GB machine, with it ~41 GB.
        let minimal_memory = config.zisk_minimal_memory
            || attempt > 1
            || task.proof_count >= config.zisk_minimal_memory_from;
        match run_prove(config, task, minimal_memory).await {
            Ok(()) => return Ok(()),
            // A killed group can exit with `signal: 9`: never retry a cancel.
            Err(e) if task.cancel.is_cancelled() => return Err(e),
            Err(e) if attempt <= MAX_PROVE_RETRIES && is_transient_prover_error(&e.to_string()) => {
                warn!(
                    "Job {} hit a transient prover error (attempt {}/{}); retrying in {}s with --minimal-memory",
                    task.job_id, attempt, MAX_PROVE_RETRIES, PROVE_RETRY_DELAY_SECS
                );
                last_err = e;
                tokio::select! {
                    _ = task.cancel.cancelled() => anyhow::bail!(CANCELLED),
                    _ = tokio::time::sleep(Duration::from_secs(PROVE_RETRY_DELAY_SECS)) => {}
                }
            }
            Err(e) => return Err(e),
        }
    }
    Err(last_err)
}

async fn run_prove(config: &Config, task: &ProveTask, minimal_memory: bool) -> anyhow::Result<()> {
    // Run the ZisK prove pipeline. With `plonk` set the output at
    // `proof.bin` is a bincode-encoded ZisK `Proof` whose body is the
    // fflonk PLONK SNARK; without it the body is the vadcop-final STARK,
    // which the aggregator guest can verify recursively.
    let proof_output_path = task.output_dir.join("proof.bin");
    let mut zisk_args: Vec<String> = vec![
        "prove".to_string(),
        "--elf".to_string(),
        task.elf_path.display().to_string(),
        "--inputs".to_string(),
        task.input_path.display().to_string(),
        "--proving-key".to_string(),
        config.proving_key_path.display().to_string(),
        "--output".to_string(),
        proof_output_path.display().to_string(),
        // The Rust emulator is the default (--asm would select the assembly
        // one).
        "--gpu".to_string(),
        "--verify-proof".to_string(),
    ];
    if task.plonk {
        zisk_args.push("--proving-key-plonk".to_string());
        zisk_args.push(config.proving_key_plonk_path.display().to_string());
        zisk_args.push("--plonk".to_string());
    }
    if minimal_memory {
        zisk_args.push("--minimal-memory".to_string());
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
        output_or_cancel(cmd, "mpirun", &task.cancel, KILL_GRACE).await?
    } else {
        let mut cmd = Command::new(&config.cargo_zisk_bin);
        cmd.args(&zisk_args);
        output_or_cancel(cmd, "cargo-zisk", &task.cancel, KILL_GRACE).await?
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        anyhow::bail!(
            "cargo-zisk prove failed (exit {}): {}\n{}",
            output.status,
            stderr,
            stdout
        );
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
    if !task.plonk {
        // STARK job: decode the vadcop blob to surface program_vk/zisk_vk
        // (stark.json) and the 256-byte publics (publics.bin).
        match crate::prover::recursion::write_stark_artifacts(&task.output_dir).await {
            Ok(()) => {}
            Err(e) => warn!("write stark artifacts: {}", e),
        }
        return Ok(());
    }
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
            // publics.bin keeps the guest's u32 view (what the digest parsers
            // read), not the 8-byte-word string the contract hashes.
            let publics_path = task.output_dir.join("publics.bin");
            if let Err(e) = tokio::fs::write(&publics_path, &snark.program_publics).await {
                warn!("write publics.bin: {}", e);
            }
        }
        Err(e) => warn!("parse proof.bin into SNARK payload: {}", e),
    }

    Ok(())
}

/// `cmd.output()` that runs `cmd` in its own process group, so a cancel can
/// kill the whole group (mpirun and its ranks), not only the direct child:
/// SIGTERM, then SIGKILL after `grace`. Fails with [`CANCELLED`] once the
/// group is dead, so the next job never shares the GPU with it.
async fn output_or_cancel(
    mut cmd: Command,
    what: &str,
    cancel: &CancellationToken,
    grace: Duration,
) -> anyhow::Result<Output> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .process_group(0);
    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to spawn {}: {}", what, e))?;
    // The group id is the child's pid. Read it now: it is gone once the
    // child is reaped, while a grandchild may still hold the group. Never
    // pid 1: kill(-1) would signal every process we may signal.
    let pgid = child
        .id()
        .and_then(|p| i32::try_from(p).ok())
        .filter(|p| *p > 1)
        .and_then(rustix::process::Pid::from_raw);
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let run = async { tokio::join!(child.wait(), read_pipe(stdout), read_pipe(stderr)) };
    let (status, stdout, stderr) = tokio::select! {
        r = run => r,
        _ = cancel.cancelled() => {
            kill_group(&mut child, pgid, grace).await;
            anyhow::bail!(CANCELLED);
        }
    };
    Ok(Output {
        status: status.map_err(|e| anyhow::anyhow!("failed to wait for {}: {}", what, e))?,
        stdout,
        stderr,
    })
}

async fn read_pipe(pipe: Option<impl tokio::io::AsyncRead + Unpin>) -> Vec<u8> {
    let mut buf = Vec::new();
    if let Some(mut p) = pipe {
        let _ = p.read_to_end(&mut buf).await;
    }
    buf
}

/// SIGTERM the child's group, SIGKILL it after `grace`, then reap the child.
async fn kill_group(child: &mut Child, pgid: Option<rustix::process::Pid>, grace: Duration) {
    use rustix::process::{kill_process_group, Signal};
    let Some(pgid) = pgid else {
        let _ = child.start_kill();
        let _ = child.wait().await;
        return;
    };
    let _ = kill_process_group(pgid, Signal::TERM);
    let _ = tokio::time::timeout(grace, child.wait()).await;
    // Ranks can outlive their launcher: SIGKILL whatever is left.
    let _ = kill_process_group(pgid, Signal::KILL);
    let _ = child.wait().await;
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn test_config(name: &str) -> Config {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../target/service-tests")
            .join(format!("{}-{}", name, Uuid::new_v4()));
        Config {
            listen_addr: String::new(),
            proving_key_path: PathBuf::new(),
            proving_key_plonk_path: PathBuf::new(),
            circuit_elf_path: PathBuf::new(),
            aggregator_elf_path: PathBuf::new(),
            results_elf_path: PathBuf::new(),
            cargo_zisk_bin: "false".to_string(),
            proof_output_dir: dir,
            max_queue_size: 8,
            zisk_mpi_procs: 1,
            zisk_mpi_threads: 0,
            zisk_mpi_bind_to: "none".to_string(),
            zisk_minimal_memory: false,
            zisk_minimal_memory_from: 512,
            keep_inputs: false,
        }
    }

    // Handle whose worker loop has already returned (its channel closed);
    // submits must be refused.
    pub(crate) async fn stopped_handle(config: Config) -> ProverHandle {
        let jobs: Arc<DashMap<Uuid, Job>> = Arc::new(DashMap::new());
        let (tx, rx) = tokio::sync::mpsc::channel::<ProveTask>(1);
        let worker = tokio::spawn(worker_loop(config, rx, jobs.clone(), |_, _| async {
            Ok(())
        }));
        drop(tx);
        let (sender, _) = tokio::sync::mpsc::channel::<ProveTask>(1);
        let h = ProverHandle {
            jobs,
            sender,
            worker,
        };
        for _ in 0..100 {
            if !h.worker_running() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        h
    }

    async fn wait_finished(h: &ProverHandle, id: Uuid) -> Job {
        for _ in 0..500 {
            let job = h.jobs.get(&id).map(|j| j.clone()).expect("job in map");
            if matches!(job.status, JobStatus::Done | JobStatus::Failed) {
                return job;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("job {} did not finish", id);
    }

    #[tokio::test]
    async fn panicking_job_fails_alone() {
        let config = test_config("panic");
        let dir = config.proof_output_dir.clone();
        let h = ProverHandle::spawn(config, |_, task| async move {
            if task.proof_count == 1 {
                panic!("boom from job");
            }
            Ok(())
        });
        let elf = PathBuf::from("unused.elf");
        let a = h
            .submit(vec![1], &dir, JobKind::Batch, elf.clone(), vec![], 1)
            .await
            .unwrap();
        let b = h
            .submit(vec![2], &dir, JobKind::Batch, elf, vec![], 2)
            .await
            .unwrap();

        let ja = wait_finished(&h, a).await;
        assert_eq!(ja.status, JobStatus::Failed);
        let err = ja.error.unwrap();
        assert!(
            err.contains("panicked") && err.contains("boom from job"),
            "{err}"
        );
        assert_eq!(wait_finished(&h, b).await.status, JobStatus::Done);
        assert!(h.worker_running());
        assert_eq!(h.queue_len(), 0);
        // The witness is deleted after proving, panic or not.
        assert!(!dir.join(a.to_string()).join("input.bin").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn rejected_submit_leaves_no_job() {
        let config = test_config("rejected");
        let dir = config.proof_output_dir.clone();
        let h = stopped_handle(config).await;
        assert!(!h.worker_running());
        for _ in 0..3 {
            let err = h
                .submit(vec![1], &dir, JobKind::Batch, PathBuf::new(), vec![], 1)
                .await
                .unwrap_err();
            assert!(err.to_string().contains("closed"), "{err}");
        }
        assert_eq!(h.queue_len(), 0);
        assert!(h.jobs.is_empty());
        // No per-job dir (and no witness) survives the rejection.
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // Handle whose prove holds every job until a permit is added; records the
    // proof_count of each job it starts.
    pub(crate) fn gated_handle(
        config: Config,
    ) -> (
        ProverHandle,
        Arc<tokio::sync::Semaphore>,
        Arc<std::sync::Mutex<Vec<usize>>>,
    ) {
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let ran = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (g, r) = (gate.clone(), ran.clone());
        let h = ProverHandle::spawn(config, move |_, task| {
            let (g, r) = (g.clone(), r.clone());
            async move {
                r.lock().unwrap().push(task.proof_count);
                g.acquire().await.unwrap().forget();
                Ok(())
            }
        });
        (h, gate, ran)
    }

    pub(crate) async fn wait_status(h: &ProverHandle, id: Uuid, want: JobStatus) {
        for _ in 0..500 {
            if h.jobs.get(&id).is_some_and(|j| j.status == want) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("job {} never reached {:?}", id, want);
    }

    // Alive and not a zombie.
    fn alive(pid: &str) -> bool {
        match std::fs::read_to_string(format!("/proc/{}/stat", pid.trim())) {
            Ok(stat) => stat
                .rsplit_once(") ")
                .is_some_and(|(_, rest)| !rest.starts_with('Z')),
            Err(_) => false,
        }
    }

    async fn wait_dead(pid: &str) {
        for _ in 0..300 {
            if !alive(pid) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("process {} survived the cancel", pid.trim());
    }

    async fn read_when_written(path: &Path) -> String {
        for _ in 0..500 {
            if let Ok(s) = std::fs::read_to_string(path) {
                if s.ends_with('\n') {
                    return s;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("{} never written", path.display());
    }

    #[tokio::test]
    async fn cancelled_queued_job_never_proves() {
        let config = test_config("cancel-queued");
        let dir = config.proof_output_dir.clone();
        let (h, gate, ran) = gated_handle(config);
        let elf = PathBuf::from("unused.elf");
        let a = h
            .submit(vec![1], &dir, JobKind::Batch, elf.clone(), vec![], 1)
            .await
            .unwrap();
        wait_status(&h, a, JobStatus::Running).await;
        let b = h
            .submit(vec![2], &dir, JobKind::Batch, elf.clone(), vec![], 2)
            .await
            .unwrap();
        assert!(dir.join(b.to_string()).join("input.bin").exists());

        let job = h.cancel(b, &dir).await.unwrap();
        assert_eq!(job.status, JobStatus::Failed);
        assert_eq!(job.error.as_deref(), Some(CANCELLED));
        assert_eq!(h.queue_len(), 0);
        // The witness goes at once, not when the worker reaches the job.
        assert!(!dir.join(b.to_string()).exists());
        // Repeats and unknown ids change nothing.
        assert_eq!(h.cancel(b, &dir).await.unwrap().status, JobStatus::Failed);
        assert!(h.cancel(Uuid::new_v4(), &dir).await.is_none());

        // The worker skips b and proves c next.
        let c = h
            .submit(vec![3], &dir, JobKind::Batch, elf, vec![], 3)
            .await
            .unwrap();
        gate.add_permits(2);
        assert_eq!(wait_finished(&h, a).await.status, JobStatus::Done);
        assert_eq!(wait_finished(&h, c).await.status, JobStatus::Done);
        assert_eq!(*ran.lock().unwrap(), vec![1, 3]);
        let jb = h.jobs.get(&b).unwrap().clone();
        assert_eq!(jb.error.as_deref(), Some(CANCELLED));
        assert!(jb.started_at.is_none());
        // A finished job is left alone.
        let ja = h.cancel(a, &dir).await.unwrap();
        assert_eq!((ja.status, ja.error), (JobStatus::Done, None));
        assert!(h.worker_running());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn cancelled_running_job_kills_its_process_group() {
        let config = test_config("cancel-running");
        let dir = config.proof_output_dir.clone();
        // A real subprocess in its own group: the leader and a background
        // child that outlives it unless the whole group is killed.
        let h = ProverHandle::spawn(config, |_, task| async move {
            let script = format!(
                "echo $$ > {d}/leader.pid; sleep 60 & echo $! > {d}/child.pid; wait",
                d = task.output_dir.display()
            );
            let mut cmd = Command::new("sh");
            cmd.arg("-c").arg(script);
            output_or_cancel(cmd, "sh", &task.cancel, KILL_GRACE)
                .await
                .map(|_| ())
        });
        let id = h
            .submit(vec![1], &dir, JobKind::Batch, PathBuf::new(), vec![], 1)
            .await
            .unwrap();
        let job_dir = dir.join(id.to_string());
        let leader = read_when_written(&job_dir.join("leader.pid")).await;
        let child = read_when_written(&job_dir.join("child.pid")).await;
        assert!(alive(&leader) && alive(&child));

        let t0 = Instant::now();
        assert_eq!(h.cancel(id, &dir).await.unwrap().status, JobStatus::Running);
        let job = wait_finished(&h, id).await;
        assert_eq!(job.status, JobStatus::Failed);
        assert_eq!(job.error.as_deref(), Some(CANCELLED));
        // SIGTERM sufficed: no wait for the SIGKILL grace.
        assert!(t0.elapsed() < KILL_GRACE, "{:?}", t0.elapsed());
        wait_dead(&leader).await;
        wait_dead(&child).await;
        assert!(!job_dir.exists());
        assert!(h.worker_running());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // A group that ignores SIGTERM is SIGKILLed after the grace.
    #[tokio::test]
    async fn term_ignoring_group_is_killed() {
        let dir = test_config("cancel-kill").proof_output_dir;
        std::fs::create_dir_all(&dir).unwrap();
        let pid = dir.join("child.pid");
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(format!(
            "trap '' TERM; sleep 60 & echo $! > {}; wait",
            pid.display()
        ));
        let cancel = CancellationToken::new();
        let run = tokio::spawn({
            let cancel = cancel.clone();
            async move { output_or_cancel(cmd, "sh", &cancel, Duration::from_millis(300)).await }
        });
        let child = read_when_written(&pid).await;
        let t0 = Instant::now();
        cancel.cancel();
        let err = run.await.unwrap().unwrap_err();
        assert_eq!(err.to_string(), CANCELLED);
        assert!(t0.elapsed() < Duration::from_secs(5), "{:?}", t0.elapsed());
        wait_dead(&child).await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    // A cancel during the retry delay ends the job: no further attempt.
    #[tokio::test]
    async fn cancel_stops_transient_retries() {
        use std::os::unix::fs::PermissionsExt;
        let mut config = test_config("cancel-retry");
        let dir = config.proof_output_dir.clone();
        std::fs::create_dir_all(&dir).unwrap();
        let attempts = dir.join("attempts");
        let bin = dir.join("fake-zisk");
        std::fs::write(
            &bin,
            format!(
                "#!/bin/sh\necho x >> {}\necho 'cudaGetLastError: context is destroyed' >&2\nexit 1\n",
                attempts.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        config.cargo_zisk_bin = bin.display().to_string();
        let task = ProveTask {
            job_id: Uuid::new_v4(),
            input_path: dir.join("input.bin"),
            output_dir: dir.clone(),
            elf_path: PathBuf::new(),
            plonk: false,
            proof_count: 0,
            cancel: CancellationToken::new(),
        };
        let cancel = task.cancel.clone();
        let run = tokio::spawn(async move { run_prove_with_retry(&config, &task).await });
        read_when_written(&attempts).await;
        let t0 = Instant::now();
        cancel.cancel();
        let err = run.await.unwrap().unwrap_err();
        assert_eq!(err.to_string(), CANCELLED);
        // At once, not after the retry delay.
        assert!(t0.elapsed() < Duration::from_secs(2), "{:?}", t0.elapsed());
        assert_eq!(std::fs::read_to_string(&attempts).unwrap(), "x\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn snark_self_check_is_transient() {
        assert!(is_transient_prover_error(
            "cargo-zisk prove failed (exit exit status: 1): Error: snark proof verification \
             failed: Proof error: SNARK proof verification failed: "
        ));
        assert!(!is_transient_prover_error("Error: guest panicked: SIGABRT"));
    }

    #[test]
    fn host_crash_signals_are_transient() {
        let msg = |sig: &str| format!("cargo-zisk prove failed (exit {sig}): \n");
        assert!(is_transient_prover_error(&msg(
            "signal: 11 (SIGSEGV) (core dumped)"
        )));
        assert!(is_transient_prover_error(&msg(
            "signal: 7 (SIGBUS) (core dumped)"
        )));
        assert!(is_transient_prover_error(&msg("signal: 9 (SIGKILL)")));
        assert!(!is_transient_prover_error(&msg(
            "signal: 6 (SIGABRT) (core dumped)"
        )));
        // Prefix of a longer number must not match.
        assert!(!is_transient_prover_error(&msg("signal: 110")));
        assert!(!is_transient_prover_error(&msg("signal: 70 (SIG?)")));
        assert!(!is_transient_prover_error(
            "cargo-zisk prove failed (exit exit status: 1): Error: assertion failed: ok == 1"
        ));
    }
}
