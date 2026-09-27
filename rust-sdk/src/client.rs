//! HTTP client for the davinci-zkvm prover service.
//!
//! Status mapping: 425 -> [`Error::NotReady`], 422 -> [`Error::JobFailed`],
//! 404 -> [`Error::NotFound`], 503 -> [`Error::QueueFull`], anything else
//! unexpected -> [`Error::Status`]. A `done` job is not a valid batch: check
//! the publics (`BatchPublics::passed`) before settling.

use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::types::{Health, Job, JobId, JobStatus, ProveRequest, ResultsRequest};
use crate::Error;

/// Largest response body read (the biggest artifact served here is ~3 KB).
const MAX_BODY: usize = 16 << 20;
/// Longest error text kept from a response.
const MAX_ERR: usize = 4096;
/// Consecutive transient poll failures `wait` tolerates.
const MAX_POLL_ERRORS: u32 = 5;

/// The four `ZiskVerifier.verifySnarkProof` arguments.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PlonkSnark {
    pub program_vk: [u8; 32],
    pub root_c_vadcop_final: [u8; 32],
    /// 512 bytes: 64 publics as u64 LE words.
    pub public_values: Vec<u8>,
    /// 768 bytes: ABI-encoded `uint256[24]`.
    pub proof_bytes: Vec<u8>,
}

#[derive(Deserialize)]
struct SnarkJson {
    program_vk: String,
    root_c_vadcop_final: String,
    public_values: String,
    proof_bytes: String,
}

#[derive(Serialize, Deserialize)]
struct Submitted {
    job_id: JobId,
}

#[derive(Clone, Debug)]
pub struct ProverClient {
    base: String,
    http: reqwest::Client,
}

fn hex_bytes(field: &str, s: &str) -> Result<Vec<u8>, Error> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s))
        .map_err(|_| Error::Input(format!("{field}: bad hex")))
}

fn hex_fixed<const N: usize>(field: &str, s: &str) -> Result<[u8; N], Error> {
    hex_bytes(field, s)?
        .try_into()
        .map_err(|_| Error::Input(format!("{field}: want {N} bytes")))
}

fn error_text(body: &[u8]) -> String {
    #[derive(Deserialize)]
    struct E {
        error: String,
    }
    let text = match serde_json::from_slice::<E>(body) {
        Ok(e) => e.error,
        Err(_) => String::from_utf8_lossy(body).into_owned(),
    };
    text.chars().take(MAX_ERR).collect()
}

fn map_status(status: u16, body: &[u8]) -> Error {
    match status {
        404 => Error::NotFound(error_text(body)),
        422 => Error::JobFailed(error_text(body)),
        425 => Error::NotReady,
        503 => Error::QueueFull,
        _ => Error::Status {
            status,
            body: error_text(body),
        },
    }
}

async fn read_body(mut resp: reqwest::Response) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| Error::Http(e.to_string()))? {
        if out.len() + chunk.len() > MAX_BODY {
            return Err(Error::Http("response body too large".into()));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

// Worth retrying while polling: network trouble and server-side hiccups.
fn transient(e: &Error) -> bool {
    matches!(e, Error::Http(_) | Error::QueueFull)
        || matches!(e, Error::Status { status, .. } if *status >= 500)
}

impl ProverClient {
    /// Client with a 10 s connect and 300 s request timeout (`/prove`
    /// verifies every ballot proof before answering).
    pub fn new(base_url: &str) -> Self {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(300))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self::with_http(base_url, http)
    }

    pub fn with_http(base_url: &str, http: reqwest::Client) -> Self {
        ProverClient {
            base: base_url.trim_end_matches('/').to_string(),
            http,
        }
    }

    async fn send(&self, req: reqwest::RequestBuilder, want: u16) -> Result<Vec<u8>, Error> {
        let resp = req.send().await.map_err(|e| Error::Http(e.to_string()))?;
        let status = resp.status().as_u16();
        let body = read_body(resp).await?;
        if status != want {
            return Err(map_status(status, &body));
        }
        Ok(body)
    }

    async fn get(&self, path: &str) -> Result<Vec<u8>, Error> {
        self.send(self.http.get(format!("{}{path}", self.base)), 200)
            .await
    }

    async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T, Error> {
        Ok(serde_json::from_slice(&self.get(path).await?)?)
    }

    async fn submit<T: Serialize>(&self, path: &str, body: &T) -> Result<JobId, Error> {
        let req = self.http.post(format!("{}{path}", self.base)).json(body);
        let s: Submitted = serde_json::from_slice(&self.send(req, 202).await?)?;
        Ok(s.job_id)
    }

    /// `POST /prove`.
    pub async fn prove(&self, r: &ProveRequest) -> Result<JobId, Error> {
        self.submit("/prove", r).await
    }

    /// `POST /results` (circuit-results).
    pub async fn results(&self, r: &ResultsRequest) -> Result<JobId, Error> {
        self.submit("/results", r).await
    }

    pub async fn job(&self, id: &JobId) -> Result<Job, Error> {
        self.get_json(&format!("/jobs/{id}")).await
    }

    /// Polls until `done` (returned) or `failed` ([`Error::JobFailed`]).
    /// Up to 5 consecutive transient errors are tolerated; a 404 is not.
    pub async fn wait(&self, id: &JobId, poll: Duration, timeout: Duration) -> Result<Job, Error> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut errors = 0;
        loop {
            match self.job(id).await {
                Ok(job) => {
                    errors = 0;
                    match job.status {
                        JobStatus::Done => return Ok(job),
                        JobStatus::Failed => {
                            return Err(Error::JobFailed(job.error.unwrap_or_default()))
                        }
                        JobStatus::Queued | JobStatus::Running => {}
                    }
                }
                Err(e) if transient(&e) && errors + 1 < MAX_POLL_ERRORS => errors += 1,
                Err(e) => return Err(e),
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(Error::Timeout);
            }
            tokio::time::sleep(poll.min(deadline - now)).await;
        }
    }

    /// `GET /jobs/{id}/snark`; 425 while running, 422 if the job failed.
    pub async fn snark(&self, id: &JobId) -> Result<PlonkSnark, Error> {
        let j: SnarkJson = self.get_json(&format!("/jobs/{id}/snark")).await?;
        let public_values = hex_bytes("public_values", &j.public_values)?;
        let proof_bytes = hex_bytes("proof_bytes", &j.proof_bytes)?;
        if public_values.len() != 512 || proof_bytes.len() != 768 {
            return Err(Error::Input(
                "snark: public_values must be 512 bytes, proof_bytes 768".into(),
            ));
        }
        Ok(PlonkSnark {
            program_vk: hex_fixed("program_vk", &j.program_vk)?,
            root_c_vadcop_final: hex_fixed("root_c_vadcop_final", &j.root_c_vadcop_final)?,
            public_values,
            proof_bytes,
        })
    }

    /// `GET /jobs/{id}/publics`: the 256-byte u32 register view.
    pub async fn publics(&self, id: &JobId) -> Result<Vec<u8>, Error> {
        self.get(&format!("/jobs/{id}/publics")).await
    }

    pub async fn health(&self) -> Result<Health, Error> {
        self.get_json("/health").await
    }
}
