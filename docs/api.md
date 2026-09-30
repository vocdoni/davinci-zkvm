# HTTP API

The service listens on `LISTEN_ADDR` (port 8080 in the Docker setup). All
request and response bodies are JSON unless noted. The API has no
authentication; expose it only to the sequencer that uses it.

Proving is asynchronous. A submit call validates the request, builds the
guest input and returns `202 Accepted` with a job ID. The job then runs on
the GPU, one job at a time in submission order. Poll the job and download its
artifacts when it is `done`.

```bash
curl -s -X POST localhost:8080/prove -H 'Content-Type: application/json' -d @batch.json
# {"job_id":"3f0c…","status":"queued"}
curl -s localhost:8080/jobs/3f0c…          # {"status":"running",…}
curl -s localhost:8080/jobs/3f0c…/snark    # the on-chain payload
```

Jobs are tracked in memory: after a restart the service no longer knows
earlier job IDs.

## Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/prove` | Prove one vote batch. PLONK by default, STARK with `"output": "stark"`. |
| `POST` | `/results` | Prove the decrypted tally of an election (results guest), PLONK. |
| `POST` | `/fold` | Chained mode: fold completed STARK batch jobs into the election chain. |
| `POST` | `/finalize` | Chained mode: verify the results and wrap the chain in the final PLONK. |
| `POST` | `/jobs/import` | Chained mode: register a batch (default) or fold (`?kind=fold`) STARK `proof.bin` proved on another prover. |
| `GET` | `/jobs/{id}` | Job status and timing. |
| `GET` | `/jobs/{id}/snark` | The four `verifySnarkProof` arguments of a PLONK job. |
| `GET` | `/jobs/{id}/snark/raw` | The raw `proof.bin` (bincode), for `cargo-zisk verify` or `/jobs/import`. |
| `GET` | `/jobs/{id}/publics` | The guest's public outputs as 64 little-endian `u32` (256 bytes). |
| `GET` | `/jobs/{id}/stark` | `program_vk` and `zisk_vk` of a STARK job. |
| `GET` | `/jobs/{id}/proof/stark` | The vadcop-final STARK blob the aggregator guest verifies. |
| `GET` | `/jobs/{id}/inputs` | The job's `input.bin`. Only with `DAVINCI_KEEP_INPUTS=1`, otherwise 404. |
| `GET` | `/health` | Liveness and queue length. |

### Status codes

| Code | Meaning |
|---|---|
| `202` | Job accepted: `{"job_id": "<uuid>", "status": "queued"}`. |
| `400` | Invalid JSON or request, a referenced job that is missing, not done or of the wrong kind, or an unknown `kind` on `/jobs/import`. Body: `{"error": "..."}`. |
| `404` | Unknown job or missing artifact. |
| `415` | JSON body sent without `Content-Type: application/json`. |
| `422` | JSON that does not match the request schema; on artifact routes, a failed job (the body carries the prover error); on `/jobs/import`, a body that is not a STARK proof. |
| `425` | The job is still queued or running. |
| `503` | The queue is full (`MAX_QUEUE_SIZE`), or, on `/health`, the prover worker has stopped. |

## Encodings

Byte order depends on where a value comes from:

- **Arbo little-endian hex** (32 bytes, `0x` optional): everything that is an
  arbo state-tree value. That is the `state` block's `process_id` and roots,
  every field of an SMT entry, the chained-mode `config` and `results`
  payloads, and the whole `/results` body.
- **Big-endian hex** (32 bytes, `0x` prefix): curve coordinates, the
  re-encryption key and seed, the `ballot_proofs` coordinates, census proofs,
  voter and CSP signature fields, and the `kzg` block's `process_id` and
  `root_hash_before`. KZG commitments are 48 bytes (96 hex characters).
- **Decimal strings**: snarkjs proofs and verification keys, ballot proof
  public inputs, and the signer address in `sigs`.

The Go and Rust SDKs build these bodies from typed values; use them unless
you have a reason not to.

## `POST /prove`

| Field | Required | Content |
|---|---|---|
| `vk` | yes | snarkjs verification key of the ballot circuit. |
| `proofs` | yes | snarkjs Groth16 ballot proofs, 1 to 1024. |
| `public_inputs` | yes | One `[address, vote_id, inputs_hash]` per proof, decimal. |
| `sigs` | yes | One vote-ID signature per proof: `signature_r`, `signature_s`, `signature_v` (0 or 1), `vote_id`, `address`, `public_key_x`, `public_key_y`. |
| `state` | yes | State transition: counts (`voters_count`, `overwritten_count`, `occupied_before`), `process_id`, `old_state_root`, `new_state_root`, the SMT chains `vote_id_smt`, `ballot_smt`, `refresh_smt`, `results_smt`, the five `process_smt` read proofs, and `ballot_proofs` (old accumulator, new, overwritten and refreshed ballots). |
| `census_proofs` | one of | lean-IMT membership proof per voter (`root`, `leaf`, `index`, `siblings`). |
| `csp_data` | one of | CSP attestation per voter (`r`, `s`, `recid`, `voter_address`, `weight`, `index`). |
| `reencryption` | yes | `encryption_key_x`, `encryption_key_y`, the batch `seed` and one `{original, reencrypted}` entry of 16 ciphertexts per voter. |
| `kzg` | per-batch mode | `process_id`, `root_hash_before` and the blob `commitments`. Omit in chained mode. |
| `output` | no | `"plonk"` (default) or `"stark"`. |

"Required" means required for a valid batch. The service accepts a request
without these blocks, and the guest then proves `ok = 0`. The full input
format and every check are in [`circuit/CIRCUIT.md`](../circuit/CIRCUIT.md).
The `seed` is secret: draw a fresh one per batch and never reuse or log it.

A job that finishes is not necessarily an accepted batch. Read the public
outputs (register 0 `ok`, register 1 `fail_mask`) from `publics` or from the
snark's `public_values` before settling; the SDKs parse them for you.

## `GET /jobs/{id}`

```json
{
  "job_id": "3f0c…",
  "status": "done",
  "kind": "batch",
  "created_at": "2026-01-01T00:00:00Z",
  "started_at": "2026-01-01T00:00:01Z",
  "finished_at": "2026-01-01T00:01:25Z",
  "elapsed_ms": 84300
}
```

`status` is `queued`, `running`, `done` or `failed` (with `error`). `kind` is
`batch`, `batchstark`, `fold`, `finalize` or `results`. Fold and finalize jobs
list the jobs they consumed in `parent_job_ids`.

## `GET /jobs/{id}/snark`

```json
{
  "program_vk": "0x… (32 bytes)",
  "root_c_vadcop_final": "0x… (32 bytes)",
  "public_values": "0x… (512 bytes)",
  "proof_bytes": "0x… (768 bytes)"
}
```

The fields are, in order of the Solidity signature, the arguments of
`ZiskVerifier.verifySnarkProof(programVK, rootCVadcopFinal, publicValues, proofBytes)`.
`public_values` is the 64 guest outputs as 8-byte little-endian words.
Compare `program_vk` and `root_c_vadcop_final` against pinned values
(`rust-sdk/src/release.rs`) instead of trusting them.

## `POST /results`

Proves the tally of one election with the results guest. All 32-byte values
are arbo little-endian hex:

```text
{
  "state_root":   final state root (raw arbo root bytes),
  "enc_key_x":    election key, twisted Edwards x,
  "enc_key_y":    election key, twisted Edwards y,
  "key_siblings": inclusion proof of state key 0x03, root to leaf, up to 64,
  "accumulator":  64 coordinates of the results accumulator (state key 0x04),
  "acc_siblings": inclusion proof of state key 0x04,
  "results":      16 plaintexts (u64),
  "cp_proofs":    16 × {"a1x", "a1y", "a2x", "a2y", "z"}
}
```

The frame, the checks, the 43 output registers and the fail bits are in
[`circuit-results/RESULTS.md`](../circuit-results/RESULTS.md).

## Chained mode

`config` is the immutable election configuration, arbo little-endian hex:
`process_id`, `ballot_mode`, `enc_x`, `enc_y`, `census_origin` (number),
`census_root`, `ballot_vk_hash`.

`POST /fold`

| Field | Content |
|---|---|
| `config` | Election configuration. |
| `batch_jobs` | Completed `batchstark` job IDs, in chain order. |
| `prev_fold_job` | Previous fold job. Omit for the genesis fold. |
| `fold_vk` | Aggregator program vk to bind (`0x` + 64 hex, big-endian). Defaults to the previous fold's vk, or zero for the bootstrap fold. |

`POST /finalize`

| Field | Content |
|---|---|
| `config` | Election configuration. |
| `fold_job` | The last completed fold job. |
| `fold_vk` | Optional, defaults to the fold proof's own vk. |
| `results` | `ballot` (64 accumulator coordinates), `results` (16 plaintexts), `cp_proofs` (16 Chaum-Pedersen proofs) and `siblings` (inclusion proof of the results leaf). |

Fold and finalize read the referenced proofs from the service's own job
directory, so every job they reference must live on the same service.
`POST /jobs/import` takes a raw `proof.bin` body (as served by
`/jobs/{id}/snark/raw` on another prover), checks that it decodes as a STARK
and returns `200` with `{"job_id": "…"}`. The optional query parameter `kind`
sets the job kind: `batch` (the default) registers a completed `batchstark`
job for `batch_jobs`; `fold` registers a completed `fold` job for
`prev_fold_job` or `/finalize`, which moves a fold chain to another prover.
The aggregator verifies every imported proof in-guest, an imported fold
against the `fold_vk` bound in the config commitment, so importing does not
require trusting the uploader.

`GET /jobs/{id}/stark` returns `{"program_vk": "0x…", "zisk_vk": "0x…"}` of a
STARK job. A fold or finalize job's `publics` are the 53-word aggregator
digest (`chain.ParseDigest` in the Go SDK). See
[architecture.md](architecture.md#chained-mode) for the verification rules.

## `GET /health`

```json
{"status": "ok", "worker": "running", "version": "0.1.0", "queue_len": 0}
```

Returns `503` with `"status": "degraded"` once the prover worker has stopped;
restart the service.
