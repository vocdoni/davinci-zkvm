# davinci-zkvm

A production-ready ZisK zkVM service that verifies batches of 128 Groth16 BN254 proofs and generates a single ZisK STARK proof, accessible via a simple HTTP API.

## Overview

`davinci-zkvm` wraps the [ZisK](https://github.com/0xPolygonHermez/zisk) zkVM prover in an HTTP service. Callers submit batches of 128 [snarkjs](https://github.com/iden3/snarkjs) Groth16 BN254 proofs via `POST /prove`. The service queues the request, runs the ZisK STARK prover, and makes the final proof available for download.

**Key properties:**
- Single sequential job queue (ZisK prover uses all available GPU/CPU resources)
- Pre-built circuit ELF checked into the repository — no ZisK toolchain required at runtime
- Supports both CPU proving and CUDA GPU proving (NVIDIA RTX/Blackwell, sm_120)
- Fully Dockerized with two images: CPU (`Dockerfile`) and GPU (`Dockerfile.cuda`)

## Quick Start

### Prerequisites

- Docker + Docker Compose
- ZisK proving key (≈36 GB) at `~/.zisk/provingKey` (see [Setup](#proving-key-setup))
- *(GPU only)* NVIDIA driver 570+, CUDA 12.8, nvidia-container-toolkit

### CPU (default)

```bash
git clone https://github.com/0xPolygonHermez/davinci-zkvm.git
cd davinci-zkvm
docker compose up -d
```

### GPU (CUDA)

```bash
git clone https://github.com/0xPolygonHermez/davinci-zkvm.git
cd davinci-zkvm
docker compose -f docker-compose.cuda.yml up -d
```

The service is available at `http://localhost:8080`.

## API Reference

### `POST /prove`

Submit a batch of 128 Groth16 BN254 proofs for ZisK proving.

**Request body:**
```json
{
  "vk": { ...snarkjs verification key... },
  "proofs": [ ...array of 128 snarkjs Groth16 proofs... ],
  "public_inputs": [ ["input1", "input2"], ... ]
}
```

The `vk` and `proofs` fields use the standard [snarkjs](https://github.com/iden3/snarkjs) JSON format (`verification_key.json` and `proof.json` respectively).

**Response `202 Accepted`:**
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued"
}
```

**Response `400 Bad Request`:** invalid request (missing/malformed fields).

**Response `503 Service Unavailable`:** queue is full.

---

### `GET /jobs/{job_id}`

Get the status of a proof job.

**Response `200 OK`:**
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued|running|done|failed",
  "created_at": "2026-02-26T08:52:11Z",
  "started_at": "2026-02-26T08:52:15Z",
  "finished_at": "2026-02-26T08:52:41Z",
  "elapsed_ms": 26500,
  "error": null
}
```

**Response `404 Not Found`:** job not found.

---

### `GET /jobs/{job_id}/proof`

Download the final ZisK proof binary once the job is complete.

**Response `200 OK`:** binary proof file (`Content-Type: application/octet-stream`)

**Response `425 Too Early`:** proof is not ready yet (job is queued or running).

**Response `422 Unprocessable Entity`:** job failed, includes error details.

**Response `404 Not Found`:** job not found.

---

### `GET /health`

Service health check.

**Response `200 OK`:**
```json
{
  "status": "ok",
  "version": "0.1.0",
  "queue_len": 0
}
```

## Proving Key Setup

The ZisK proving key is required and must be available at `/proving-key` inside the container (bind-mounted from the host).

```bash
# Set PROVING_KEY_PATH to override (default: ~/.zisk/provingKey)
export PROVING_KEY_PATH=/path/to/your/provingKey

# Or use the Makefile to download and install it:
make setup         # Downloads the proving key tarball (~36 GB)
make setup-trees   # Builds constant tree files (needed once, ~5 min with GPU)
```

## Configuration

The service is configured via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `LISTEN_ADDR` | `0.0.0.0:8080` | HTTP listen address |
| `PROVING_KEY_PATH` | `/proving-key` | Path to ZisK proving key directory |
| `CIRCUIT_ELF_PATH` | `/app/circuit.elf` | Path to pre-built circuit ELF |
| `CARGO_ZISK_BIN` | `cargo-zisk` | Path to cargo-zisk binary |
| `PROOF_OUTPUT_DIR` | `/tmp/proofs` | Directory for proof output files |
| `MAX_QUEUE_SIZE` | `100` | Maximum number of queued jobs |
| `RUST_LOG` | `davinci_zkvm=info` | Log level filter |

## Development

### Building from source

```bash
# Build the service binary
make build

# Build the ZisK circuit ELF (requires +zisk toolchain)
make build-circuit

# Generate binary input from test proofs
make gen-input

# Run the circuit in the ZisK emulator (fast, no GPU needed)
make run-emu

# Run full proof generation (requires proving key + GPU recommended)
make prove
```

### GPU support (CUDA)

For RTX 5000 series (Blackwell, sm_120), CUDA 12.8 is required:

```bash
# Rebuild cargo-zisk with GPU support
make build-zisk-gpu ZISK_SRC=~/path/to/zisk

# Then run setup for GPU constant trees
make setup-trees
```

### Docker

```bash
make docker-build        # Build CPU image
make docker-build-cuda   # Build CUDA GPU image
```

### Integration tests

Tests use Go and communicate with the service via HTTP. They require the service to be running.

```bash
cd integration-tests

# Run lightweight tests (no proving)
make test-unit

# Full test cycle: build Docker → start → test → stop
make test-full

# Or test against an already-running instance
DAVINCI_API_URL=http://localhost:8080 make test
```

**Environment variables for tests:**

| Variable | Default | Description |
|----------|---------|-------------|
| `DAVINCI_API_URL` | `http://localhost:8080` | Service URL |
| `DAVINCI_SKIP_PROVING` | `""` | Set to `1` to skip the full proving test |
| `DAVINCI_PROOF_TIMEOUT` | `20m` | Timeout for waiting for a proof |
| `TEST_DATA_DIR` | `../data/simple_mul_bn254` | Path to test data directory |

## Architecture

```
davinci-zkvm/
├── circuit/          # ZisK RISC-V guest program (128 Groth16 batch verifier)
│   ├── elf/          # Pre-built circuit ELF (checked in, 266 KB)
│   └── src/          # Guest source code (requires +zisk toolchain to rebuild)
├── input-gen/        # Library: snarkjs JSON → ZisK binary input conversion
├── service/          # HTTP API service (axum + tokio)
│   └── src/
│       ├── api/      # HTTP handlers (POST /prove, GET /jobs/*)
│       ├── prover/   # Background job queue and worker
│       ├── config.rs # Environment variable configuration
│       └── types.rs  # Shared types
├── data/             # Test fixtures (128 Groth16 proofs)
└── integration-tests/ # Go integration tests
```

The service maintains a single sequential job queue. When a proof job reaches the worker, it:
1. Writes the binary input to a per-job directory
2. Invokes `cargo-zisk prove` as a subprocess
3. Updates job status in memory on completion

## Proving Performance

| Mode | Time |
|------|------|
| CPU (AMD Ryzen 9) | ~747 seconds |
| GPU (NVIDIA RTX 5070 Ti, sm_120) | ~26 seconds |

## License

MIT OR Apache-2.0
