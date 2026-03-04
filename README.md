# davinci-zkvm

A [ZisK](https://github.com/0xPolygonHermez/zisk) zkVM service that verifies complete
[DAVINCI](https://github.com/vocdoni/davinci-node) voting protocol state-transitions
inside a single RISC-V circuit, producing a STARK (→ FFLONK) proof suitable for
on-chain verification.

## What it does

Each state-transition batch is verified end-to-end in a single ZisK circuit execution:

| Step | Description |
|------|-------------|
| **Groth16 batch verify** | BN254 pairing-based verification of voter ballot proofs (snarkjs) |
| **ECDSA batch verify** | secp256k1 signature verification (one per voter) |
| **State SMT transitions** | Arbo SHA-256 sparse Merkle tree updates for vote-ID, ballot, results, and process chains |
| **Census membership** | Lean-IMT Poseidon BN254 inclusion proofs (Merkle census) or ECDSA CSP authentication |
| **ElGamal re-encryption** | BabyJubJub twisted-Edwards re-encryption verification |
| **KZG blob evaluation** | EIP-4844 barycentric evaluation of encrypted ballot blobs |
| **Result accumulation** | Homomorphic ballot tally verification with overwrite support |
| **Cross-block binding** | Cryptographic binding between all protocol blocks |

The circuit produces public outputs matching
[davinci-node](https://github.com/vocdoni/davinci-node)'s `StateTransitionCircuit`
interface: root hashes, census root, voter counts, KZG blob commitment, and a
diagnostic fail-mask.

## Architecture

```
davinci-zkvm/
├── circuit/            ZisK RISC-V guest circuit (Rust, requires +zisk toolchain)
│   ├── elf/            Pre-built circuit ELF (checked in)
│   └── src/            Source: groth16, ecdsa, smt, census, csp, results, kzg, …
├── input-gen/          Rust library: typed protocol blocks → ZisK binary input
├── service/            HTTP API service (axum + tokio)
│   └── src/
│       ├── api/        POST /prove, GET /jobs/*, GET /health
│       ├── prover/     Background job queue and worker
│       ├── config.rs   Environment variable configuration
│       └── types.rs    Full typed request/response structures
└── go-sdk/             Go client library with typed builder API
    ├── *.go            Client, types, ProveBatch, PublicOutputs, converters
    └── tests/
        ├── integration/  Cheat tests (emulator), e2e + CSP integration tests
        └── Makefile      Docker compose test orchestration
```

## Quick start

### Prerequisites

- Docker + Docker Compose
- NVIDIA GPU with driver 570+, CUDA 12.8, nvidia-container-toolkit
- ZisK proving key (~36 GB) — see [Proving key setup](#proving-key-setup)

### Run with Docker

```bash
git clone https://github.com/vocdoni/davinci-zkvm.git
cd davinci-zkvm

# GPU prover (default)
docker compose up -d

# CPU-only (API only — ZisK v0.15 GPU keys are incompatible with CPU proving)
COMPOSE_PROFILES=cpu docker compose up -d
```

### Run locally (non-Docker)

```bash
# Full install: clone + build ZisK, build service, download proving key
make setup

# Run the service (sources .env.local.nodocker automatically)
make run

# Run integration tests (starts/stops service automatically)
make test
```

Override defaults as needed:

```bash
make setup PROVER_MODE=gpu ZISK_VERSION=v0.15.0 PROVING_KEY_PATH=/data/provingKey
make run   ZISK_MPI_PROCS=4 ZISK_MPI_THREADS=8
```

### Submit a proof via the Go SDK

```go
import davinci "github.com/vocdoni/davinci-zkvm/go-sdk"

client := davinci.NewClient("http://localhost:8080")

batch := &davinci.ProveBatch{
    VK:     vk,
    Voters: voters,       // []VoterBallot with Groth16 proofs + ECDSA sigs
    State:  stateData,    // StateTransitionData (SMT transitions)
    Census: censusProofs, // []CensusProof (Merkle) or CspData
    Reenc:  reencData,    // ReencryptionData (ElGamal)
    KZG:    kzgData,      // KZGRequest (blob evaluation)
}

result, err := client.Prove(ctx, batch)
// result.Outputs.OK, result.Outputs.RootHashAfter, ...
```

See [go-sdk/README.md](go-sdk/README.md) for full API documentation.

## API reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/prove` | Submit a state-transition batch for proving |
| `GET` | `/jobs/{id}` | Get job status |
| `GET` | `/jobs/{id}/proof` | Download proof binary (once done) |
| `GET` | `/health` | Service health check |

### `POST /prove`

Accepts a JSON body with typed protocol blocks. See `service/src/types.rs` for the
full `ProveRequest` schema, or use the Go SDK's `ProveBatch` which handles serialization.

### `GET /jobs/{id}`

```json
{
  "job_id": "...",
  "status": "queued|running|done|failed",
  "elapsed_ms": 35000,
  "error": null
}
```

## Proving key setup

The proving key (~36 GB) is downloaded automatically by `make setup`.

For Docker, mount it as a volume:

```bash
# Point PROVING_KEY_PATH to your existing key, or let install.sh download it first
docker compose up -d
```

Or set `PROVING_KEY_PATH` in `.env` to point to an existing key directory.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `LISTEN_ADDR` | `0.0.0.0:8080` | HTTP listen address |
| `PROVING_KEY_PATH` | `/proving-key` | ZisK proving key directory |
| `CIRCUIT_ELF_PATH` | `/app/circuit.elf` | Pre-built circuit ELF |
| `CARGO_ZISK_BIN` | `cargo-zisk` | Path to cargo-zisk binary |
| `PROOF_OUTPUT_DIR` | `/tmp/proofs` | Proof output directory |
| `MAX_QUEUE_SIZE` | `100` | Maximum queued jobs |
| `ZISK_MPI_PROCS` | `1` | MPI processes for proving (`>1` runs `mpirun`) |
| `ZISK_MPI_THREADS` | `0` | Threads per MPI process (sets `OMP_NUM_THREADS` and `RAYON_NUM_THREADS`; `0` = unset) |
| `ZISK_MPI_BIND_TO` | `none` | `mpirun --bind-to` policy |

## Development

```bash
# Build the circuit ELF (requires +zisk toolchain)
cd circuit && cargo +zisk build --release --target riscv64ima-zisk-zkvm-elf
cp circuit/target/riscv64ima-zisk-zkvm-elf/release/davinci-zkvm-circuit circuit/elf/circuit.elf

# Build service binary only
cargo build --release -p davinci-zkvm-service

# Run cheat tests (emulator, no service needed)
cd go-sdk/tests && make test-unit

# Run full integration tests (requires running service)
cd go-sdk/tests && make test
```

### Docker

```bash
# Build images
docker compose build davinci-zkvm      # CUDA GPU image  (Dockerfile.cuda)
docker compose build davinci-zkvm-cpu  # CPU-only image  (Dockerfile)

# Run
docker compose --profile cuda up -d    # Start CUDA GPU service
docker compose --profile cpu  up -d    # Start CPU-only service
```

## Circuit specification

See [CIRCUIT.md](CIRCUIT.md) for a detailed formal specification of every constraint
checked by the circuit, including input/output encoding, fail-mask bits, and
cross-block binding rules.

## Tests

| Test suite | Command | Requirements |
|------------|---------|--------------|
| **Cheat tests** (7 tests) | `make test` | `ziskemu` in PATH |
| **CSP integration** | `cd go-sdk/tests && make test` | Running service |
| **Full E2E** (8 transitions) | `cd go-sdk/tests && make test` | Running service |
| **Lightweight** | `make test-unit` | Running service |

Cheat tests exercise the circuit in the ZisK emulator with deliberate protocol
violations (wrong census root, wrong state root, mismatched vote IDs, wrong
re-encryption key, wrong KZG data) and verify that the fail-mask correctly
identifies each violation.
