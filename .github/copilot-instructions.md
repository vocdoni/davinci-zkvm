# Copilot Instructions — davinci-zkvm

## What this is

A ZisK zkVM service that verifies DAVINCI state transitions. The system takes
`davinci-stark` ballot proofs and other protocol blocks as input, encodes them
into a binary guest input, executes the ZisK RISC-V guest circuit, and produces
a zkVM proof that the state transition is valid.

Current ZisK runtime: **v0.16.0**

## Architecture

```
                POST /prove
                    │
              ┌─────▼──────┐
              │   service   │  Axum HTTP service, async job queue
              │  (Rust)     │  Calls cargo-zisk to execute + prove
              └─────┬───────┘
                    │ encodes request via
              ┌─────▼──────┐
              │  input-gen  │  Binary encoder: request JSON → guest input bytes
              │  (Rust lib) │  Block tags: DSTARKB!, STAG5TX!, REG5BLK!, KZGBLK!!
              └─────┬───────┘
                    │ feeds
              ┌─────▼──────┐
              │   circuit   │  ZisK RISC-V guest (NOT in workspace)
              │  (Rust)     │  Verifies proofs, signatures, SMTs, bindings
              └─────────────┘

              ┌─────────────┐
              │   go-sdk    │  Go client SDK + integration test suite
              │  (Go)       │  Typed client, ballot builders, ecgfp5 helpers
              └─────────────┘
```

The sibling crate `davinci-stark` (at `../..` relative to `circuit/`) provides
the ballot proof system. The circuit embeds a fixed `davinci-stark` verifier.

## Build & test

### Rust workspace (service + input-gen)

```bash
# All workspace tests
cargo test

# Single crate
cargo test -p davinci-zkvm-input-gen
cargo test -p davinci-zkvm-service

# Single test
cargo test -p davinci-zkvm-input-gen -- test_name
```

### Circuit (excluded from workspace)

The circuit is a ZisK RISC-V guest. It requires the `+zisk` toolchain and
**cannot** be compiled with standard cargo.

```bash
cd circuit
cargo +zisk build --release --target riscv64ima-zisk-zkvm-elf
cargo test --manifest-path circuit/Cargo.toml   # host-side unit tests only
```

### Go SDK & integration tests

```bash
cd go-sdk && go test ./... -count=1

# Integration tests (requires running service)
cd go-sdk/tests
make test          # full suite (GPU proving)
make test-unit     # lightweight: health, validation, 404 only (no proving)

# Single Go test
cd go-sdk/tests/integration
DAVINCI_API_URL=http://localhost:8080 go test -v -run TestName ./...
```

### Full local setup & run

```bash
make setup         # install deps, build everything, generate proving key trees
make run           # start HTTP service locally
make test          # start service + run integration tests + stop
```

### Docker

```bash
docker compose --profile cuda up -d   # GPU prover
docker compose --profile cpu  up -d   # CPU API-only (no proving)
```

## Crate & package names

| Directory   | Cargo package name        | Binary name         |
|-------------|---------------------------|---------------------|
| `service/`  | `davinci-zkvm-service`    | `davinci-zkvm`      |
| `input-gen/`| `davinci-zkvm-input-gen`  | (library)           |
| `circuit/`  | `davinci-zkvm-circuit`    | `davinci-zkvm-circuit` |
| `go-sdk/`   | `github.com/vocdoni/davinci-zkvm/go-sdk` | — |

## Key conventions

### Block-tagged binary protocol

Guest input is a sequence of tagged binary blocks (`DSTARKB!`, `STAG5TX!`,
`CENSUS!!`, `CSPBLK!!`, `REG5BLK!`, `KZGBLK!!`). The encoder lives in
`input-gen/src/lib.rs`; the parser lives in `circuit/src/io.rs` and
`circuit/src/types.rs`. Both sides must agree on byte layout — changes must be
coordinated across input-gen, circuit, and go-sdk.

### Batch size

`MAX_BATCH_SIZE` is a compile-time constant (default 128, must be power of 2,
minimum 2). Set via `DAVINCI_MAX_BATCH_SIZE` env var at build time. The same
value must be used in Rust builds and the Go integration test runtime.

### Cross-block binding

The guest does not treat input blocks independently. `circuit/src/binding.rs`
enforces consistency across all blocks (process IDs match, keys match,
ciphertexts match between ballot/reencryption/state blocks). Any new block type
must be wired into the binding checks.

### Environment-driven configuration

The service reads all config from env vars (see `service/src/config.rs`). Key
variables: `LISTEN_ADDR`, `PROVING_KEY_PATH`, `CIRCUIT_ELF_PATH`,
`PROOF_OUTPUT_DIR`, `MAX_QUEUE_SIZE`, `ZISK_MPI_PROCS`.

### Fail mask output

The guest uses a bitmask to report which checks failed (see
`circuit/CIRCUIT.md` for the full bit map). Bit 31 (`FAIL_PARSE`) indicates
malformed input.

### Two Poseidon families in the circuit

- **Goldilocks Poseidon2** (width-16): used for STARK infrastructure hashing
  via the ZisK precompile. This is the verifier-side hash.
- **BN254 iden3 Poseidon**: retained only for Lean-IMT census proofs because
  the external census format is still BN254 Poseidon-based.

Do not confuse these. New ballot/state code should use the Goldilocks Poseidon2
path, not the BN254 one.

### ecgfp5 ciphertext encoding

Ballot encryption uses ecgfp5 ElGamal. Each voter has 8 ciphertext pairs
(C1, C2). The canonical encoding is 8 × 2 encoded ecgfp5 points. This encoding
must match between `davinci-stark`, `circuit/src/ecgfp5_verify.rs`,
`input-gen/src/stark_types.rs`, and `go-sdk/stark_types.go`.

### Go ↔ Rust encoding parity

The Go SDK must produce the exact same byte encodings as the Rust input-gen for
types like STARK public values, ecgfp5 points, and Poseidon2 hashes. The
integration test suite in `go-sdk/tests/integration/` is the primary validation
for this cross-language parity.

## API

`POST /prove` → async job. Returns `{ job_id, status }`.
`GET /jobs/:id` → poll job status.
`GET /health` → service health check.

See `service/src/types.rs` for the full `ProveRequest` schema and
`go-sdk/types.go` for the Go mirror.

## Migration context

The codebase is actively migrating from a Groth16/BN254/BabyJubJub ballot path
to `davinci-stark`/Goldilocks/ecgfp5. See `PLAN_INTEGRATE_ZKVM.md` for the
full migration plan and current status. Some legacy BN254/BabyJubJub code
remains in the circuit and Go tests pending full migration.
