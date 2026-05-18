# davinci-zkvm — Claude project notes

## What this is

A ZisK zkVM service for the DAVINCI voting protocol. It takes a batch of
voter ballots plus state-transition data, runs the whole protocol inside
one RISC-V circuit, and returns a PLONK SNARK ready for on-chain
verification with the contracts in `solidity/`.

The service is **PLONK-only**. STARK-only and VADCOP fallback paths were
removed in the last cleanup pass; both `PROVING_KEY_PATH` and
`PROVING_KEY_PLONK_PATH` are required at startup.

## House rules

- **Never commit or push without the user asking.** They will say "commit
  this" / "push it." Wait for it.
- **No `Co-Authored-By: Claude` (or Anthropic) trailers** in commit
  messages. Strip them if present.
- **Don't stage scratch `.md` files.** Files like `PRECOMPILE_AUDIT.md`,
  `TASK.md`, `STATUS.md`, `progress.md`, etc. are session notes and live
  untracked. `.gitignore` covers most; stage by explicit filename, never
  `git add -A` or `git add .`.
- **Plain, human voice in comments and docs.** Terse and direct. Skip the
  "stands as a testament" / "vital role" / "evolving landscape" register.
  No em-dash overuse, no rule-of-three, no marketing flourish.
- **Match the project's existing terse style** when writing Rust/Go
  comments. One short line on top of a function is usually enough.

## Layout

| Path | Notes |
|---|---|
| `circuit/` | ZisK RISC-V guest. Build with `cd circuit && cargo-zisk build --release` — the `cd` matters; building from the workspace root pulls in tokio/mio which doesn't compile for the zkvm target. Pre-built ELF lives at `circuit/elf/circuit.elf` and is tracked. |
| `input-gen/` | Typed protocol blocks → ZisK binary input. Wire format owner. |
| `service/` | Axum HTTP API. Always emits PLONK. |
| `service/src/prover/worker.rs` | Runs `cargo-zisk prove --plonk …`, with retry logic for transient ZisK flakes. |
| `service/src/prover/snark.rs` | Bincode-decodes `proof.bin` into the four Solidity-ready byte strings (`programVK`, `rootCVadcopFinal`, `publicValues`, `proofBytes`). |
| `solidity/` | Vendored upstream PLONK verifier, byte-identical to `~/.zisk/provingKeySnark/final/*.sol`. **Don't edit these in-tree** — the Go helper patches them on a temp copy at compile time, so re-copying after a new ZisK release just works. |
| `go-sdk/` | Go client. Exposes `PlonkSnark` (the 4-tuple) and `client.Prove(ctx, batch) -> ProveResult.Snark`. Never exposes STARK/VADCOP internals. |
| `go-sdk/solidity/solidity.go` | `VerifyOnSimulated(dir, snark)` — compiles the verifier (local `solc` or `docker run ethereum/solc:stable`) and runs it on `go-ethereum/ethclient/simulated.NewBackend`. |

## Build & test commands

```bash
# Rust service
cargo build --release -p davinci-zkvm-service

# Circuit ELF (needs +zisk toolchain, must run from circuit/)
cd circuit && cargo-zisk build --release
cp circuit/target/elf/riscv64ima-zisk-zkvm-elf/release/davinci-zkvm-circuit \
   circuit/elf/circuit.elf

# Docker image
docker compose --profile cuda build

# Bring the service up
docker compose --profile cuda up -d

# Go SDK + tests
cd go-sdk && go build ./...
cd go-sdk/tests && go build ./integration/...
```

Integration tests live in `go-sdk/tests/integration/` and need a running
service. The main benchmark is `TestPlonkBenchmark` (sizes
64/128/256/512, ~18 min full sweep). Single-size smoke test: edit the
`sizes` slice to `[]int{64}`, run, restore to `[]int{64, 128, 256, 512}`
before committing.

Test invocations need `DAVINCI_API_URL=http://127.0.0.1:8080` and a
generous `DAVINCI_PROOF_TIMEOUT` (≥30m).

## HTTP API surface

- `POST /prove` — submit a batch, get a job ID.
- `GET /jobs/{id}` — status.
- `GET /jobs/{id}/snark` — JSON with `program_vk`, `root_c_vadcop_final`,
  `public_values`, `proof_bytes`. These four hex strings map straight onto
  the arguments of `ZiskVerifier.verifySnarkProof`.
- `GET /jobs/{id}/snark/raw` — raw `proof.bin` (bincode), for
  `cargo-zisk verify`.
- `GET /jobs/{id}/publics` — just the 256-byte `publicValues` blob.
- `GET /jobs/{id}/inputs` — the raw `input.bin` for audit / re-proving.
- `GET /health`.

## Gotchas worth remembering

- **`cargo-zisk build` from the workspace root pulls in non-ZisK deps**
  (tokio, mio). Always `cd circuit/` first.
- **PLONK proving key `final.so` has an executable-stack flag** that
  modern Linux refuses at dlopen time. `scripts/install.sh` patches it by
  clearing the X bit on `PT_GNU_STACK`. Inside Docker the volume-mounted
  host copy is already patched, so it works transparently. If a fresh
  ZisK key download lands somewhere new, re-run `scripts/install.sh` or patch
  manually.
- **The upstream Solidity sources use `bytes32 calldata`** which current
  solc rejects. `go-sdk/solidity/solidity.go::stageAndPatchSources`
  rewrites that on a temp copy before compiling — don't fix it in-tree.
- **Transient prover flakes** (`context is destroyed`, `Proof
  contribution challenge does not match`) are auto-retried up to 3× by
  the worker. Don't widen the matcher to include bare `SIGABRT` — it
  also fires for deterministic witness-gen assertions which should not
  be retried.
- **The GPU power cap was 500 W** on this machine; raised persistently
  to 575 W via `/etc/systemd/system/nvidia-power-limit.service`.

## Performance baseline (RTX 5090, ZisK v0.18.0)

| batch | PLONK SNARK | votes/s | on-chain verify |
|---:|---:|---:|---:|
|  64 |   37 s | 1.7 | 350 ms |
| 128 |   57 s | 2.2 | 340 ms |
| 256 |   97 s | 2.6 | 340 ms |
| 512 |  138 s | 3.7 | 480 ms |

SNARK size is 2.7 KB regardless of batch.

## Workflow tips

- Read the source before editing. The codebase is small enough.
- After editing Go: `cd go-sdk && go vet ./...`. After editing Rust:
  `cargo check -p davinci-zkvm-service`. Both are subsecond.
- After editing `service/src/prover/worker.rs` or `snark.rs`, the Docker
  image is stale — rebuild with `docker compose --profile cuda build`
  before restarting the service.
- The CSP, ECDSA, and SMT wire formats are tightly coupled across
  `circuit/src/`, `input-gen/src/lib.rs`, `service/src/types.rs`, and
  `go-sdk/`. Any wire-format change has to land in all four atomically.
- When in doubt about Solidity / on-chain semantics, look at
  `solidity/ZiskVerifier.sol::verifySnarkProof` — the four arguments
  match the four fields of `PlonkSnark`.
