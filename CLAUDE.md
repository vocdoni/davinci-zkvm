# davinci-zkvm — Claude project notes

## What this is

A ZisK zkVM service for the DAVINCI voting protocol. It takes a batch of
voter ballots plus state-transition data, runs the whole protocol inside
one RISC-V circuit, and returns a PLONK SNARK ready for on-chain
verification with the contracts in `solidity/`.

There are two modes:

- **Per-batch mode** (the original): every `/prove` job returns a PLONK,
  one on-chain verification per batch (the davinci-node model).
- **Chained mode**: batches are proved STARK-only (`"output": "stark"`),
  recursively folded by a second guest (`circuit-aggregator/`), and a
  single final PLONK per election attests genesis, every transition and
  the decrypted results. See the README "Chained mode" section for the
  full design; orchestration lives in `go-sdk/chain`.

Both `PROVING_KEY_PATH` and `PROVING_KEY_PLONK_PATH` are required at
startup; chained mode additionally needs `AGGREGATOR_ELF_PATH`.

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
| `circuit/` | ZisK RISC-V guest (vote-batch circuit). Build with `cd circuit && cargo-zisk build --release` — the `cd` matters; building from the workspace root pulls in tokio/mio which doesn't compile for the zkvm target. Pre-built ELF lives at `circuit/elf/circuit.elf` and is tracked. |
| `circuit-primitives/` | no_std lib shared by both guests: SMT, Poseidon, BabyJubJub, hashing, field types, io framing. |
| `circuit-aggregator/` | Recursive aggregator guest: genesis+fold / fold / finalize modes, in-guest STARK verification via `ziskos::zisklib::verify_zisk_proof_c`. ELF at `circuit-aggregator/elf/aggregator.elf`. Same `cd`-first build rule. |
| `input-gen/` | Typed protocol blocks → ZisK binary input. Wire format owner (incl. `aggregator.rs` for fold/finalize input frames). |
| `service/src/prover/recursion.rs` | proof.bin → vadcop blob conversion for feeding proofs back into the aggregator guest. |
| `service/` | Axum HTTP API. Always emits PLONK. |
| `service/src/prover/worker.rs` | Runs `cargo-zisk prove --plonk …`, with retry logic for transient ZisK flakes. |
| `service/src/prover/snark.rs` | Bincode-decodes `proof.bin` into the four Solidity-ready byte strings (`programVK`, `rootCVadcopFinal`, `publicValues`, `proofBytes`). |
| `solidity/` | Vendored upstream PLONK verifier, byte-identical to `~/.zisk/provingKeySnark/final/*.sol`. **Don't edit these in-tree** — the Go helper patches them on a temp copy at compile time, so re-copying after a new ZisK release just works. |
| `go-sdk/` | Go client. Exposes `PlonkSnark` (the 4-tuple) and `client.Prove(ctx, batch) -> ProveResult.Snark`. Never exposes STARK/VADCOP internals (chained mode only sees job IDs + the final PLONK). |
| `go-sdk/chain/` | Chained-mode orchestrator: `Sequencer` (fold cadence, finalize), `State` (process SMT owner, reencryption, results accumulators), `Digest` (53×u32 "DAG1" publics parser + external vk-binding checks). Self-contained — must NOT import test code. |
| `go-sdk/solidity/solidity.go` | `VerifyOnSimulated(dir, snark)` — compiles the verifier (local `solc` or `docker run ethereum/solc:stable`) and runs it on `go-ethereum/ethclient/simulated.NewBackend`. |

## Build & test commands

The root `Makefile` drives the Docker workflow and is the primary entry
point (`make help` lists everything):

```bash
make install   # download both proving keys into ./zisk-keys + build image
make up        # start the prover service (first boot builds consttrees, ~10 min)
make test      # integration suite against the running service
make logs / status / shell / down / restart / clean
```

`make` targets honor `ZISK_KEYS_DIR` (default `./zisk-keys`),
`LISTEN_PORT` (default 8080), and `ZISK_TAG`/`ZISK_VERSION`. There is
also a non-Docker path for development on the build host:
`make local-setup` (runs `scripts/install.sh`), `make local-run`,
`make local-test` — these use `~/.zisk/provingKey*` and
`.env.local.nodocker`.

Direct commands when iterating:

```bash
# Rust service
cargo build --release -p davinci-zkvm-service

# Circuit ELF (needs +zisk toolchain, must run from circuit/)
cd circuit && cargo-zisk build --release
cp circuit/target/elf/riscv64ima-zisk-zkvm-elf/release/davinci-zkvm-circuit \
   circuit/elf/circuit.elf

# Aggregator ELF (same rules; rebuilding changes its program_vk)
cd circuit-aggregator && cargo-zisk build --release
cp circuit-aggregator/target/elf/riscv64ima-zisk-zkvm-elf/release/davinci-zkvm-aggregator \
   circuit-aggregator/elf/aggregator.elf

# Docker image (what `make build` runs)
docker compose --profile cuda build

# Go SDK + tests
cd go-sdk && go build ./...
cd go-sdk/tests && go build ./integration/...
```

Integration tests live in `go-sdk/tests/integration/` and need a running
service; `go-sdk/tests/Makefile` has its own targets:

```bash
cd go-sdk/tests
make test        # full suite, 30m timeout
make test-unit   # lightweight only (health/validation/404) — sets
                 # DAVINCI_SKIP_PROVING=1, no GPU needed, runs in seconds
```

Run a single proving test directly:

```bash
cd go-sdk/tests
DAVINCI_API_URL=http://127.0.0.1:8080 DAVINCI_PROOF_TIMEOUT=30m \
  go test -run TestPlonkBenchmark -v -timeout 60m ./integration/
```

The main benchmark is `TestPlonkBenchmark` (sizes 64/128/256/512,
~18 min full sweep). Single-size smoke test: edit the `sizes` slice in
`bench_test.go` to `[]int{64}`, run, restore to `[]int{64, 128, 256, 512}`
before committing.

Chained-mode tests (gated by env, need GPU service):

```bash
cd go-sdk/tests
# E2E orchestrator test (genesis -> batches -> folds -> finalize -> on-chain verify)
CHAIN_ORCH_TEST=1 DAVINCI_API_URL=http://127.0.0.1:8080 \
  CHAIN_BATCHES=2 CHAIN_BATCH_SIZE=2 CHAIN_FOLD_EVERY=1 \
  go test ./integration -run TestChainOrchestrator -v -timeout 30m

# Benchmark with per-phase breakdown (pipelined ballot gen, manual folds)
CHAIN_BENCH=1 DAVINCI_API_URL=http://127.0.0.1:8080 \
  BENCH_VOTES=1024 BENCH_BATCH_SIZE=64 BENCH_FOLD_EVERY=4 \
  go test ./integration -run TestChainBenchmark -v -timeout 120m
```

The reproducible sweep lives in `benchmark/` (`make benchmark` runs it,
`make benchmark-report` regenerates `benchmark/results/RESULTS.md` from
existing logs). Ballot inputs are pre-generated before the timed section
and cached in `benchmark/cache/ballots-<votes>.gob` — only the first run
pays the generation cost. Curated results live in `BENCHMARK.md`.

## HTTP API surface

- `POST /prove` — submit a batch, get a job ID. Optional `"output":
  "stark"|"plonk"` (default plonk); chained mode uses `stark`.
- `POST /fold` — aggregator fold over completed batch jobs (+ optional
  `prev_fold_job`); first fold carries `genesis_config`. Proof blobs are
  assembled server-side from on-disk `proof.bin` — Go never ships them.
- `POST /finalize` — last fold + results payload (CP decryption proofs,
  plaintext results, SMT inclusion siblings) → the final PLONK.
- `GET /jobs/{id}/stark` — program_vk + publics of a STARK job (the
  sequencer uses it to learn vks and parse fold digests).
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
  modern Linux refuses at dlopen time. The key installers clear the X bit
  on `PT_GNU_STACK` (`make keys` for the Docker path, `scripts/install.sh`
  for local). Inside Docker the volume-mounted host copy is already
  patched, so it works transparently. If a fresh ZisK key download lands
  somewhere new, re-run the installer or patch manually.
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
- **The host `~/.zisk/provingKey` is stale**: recursion-stage witness gen
  fails with `Failed assert in … VerifyEvaluations0/VerifyFinalPol0`.
  Prove with `--proving-key /home/p4u/davinci-zkvm/zisk-keys/provingKey`
  (the dockerized installer's copy; mounted at `/proving-key` in the
  container).
- **Chained mode: 32-byte fields are arbo-LE hex** (no `0x` prefix) in
  `ChainConfig`/`ResultsPayload`, and STATETX `ProcessID` must be arbo-LE
  too — BE encoding makes the batch circuit silently commit `ok=0` and
  the fold then rejects it.
- **Digest `step_count` counts fold steps, not batches** — the guest
  increments once per fold regardless of how many batch proofs it folds.
  `Sequencer.FoldCount()` tracks the expected value.
- **Rebuilding either guest changes its program_vk.** The sequencer
  learns vks at runtime (`GET /jobs/{id}/stark`), but anything that
  pins a vk (docs, on-chain expectations) goes stale on rebuild.
- **`verify_zisk_proof_c` + the vadcop blob layout are ZisK v0.18.0
  internals**, not stable API — pin the ZisK version;
  `service/src/prover/recursion.rs` asserts the layout.
- **Chained-mode batch 512 OOMs on this host**: the STARK prove peaks at
  ~57 GB anon RSS and the kernel kills cargo-zisk (59 GB RAM). It can
  take the service down with it. Use batch ≤ 256 in chained mode here.

## Performance baseline (RTX 5090, ZisK v0.18.0)

| batch | PLONK SNARK | votes/s | on-chain verify |
|---:|---:|---:|---:|
|  64 |   37 s | 1.7 | 350 ms |
| 128 |   57 s | 2.2 | 340 ms |
| 256 |   97 s | 2.6 | 340 ms |
| 512 |  138 s | 3.7 | 480 ms |

SNARK size is 2.7 KB regardless of batch. Chained-mode numbers
(STARK batches + folds + one final PLONK) live in `BENCHMARK.md`.

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
