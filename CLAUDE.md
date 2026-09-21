# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

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

## Conventions

- **Plain, human voice in comments and docs.** Terse and direct. Skip the
  "stands as a testament" / "vital role" / "evolving landscape" register.
  No em-dash overuse, no rule-of-three, no marketing flourish.
- **Match the project's existing terse style** when writing Rust/Go
  comments. One short line on top of a function is usually enough.

## Layout

| Path | Notes |
|---|---|
| `circuit/` | ZisK RISC-V guest (vote-batch circuit). Build with `cd circuit && cargo-zisk build --release` — the `cd` matters; building from the workspace root pulls in tokio/mio which doesn't compile for the zkvm target. Pre-built ELF lives at `circuit/elf/circuit.elf` and is tracked. |
| `circuit/CIRCUIT.md` | Formal spec of the vote-batch guest: input block ordering, wire format, output registers, per-phase constraint checks, `fail_mask` bits. Read it before touching `circuit/src/` or `input-gen/`, and update it in the same change. |
| `circuit/src/groth16.rs`, `circuit/src/kzg.rs` | In-guest batched Groth16 (BN254) verification of the per-ballot circom proofs, and the KZG/BLS12-381 checks. See the Groth16 gotcha below before touching the batch check. |
| `circuit-primitives/` | no_std lib shared by both guests: SMT, Poseidon, BabyJubJub, BN254/BLS12-381 field arithmetic (`bn254.rs`, `bn254_fr.rs`, `bls_fr.rs`), hashing, field types, io framing. |
| `circuit-aggregator/` | Recursive aggregator guest: genesis+fold / fold / finalize modes, in-guest STARK verification via `ziskos::zisklib::verify_zisk_proof_c`. ELF at `circuit-aggregator/elf/aggregator.elf`. Same `cd`-first build rule. |
| `input-gen/` | Typed protocol blocks → ZisK binary input. Wire format owner (incl. `aggregator.rs` for fold/finalize input frames). |
| `service/src/prover/recursion.rs` | proof.bin → vadcop blob conversion for feeding proofs back into the aggregator guest. |
| `service/` | Axum HTTP API. Always emits PLONK. |
| `service/src/prover/worker.rs` | Runs `cargo-zisk prove --plonk …`, with retry logic for transient ZisK flakes. |
| `service/src/prover/snark.rs` | Bincode-decodes `proof.bin` into the four Solidity-ready byte strings (`programVK`, `rootCVadcopFinal`, `publicValues`, `proofBytes`). |
| `solidity/` | Vendored upstream PLONK verifier, byte-identical to `~/.zisk-1.3/provingKeySnark/final/*.sol` (the 1.3 snark setup; the vkey constants and `rootCVadcopFinal` change with every setup). **Don't edit these in-tree** — the Go helper patches them on a temp copy at compile time, so re-copying after a new ZisK release just works. |
| `go-sdk/` | Go client. Exposes `PlonkSnark` (the 4-tuple) and `client.Prove(ctx, batch) -> ProveResult.Snark`. Never exposes STARK/VADCOP internals (chained mode only sees job IDs + the final PLONK). |
| `go-sdk/chain/` | Chained-mode orchestrator: `Sequencer` (fold cadence, finalize), `State` (process SMT owner, reencryption, results accumulators), `Digest` (53×u32 "DAG1" publics parser + external vk-binding checks). `snapshot.go` serializes/restores `State` for crash recovery (reencryption uses a random `k` per ballot, so replay isn't reproducible). `commitment.go`+`release.go` recompute the guest's `config_commitment` host-side and pin the canonical circuit-release vks (`CircuitRelease`) for independent end-to-end verification. Self-contained — must NOT import test code. |
| `go-sdk/solidity/solidity.go` | `VerifyOnSimulated(dir, snark)` — compiles the verifier (local `solc` or `docker run ethereum/solc:stable`) and runs it on `go-ethereum/ethclient/simulated.NewBackend`. |
| `go-sdk/vocdoni/` | Vendored davinci-node light crypto (ElGamal, hashing, ballot spec types) so `go-sdk` doesn't depend on the full davinci-node module. Exported so external consumers (davinci-fold) can build chain.Config/chain.Vote values; don't import davinci-node directly from go-sdk. |
| `davinci-node/`, `recursion-experiment/` | Untracked reference checkouts (gitignored, not part of this repo). Read for context; never edit or stage. |

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

The circuit cheat/soundness suite runs on `ziskemu` — no GPU, no
service, seconds per case. It is the fastest correctness loop after
touching `circuit/src/` or `input-gen/`. Needs `ziskemu` (ships in
`~/.zisk/bin`, not always on PATH) and `gen-input`
(`cargo build --release -p davinci-zkvm-input-gen`) on PATH, plus
`CIRCUIT_ELF_PATH` or the default `circuit/elf/circuit.elf`:

```bash
cd go-sdk/tests
go test ./integration -run TestCheat -v -timeout 30m
```

Run a single proving test directly:

```bash
cd go-sdk/tests
DAVINCI_API_URL=http://127.0.0.1:8080 DAVINCI_PROOF_TIMEOUT=30m \
  go test -run TestPlonkBenchmark -v -timeout 60m ./integration/
```

The main benchmark is `TestPlonkBenchmark` (sizes 64/128/256,
~12 min full sweep). Single-size smoke test: edit the `sizes` slice in
`bench_test.go` to `[]int{64}`, run, restore to `[]int{64, 128, 256}`
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
- `POST /jobs/import` — accept a raw `proof.bin` body, register it as a
  local `Done` `BatchStark` job (returns `{job_id}`), and write the same
  `stark.json`/`publics.bin` artifacts a natively proved job exposes — so a
  STARK proved on another worker can be referenced by `/fold` here. Decodes
  the blob to reject garbage early; soundness still rests on the fold
  guest's in-circuit re-verification, not on trusting the upload. Exists for
  the external scatter/gather orchestrator (the `davinci-fold` sibling
  repo); the single-worker `Sequencer` never needs it.
- `GET /jobs/{id}/stark` — program_vk + publics of a STARK job (the
  sequencer uses it to learn vks and parse fold digests).
- `GET /jobs/{id}/proof/stark` — the raw vadcop-final STARK blob the
  aggregator verifies (lazily converted from `proof.bin`, cached as
  `vadcop.bin`).
- `GET /jobs/{id}` — status.
- `GET /jobs/{id}/snark` — JSON with `program_vk`, `root_c_vadcop_final`,
  `public_values`, `proof_bytes`. These four hex strings map straight onto
  the arguments of `ZiskVerifier.verifySnarkProof`.
- `GET /jobs/{id}/snark/raw` — raw `proof.bin` (bincode), for
  `cargo-zisk verify`.
- `GET /jobs/{id}/publics` — the guest's 256-byte u32 publics (`publics.bin`).
  Not the on-chain `publicValues` string, which since ZisK 1.3 is the same 64
  publics as 8-byte LE words (512 B); `snark.rs` builds that from `publics_full`.
- `GET /jobs/{id}/inputs` — the raw `input.bin` for audit / re-proving.
- `GET /health`.

## Gotchas worth remembering

- **The Groth16 batch check must stay host-hint-free.** The random
  linear combination over the batch (scaled `A_i`, `sum r_i*C_i`, and the
  gamma-side `sum r_i*L_i`) is recomputed in-guest; the wire format
  carries no precomputed hint points. One GT equation cannot bind n+3
  free G1 points — a malicious host balances `B_i = c_i*beta` against
  `neg_alpha_rsum`, zeroes the gamma/delta terms (all-zero G1 is skipped
  by the pairing precompile) and the batch check passes for forged
  proofs. The coefficients are independent 128-bit Fiat-Shamir values
  (`r_0 = 1`, `r_i = lo128(SHA256(digest || i))`, transcript tag
  `groth16-batch-v2`), not powers of one challenge: the small-exponents
  batch argument gives 2^-128 soundness error per attempt, and starting
  `scalar_mul_bn254` at the MSB makes the per-proof muls half-cost.
  `TestCheatForgedPubs`, `TestCheatSwappedProofs`, `TestCheatZeroedVKGamma`
  and `TestCheatZeroedProofA` guard it.
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
  Prove with `--proving-key ./zisk-keys/provingKey`
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
- **`go-sdk/chain/release.go::CircuitRelease` pins the aggregator
  `program_vk` (`AggVK`) + vote-batch `batch_vk` (`BatchVK`)** for the
  external verifiability anchor. The guest's `config_commitment` is
  `sha256(config frame ‖ batch_vk ‖ fold_vk)`, so a stale manifest fails
  the commitment check after a guest rebuild. Refreeze it straight from
  `cargo-zisk setup -e <elf> -k <proving-key>`, which prints the program vk as
  `Root hash: [w0, w1, w2, w3]`; the pinned string is those four u64 words
  rendered big-endian and concatenated. (A finalize digest's
  `fold_vk`/`batch_vk`, or `FetchStarkInfo`, gives the same values but needs a
  working prover and a GPU.)
- **`verify_zisk_proof_c` + the vadcop blob layout are ZisK internals**, not
  stable API — pin the ZisK version. On 1.3 the call takes six arguments
  (proof, `expected_setup_vk`, `expected_program_vk`), the blob tail is
  `[zisk_vk(4)][hash_tag(1)]`, and an uncompressed proof carries the
  `is_vadcop_final_proof` flag so `n_publics` is 69, shifting the vk/publics
  offsets by one word. `circuit-aggregator/src/main.rs` pins the accepted
  shape and asserts it; `input-gen/src/aggregator.rs` rebuilds the same
  layout host-side. Both must move together.
- **`SETUP_VK` in the aggregator guest must stay a compile-time constant.**
  It is the ZisK vadcop-final setup key
  (`provingKey/zisk/vadcop_final/vadcop_final.verkey.json`), and upstream is
  explicit that a key read from program input makes verification self-keyed
  and authenticates nothing. `batch_vk`/`fold_vk` stay runtime-bound: they are
  folded into `config_commitment` and pinned externally by `CircuitRelease`,
  which is what makes the chain's program authorization hold. Refreeze
  `SETUP_VK` whenever the ZisK release or its setup key changes.
- **128 is the maximum batch size** (`MAX_BATCH_SIZE` in
  `circuit-primitives/src/types.rs`, mirrored in `input-gen` and
  `go-sdk/types.go`): the circuit rejects any batch with more than 128
  proofs. Raising it means changing all three constants and rebuilding
  both ELFs (new program_vk). **Lowered from 256 to 128 for GPU-memory
  safety:** batch 256 at full ballot capacity (`num_fields = 16`) peaks at
  ~31.3 GB even with `--minimal-memory`, within ~0.7 GB of the 32 GB GPU
  ceiling and with no softer knob left — so any future circuit growth would
  push it over with no recovery path. 128 keeps a comfortable margin. Before
  raising the cap again, re-measure peak GPU memory at the new worst case
  (`batch × num_fields = 16`); `--minimal-memory` is still auto-enabled on
  retry as a backstop (see Performance baseline).
- **Ballot capacity is `NUM_FIELDS = 16`** (`circuit-primitives/src/types.rs`,
  mirrored in `input-gen/src/lib.rs` and `go-sdk/types.go`;
  davinci-node calls it `FieldsPerBallot`). The fixed-size gnark/circom
  circuits always carry 16 ElGamal ciphertexts, but the zkVM guest reads
  the election's declared `num_fields` from bits[0:8] of the committed
  BallotMode leaf (`process_proofs[1].new_value[0]`, bound to the
  `old_state_root`) and skips per-field EC work on padded slots
  `i >= num_fields`. **Soundness rests on identity-padding:** davinci-node
  stores the TE identity ciphertext `((0,1),(0,1))` in padded slots (not an
  encryption-of-zero), and the guest asserts each padded slot is identity
  before skipping its reencryption-verify and accumulator EC adds
  (`verify_reencryption` / `ballot_net` in `circuit-primitives/src/`). The
  SHA-256 ballot leaf still covers all 16 coords. Reencryption uses a
  distinct offset scalar per field, chained with SHA-256:
  `k_0 = H(k)`, `k_{i+1} = H(k_i)` where `H(x) = sha256(x_be32) mod r`
  (`sha256_to_scalar` in `circuit-primitives/src/babyjubjub.rs`, mirrored by
  the producer in davinci-node `crypto/elgamal/ballot.go::reencryptScalar`).
  SHA-256 keeps the k-chain on the `sha256f` precompile instead of the ArithEq
  state machine (one `arith256_mod` row per step for the Fr reduction); this
  diverges from davinci-node's own gnark circuit, which is acceptable since the
  zkVM is the production prover. `TestCheatTamperPaddedSlot` guards the skip;
  sweep configs in tests with `BALLOT_NUM_FIELDS`.

## ZisK 1.3.0-alpha + BabyJubJub precompile

The guests build against upstream `ziskos` pinned by rev
(`9e9291d2`, branch `pre-develop-1.3.0-alpha`), which carries the BabyJubJub
precompile. `circuit-primitives/src/babyjubjub.rs` is affine and
syscall-backed: no projective coordinates, no field inversions.

Toolchain lives in `~/.zisk-1.3` (binaries, both proving keys, guest
toolchain). Build and prove with `PATH=$HOME/.zisk-1.3/bin:$PATH`.

- **`cargo-zisk` hardcodes the rustup toolchain name `zisk`**
  (`RUSTUP_TOOLCHAIN_NAME` in `ziskbuild`), so the 1.3 toolchain must be
  linked under exactly that name or it silently pairs the new driver with an
  old target spec. The symptom is a link error, `region 'rom' already
  defined`. Fix: `rustup toolchain link zisk ~/.zisk-1.3/toolchains/zisk-4.0.0`.
- **`program-setup` is now `setup`**, and `--gpu` was dropped from it (hash
  mode comes from the proving key's `global_info.json`).
- **`cargo-zisk prove` dropped `--emulator`** (the Rust emulator is the
  default; `--asm` selects the assembly one) and renamed `--verify-proofs` to
  `--verify-proof`.
- **The proving key must be a Poseidon hash mode.** 1.3 defaults to Blake3,
  which cannot do PLONK wrapping at all. The installed key is Poseidon1.
- **`ziskos` 1.3 drags a CUDA prover into guest builds** via
  `zisk-verifier` -> `proofman-fields` -> `proofman-starks-lib-c`, which is
  unconditional. `circuit-primitives/Cargo.toml` declares that crate solely to
  force its `cpu-only` feature through feature unification. It must stay a
  `branch` ref, matching upstream: a cargo source id includes the git ref, so
  pinning `rev` would resolve a second copy of the crate and break the
  unification. Also note nvcc rejects gcc > 14, so CUDA builds need
  `CUDAHOSTCXX=/usr/bin/g++-14`.
- **1.3 weakened `is_on_curve_bn254`**: it now ends in
  `eq(lhs, rhs) || eq(p, G1_IDENTITY)` and so accepts the all-zero identity,
  where v0.18's plain `eq(lhs, rhs)` rejected it. `g1_is_valid` in
  `circuit-primitives/src/bn254.rs` re-asserts non-identity; every G1 point
  that feeds the batch MSM goes through it.
- **The precompile does not reduce its inputs.** It requires both coordinates
  in Fr range, but stored ballot coords are raw words (the SMT leaf hash binds
  bytes, not residues), so `x + p` legitimately arrives as an encoding of `x`.
  `babyjubjub.rs::canon` reduces at the untrusted boundary — the accumulator,
  the public point API and the reencryption inputs — which keeps `affine_add`
  syscall-only on the hot path.

**PLONK works on 1.3, but only with a consistently built toolchain.** The
binaries in `~/.zisk-1.3/bin` are built from `~/zisk-1.3` (branch head, proofman
`20f09bff`) with three local patches to the proofman checkout under
`~/.cargo/git/checkouts/pil2-proofman-*/20f09bf` (saved as
`~/.zisk-1.3/patches/*.patch`, re-apply after any `cargo clean`/re-fetch):

- `provers/starks-lib-c/build.rs`: link `cudart_static` from `$CUDA_HOME/lib64`.
  Upstream hardcodes `/usr/local/cuda/lib64`, which is CUDA 12.8 here, while
  nvcc has to be 13.1 (12.8 cannot compile against glibc 2.43). Mixing them
  breaks the `cudaDeviceProp` layout: `multiProcessorCount` reads as 1, sppark
  launches a 0-block grid, every PLONK MSM fails with
  `cudaErrorInvalidConfiguration`, and the proof comes out with T1/T2/T3/Wxi/Wxiw
  zeroed (A/B/C/Z only look populated because of the host-side blinding
  correction). That was the "SNARK verification failed" of the first port.
- `src/bn128/src/msm/msm_bn128.cu`: log the CUDA error instead of silently
  returning the point at infinity.
- `src/bn128/src/poseidon/poseidon_bn128.cu`: `__launch_bounds__(512)` on the
  grinding kernel; without it the 512-thread launch does not fit on sm_120 and
  recursivef aborts with `too many resources requested for launch`.

Build recipe (cargo treats git checkouts as immutable, so after touching a
patched C++ file run `make -j starks_lib_gpu` in `pil2-stark/` and
`cargo clean -p proofman-starks-lib-c` before the build):

```bash
cd ~/zisk-1.3 && CUDA_HOME=/usr/local/cuda-13.1 PATH=/usr/local/cuda-13.1/bin:$PATH \
  NVCC_PREPEND_FLAGS="-ccbin g++-14" CUDAHOSTCXX=/usr/bin/g++-14 CUDA_ARCHS=120 \
  cargo build --release --target x86_64-unknown-linux-gnu
cp target/x86_64-unknown-linux-gnu/release/{cargo-zisk,cargo-zisk-dev,ziskemu,zisk-transpiler-riscv,zisk-coordinator,zisk-worker} ~/.zisk-1.3/bin/
```

Two consumer-side changes came with it: `solidity/` is re-vendored from the
1.3 snark setup, and the on-chain `publicValues` is now the 512-byte
`snark_inputs_bytes` encoding (see the API notes), which `snark.rs` derives from
`publics_full`. Batch 64 PLONK proves in ~26 s and `TestChainOrchestrator`
passes with the final PLONK verified on the simulated chain.

The Docker/`ziskup` install path (`Makefile`, `Dockerfile.*`,
`scripts/install*.sh`) still targets the v0.18.0 **release** and cannot work
against an unreleased branch. Use the local toolchain in `~/.zisk-1.3` for 1.3
work.

### Measured (RTX 5090, num_fields=6, STARK, GPU)

Same input files proved on both stacks, both verified:

| batch | v0.18.0 | 1.3 + precompile | speedup | votes/min |
|---:|---:|---:|---:|---:|
|  64 | 61.2 s | 22.6 s | 2.71x | 63 -> 170 |
| 128 | 94.0 s | 32.8 s | 2.87x | 82 -> 234 |

Two variables move at once there (ZisK version and the precompile), so treat
the speedup as the combination, not the precompile alone.

Per-batch PLONK on the same stack (`TestPlonkBenchmark`, service job time,
votes/min = batch / proof; 256 and 512 measured on a scratch guest with the
cap raised, see `BENCHMARK.md`):

| batch | num_fields=2 | votes/min | num_fields=16 | votes/min |
|---:|---:|---:|---:|---:|
|  64 |  22.8 s | 168 |  29.1 s | 132 |
| 128 |  31.6 s | 243 |  43.7 s | 176 |
| 256 |  51.1 s | 300 |  73.8 s | 208 |
| 512 |  71.3 s | 431 | 123.5 s | 249 |

## Historical baseline (RTX 5090, ZisK v0.18.0)

Ballot capacity is 16 fields (`NUM_FIELDS`), but the guest reads the
election's declared `num_fields` from the committed BallotMode leaf and
skips the per-field EC work on identity-padded slots `i >= num_fields`
(see the `NUM_FIELDS` gotcha above). Proving time therefore scales with
the *declared* field count, not the 16-field maximum. PLONK SNARK time
(`TestPlonkBenchmark`, sweep the field count with `BALLOT_NUM_FIELDS`):

| batch | num_fields=2 | num_fields=16 | on-chain verify |
|---:|---:|---:|---:|
|  64 |   38 s |    83 s | ~0.3–0.5 s |
| 128 |   73 s |   164 s | ~0.5 s |
| ~~256~~ |  102 s | 289 s (min-mem) | ~0.3 s |

128 is now the `MAX_BATCH_SIZE` cap; the 256 row is retained for context
(it is the corner that motivated the cap — see below). SNARK size is 768 B
`proofBytes` / 256 B `publicValues` (512 B on 1.3), invariant across batch size and field
count (the on-chain interface does not change with `num_fields`). On-chain
verify is field-count independent.

**Why the cap is 128: batch 256 at num_fields=16 sits at the GPU edge.**
The per-field chained reencryption (a distinct SHA-256-chained offset scalar
per ciphertext field) means ~16 EC scalar-muls per ballot at full capacity;
at 256 ballots the default GPU schedule overflows
32 GB during inner-proof generation (deterministic SIGKILL, not a transient
flake). `cargo-zisk prove --minimal-memory` reschedules witness storage and
keeps the footprint under the ceiling (peak ~31.3 GB), proving+verifying in
~289 s — but that leaves only ~0.7 GB of headroom and no softer knob below it,
so any future circuit growth would OOM 256 with no recovery path. We therefore
capped `MAX_BATCH_SIZE` at 128, which proves comfortably. `--minimal-memory`
stays wired as a backstop: it only reschedules witness storage — it doesn't
touch the circuit, constraints, or the proven statement, so the result still
verifies and soundness is unaffected (the proof bytes differ run-to-run anyway:
the PLONK wrap is zero-knowledge). The speed cost is small: a matched A/B on
one batch-128 num_fields=16 input measured 138.4 s plain vs 142.1 s with
`--minimal-memory` (+2.7%); on a lighter input it was +0.7%. The worker
auto-escalates to it on any retry, and `ZISK_MINIMAL_MEMORY=1` forces it from
the first attempt — relevant only if the cap is ever raised back toward 256.

Chained-mode numbers (STARK batches + folds + one final PLONK) live in
`BENCHMARK.md`.

## Workflow tips

- Read the source before editing. The codebase is small enough.
- After editing Go: `cd go-sdk && go vet ./...`. After editing Rust:
  `cargo check -p davinci-zkvm-service`. Both are subsecond.
- After editing `service/src/prover/worker.rs` or `snark.rs`, the Docker
  image is stale — rebuild with `docker compose --profile cuda build`
  before restarting the service.
- `circuit/CIRCUIT.md` is the guest's spec, not a changelog — a wire
  format or constraint change lands there in the same commit.
- The CSP, ECDSA, and SMT wire formats are tightly coupled across
  `circuit/src/`, `input-gen/src/lib.rs`, `service/src/types.rs`, and
  `go-sdk/`. Any wire-format change has to land in all four atomically.
- When in doubt about Solidity / on-chain semantics, look at
  `solidity/ZiskVerifier.sol::verifySnarkProof` — the four arguments
  match the four fields of `PlonkSnark`.
