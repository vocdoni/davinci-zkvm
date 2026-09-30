# Testing

The suites fall into three groups: unit tests that run anywhere, circuit
tests that run the guests on the ZisK emulator, and integration tests and
benchmarks that need a running prover with a GPU.

## Unit tests

```bash
cargo test -p davinci-zkvm-service -p davinci-zkvm-sdk -p davinci-zkvm-input-gen
cd go-sdk && go test $(go list ./... | grep -v /tests/integration)
```

The Rust SDK tests replay vectors produced by the Go reference code in
`rust-sdk/testdata/`. After changing the Go side, regenerate them:

```bash
cd go-sdk && go run ./cmd/sdk-vectors -out ../rust-sdk/testdata
```

A default run is deterministic and leaves the Groth16 proof fixtures alone;
`-proofs` regenerates those too (it needs the davinci-circom artifacts, see
`-circom`) and changes `wire_prove.json`. CI fails if the committed vectors
differ from a default run.

`go-sdk/solidity` compiles the contracts with a local `solc` or, when none is
installed, with `docker run ethereum/solc:0.8.28`.

## Circuit tests on the emulator

The cheat suites build an honest input, check that the guest accepts it, then
tamper with one value at a time and check that the guest rejects it with the
expected `fail_mask`. They run on `ziskemu` in seconds per case, with no GPU
and no service, and are the fastest check after changing a guest or the input
encoders.

Requirements:

- `ziskemu` on the `PATH` (it ships in `~/.zisk/bin`);
- the input generators: `cargo build --release -p davinci-zkvm-input-gen`
  (found in `target/release`, on the `PATH`, or through `GEN_INPUT_BIN` and
  `GEN_RESULTS_INPUT_BIN`);
- the guest ELFs, by default the committed ones (`CIRCUIT_ELF_PATH` and
  `RESULTS_ELF_PATH` override them).

```bash
cd go-sdk/tests
go test ./integration -run 'TestCheat|TestResultsCheat' -v -timeout 30m
```

A missing generator makes the tests skip rather than fail, so check the
output for `SKIP`. `TestCheat*` covers the vote-batch guest, including the
ballot-slot and CSP cases, and `TestResultsCheat` the results guest.

## Integration tests

These submit real batches to a prover and need one running (`make up`):

```bash
make test                          # full suite against localhost:8080
cd go-sdk/tests && make test-unit  # health and validation checks only, no proving
```

| Test | What it does |
|---|---|
| `TestChainedStateTransitions` | Many consecutive batches on one election, including overwrites, then decrypts and checks the tally. |
| `TestFullE2E` | Fresh votes, overwrites and silent refreshes, each transition settled on a simulated chain with real blob transactions. |
| `TestCSPChainedStateTransitions` | The same with a CSP census. |
| `TestPlonkBenchmark` | Proving time per batch size (see below). |

| Variable | Default | Effect |
|---|---|---|
| `DAVINCI_API_URL` | `http://localhost:8080` | Prover URL. |
| `DAVINCI_PROOF_TIMEOUT` | `5m` | Timeout per proof. Raise it for large batches. |
| `VOTES_PER_BATCH` | `4` | Scales the batch sizes of the e2e and CSP tests. |
| `DAVINCI_INTEGRATION_BATCH_SIZES` | built-in list | Comma-separated batch sizes for `TestChainedStateTransitions`. |
| `BALLOT_NUM_FIELDS` | `6` | Ballot field count of the test elections (1 to 16). |
| `DAVINCI_TEST_ELECTION_SEED` | random | Fixes the election keys, so generated ballots can be cached. |

Ballot proofs are generated on the CPU, about a second each. The benchmarks
cache them under `benchmark/cache/`, so only the first run pays for them.

## Benchmarks

`TestPlonkBenchmark` proves two batches per size on one election; the second
carries as many silent refreshes as votes, which is the steady state:

```bash
cd go-sdk/tests
DAVINCI_PROOF_TIMEOUT=30m BENCH_SIZES=64,128,256 BALLOT_NUM_FIELDS=2 \
  go test ./integration -run TestPlonkBenchmark -v -timeout 120m
```

It fails if the guest rejects a batch, so reported times are always for
accepted batches. `BENCH_PREGEN=1` with `-run TestGenerateBenchBallots` fills
the ballot cache ahead of time.

The chained-mode sweep lives in [`benchmark/`](../benchmark/README.md)
(`make benchmark`). Curated results are in [BENCHMARK.md](../BENCHMARK.md).

## Chained-mode tests

Each is gated by an environment variable and needs a running prover, except
`TestGenChainInputs`, which only needs `ziskemu` and the input generators:

| Variable | Test | What it does |
|---|---|---|
| `CHAIN_ORCH_TEST=1` | `TestChainOrchestrator` | A full election through `chain.Sequencer`: batches, folds, finalize and on-chain verification. |
| `CHAIN_SERVICE_TEST=1` | `TestChainServiceFlow` | The same flow over raw HTTP, checking digest continuity and vk binding. |
| `CHAIN_ATTACK_TEST=1` | `TestChainAttackFoldChain` | Reordered, skipped and replayed batches and a forged `fold_vk` must fail to fold. |
| `CHAIN_BENCH=1` | `TestChainBenchmark` | Per-phase timing of a chained election. |
| `CHAIN_INPUT_DIFF=1` | `TestChainInputDiff` | Compares the service's guest input with a locally built one. |
| `CHAIN_OUT_DIR=<dir>` | `TestGenChainInputs` | Writes batch inputs and a chain config for the `agg-input` tool. |

`CHAIN_BATCHES`, `CHAIN_BATCH_SIZE` and `CHAIN_FOLD_EVERY` size the election;
`BENCH_VOTES`, `BENCH_BATCH_SIZE` and `BENCH_FOLD_EVERY` size the benchmark.
For example:

```bash
cd go-sdk/tests
CHAIN_ORCH_TEST=1 CHAIN_BATCHES=2 CHAIN_BATCH_SIZE=2 CHAIN_FOLD_EVERY=1 \
  go test ./integration -run TestChainOrchestrator -v -timeout 30m
```

## Continuous integration

`.github/workflows/main.yml` runs formatting, lints, unit tests and the
vector check on every pull request. On self-hosted runners it also runs the
cheat suites on `ziskemu` and rebuilds the guests to check that the committed
ELFs match the source. Tests that need a GPU prover are run by hand.
