# Chained-mode benchmark

Reproducible sweep for the chained-mode pipeline: proves N votes per
setup through `TestChainBenchmark` (batches STARK-only, recursive folds,
one final PLONK, on-chain verification on a simulated backend), then
writes a markdown report with the per-phase breakdown.

Ballot inputs (Groth16 proofs, signatures, census proofs) are generated
**before the clock starts** — in production they come from voters'
devices — and cached in `benchmark/cache/ballots-<votes>.gob`, so only
the first run pays the ~13 min generation cost; all later runs and all
batch sizes reuse the same votes. Delete the cache file to regenerate.

Needs a running GPU service (`make up` or `make local-run`).

## Run

```bash
make benchmark                  # full sweep against $(API_URL), ~1 h on an RTX 5090
make benchmark-report           # regenerate the report from existing logs

# or directly, with knobs:
DAVINCI_API_URL=http://127.0.0.1:8080 \
BENCH_VOTES=1024 BENCH_SETUPS="64:4 128:4 256:2" \
  ./benchmark/run.sh
```

Each `batch:fold_every` setup runs serially (single GPU) and logs to
`benchmark/results/chain-bench-<batch>x<fold>.log`; the report lands in
`benchmark/results/RESULTS.md`. Curated results are kept in the
top-level `BENCHMARK.md`.

256 is the maximum batch size (`MAX_BATCH_SIZE`); the circuit rejects
anything larger. For bigger elections, keep the batch ≤ 256 and fold
more often.

## Knobs

| Env | Default | Meaning |
|---|---|---|
| `DAVINCI_API_URL` | `http://127.0.0.1:8080` | service URL |
| `BENCH_VOTES` | `1024` | votes per setup (must be a multiple of every batch size) |
| `BENCH_SETUPS` | `64:4 128:4 256:2` | space-separated `batch_size:fold_every` pairs |
| `DAVINCI_PROOF_TIMEOUT` | `60m` | per-job timeout |
| `OUT_DIR` | `benchmark/results` | logs + report directory |
| `BENCH_CACHE_DIR` | `benchmark/cache` | pre-generated ballot cache |

## What is measured

The timed section starts after all ballot inputs exist and covers:

- **batch STARK proves** — `POST /prove` with `"output": "stark"`.
- **folds** — `POST /fold`; the first fold includes the bootstrap fold
  that teaches the sequencer the aggregator vk (~2× a steady-state fold).
- **finalize** — CP decryption-proof verification + results inclusion +
  PLONK wrap; per-election constant.
- **on-chain verify** — final PLONK on `simulated.NewBackend`.
