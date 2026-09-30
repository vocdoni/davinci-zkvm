# Chained-mode benchmark

Reproducible sweep of the chained-mode pipeline. For each setup it proves a
fixed number of votes through `TestChainBenchmark`: batch STARKs, recursive
folds, one final PLONK and its verification on a simulated chain. It then
writes a report with the time spent in each phase.

It needs a running prover (`make up` or `make local-run`).

## Run

```bash
make benchmark          # full sweep against the local prover
make benchmark-report   # rebuild the report from existing logs

# or directly:
DAVINCI_API_URL=http://127.0.0.1:8080 \
BENCH_VOTES=1024 BENCH_SETUPS="64:4 128:4 256:2" \
  ./benchmark/run.sh
```

Setups run one after another. Each writes
`benchmark/results/chain-bench-<batch>x<fold>.log`, and the report goes to
`benchmark/results/RESULTS.md`. Curated results are kept in
[BENCHMARK.md](../BENCHMARK.md).

Ballot inputs (Groth16 proofs, signatures, census proofs) are generated
before the clock starts, since voters produce them on their own devices. They
are cached in `benchmark/cache/ballots-<votes>.gob`, so only the first run
pays for them and every batch size reuses the same votes. Delete the file to
regenerate.

Batches hold at most 1024 ballots (`MAX_BATCH_SIZE`).

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `DAVINCI_API_URL` | `http://127.0.0.1:8080` | Prover URL. |
| `BENCH_VOTES` | `1024` | Votes per setup; must be a multiple of every batch size. |
| `BENCH_SETUPS` | `64:4 128:4 256:2` | Space-separated `batch_size:fold_every` pairs. |
| `DAVINCI_PROOF_TIMEOUT` | `60m` | Timeout per job. |
| `OUT_DIR` | `benchmark/results` | Logs and report. |
| `BENCH_CACHE_DIR` | `benchmark/cache` | Ballot cache. |

## What is measured

The clock starts once all ballot inputs exist and covers:

- **batch proofs**: `POST /prove` with `"output": "stark"`;
- **folds**: `POST /fold`, including the one-off bootstrap fold that learns
  the aggregator vk (about twice a regular fold);
- **finalize**: decryption-proof checks, results inclusion and the PLONK
  wrap, a constant per election;
- **on-chain verification** of the final PLONK on a simulated chain.
