# Benchmarks

Measured on a single NVIDIA RTX 5090 (59 GB host RAM), ZisK v0.18.0.
Reproduce with `make benchmark` (see `benchmark/README.md`); raw logs and
the auto-generated table land in `benchmark/results/`.

## Chained mode — 1024-vote election, one final PLONK

Ballot inputs (Groth16 proofs, signatures, census proofs) are generated
on voters' devices, so they are pre-generated and cached before the
clock starts. The timed section is the sequencer's critical path: batch
STARK proves, recursive folds, and the finalize step (Chaum-Pedersen
decryption verification + results inclusion + PLONK wrap).

| batch | fold every | folds | stark avg / batch | fold avg | finalize | total | votes/s | on-chain verify |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
|  64 | 4 | 4 | 35.3s | 23.9s | 25.2s | 11m26s | 1.49 | 0.51 s |
| 128 | 4 | 2 | 55.5s | 27.6s | 25.2s |  8m45s | 1.95 | 0.37 s |
| 256 | 2 | 2 | 1m35s | 25.1s | 25.2s |  7m34s | 2.25 | 0.51 s |

- One on-chain verification per **election**, regardless of vote count.
  The final 2.7 KB PLONK attests genesis-state correctness, every batch
  transition (recursive STARK verification), and the decrypted results.
- The first fold includes a one-off bootstrap fold that teaches the
  sequencer the aggregator program_vk (~2x a steady-state fold, ~35s vs
  ~20s); amortized to zero over an election.
- Finalize is a per-election constant (~25s), independent of vote count.
- Batches and folds serialize on the single GPU; fold overhead is ~5–7%
  of total time. A second service instance would pipeline batching and
  folding.
- All rows are on the fully-optimized batch circuit: SMT node-hash skip
  on padding levels, lazy SMT leaf hashing, and projective re-encryption
  equality (fixed-base windowed scalar mul + projective accumulators, no
  per-point inversion). See `circuit/CIRCUIT.md` §15. These lifted
  throughput ~12–25% over the previous sweep (64: 1.33→1.49, 128:
  1.68→1.95, 256: 1.80→2.25 v/s) even with the added process-config
  inclusion-proof verification now in-circuit.
- **256 is the maximum batch size** (`MAX_BATCH_SIZE`): the circuit
  rejects any batch with more than 256 proofs. Pick a batch ≤ 256 and
  fold more often for larger elections.

## Scaling — 5120 votes measured, 20000 projected

Larger elections amortize the per-election finalize constant toward zero
and let folds use a wider fan-in, so throughput rises slightly above the
1024-vote rows. Measured at 5120 votes (batch 256, fold every 4):

| votes | batch | fold every | folds | stark avg / batch | steady fold | finalize | total | votes/s | on-chain verify |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 5120 | 256 | 4 | 5 | 1m42s | 20.0s | 25.1s | 36m25s | 2.34 | 0.50 s |

The batch STARK average is ~8% above the 1024-vote rows (1m42s vs 1m35s):
over a 34-min continuous batch-proving stretch the GPU thermally
throttles, where the short 1024-vote run stayed cool. The steady fold
holds dead flat at 20.0s across all four steady folds; the first fold is
the usual ~35s bootstrap.

**Projected 20000 votes**, best config (batch 250 → 80 batches, fold
every 8 → 10 folds), using the sustained 5120 rates:

| term | basis | time |
|---|---|---|
| batch proving | 20000 × 0.399 s/vote (sustained) | ~7990 s |
| folds | 1 bootstrap (~41s) + 9 steady 9-inner (~26s) | ~275 s |
| finalize | per-election constant | 25 s |
| **total** | | **~2h18m** |
| **throughput** | | **~2.41 votes/s** |

One on-chain verification (~0.5 s) for the whole 20000-vote election. The
projection rests on the sustained (already-throttled) batch rate, so the
real 80-batch run should land close rather than degrade further. Batch
proving is ~96% of the time; fold cadence moves the total by ~1–2%.

## Per-batch mode — one PLONK + one on-chain verification per batch

| batch | PLONK SNARK | votes/s | on-chain verify |
|---:|---:|---:|---:|
|  64 |  34 s | 1.9 | 315 ms |
| 128 |  52 s | 2.4 | 349 ms |
| 256 |  88 s | 2.9 | 349 ms |

SNARK size is 2.7 KB regardless of batch size.

## Comparing the modes

Per-batch mode has higher raw throughput — chained-mode batches do more
work in-circuit (ballot re-encryption into the homomorphic accumulators
replaces the KZG block) — but it costs one Ethereum verification per
batch: 1024 votes at batch 256 is 4 on-chain transactions vs 1.

Chained mode trades ~1.3x prover throughput (at batch 256: 2.9 v/s
per-batch vs 2.25 v/s chained) for a constant on-chain footprint: a
1024-vote election lands on-chain as a single proof, and a 1M-vote
election would too. Past a handful of batches, chained mode is strictly
cheaper on-chain and the only mode that scales to large elections.
