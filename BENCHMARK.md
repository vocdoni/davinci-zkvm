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
- **128 is the maximum batch size** (`MAX_BATCH_SIZE`): the circuit
  rejects any batch with more than 128 proofs. Pick a batch ≤ 128 and
  fold more often for larger elections. **Lowered from 256 to 128 for
  GPU-memory safety** (see the per-batch section below): batch 256 at full
  ballot capacity peaks ~31.3 GB even under `--minimal-memory`, leaving no
  headroom on the 32 GB GPU. The chained-mode tables above (and the 5120 /
  20000 rows below) were measured under the previous 256 cap and at the
  8-field era; they are retained as historical references — production now
  caps at 128.

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

Ballot capacity is 16 fields; the guest skips per-field EC work on padded
slots, so PLONK time scales with the election's declared `num_fields`, not
the 16-field max (sweep with `BALLOT_NUM_FIELDS`):

| batch | PLONK (num_fields=2) | PLONK (num_fields=16) | on-chain verify |
|---:|---:|---:|---:|
|  64 |  38 s |    83 s | ~0.3–0.5 s |
| 128 |  73 s |   164 s | ~0.5 s |
| ~~256~~ | 102 s | 289 s (min-mem) | ~0.3 s |

128 is the `MAX_BATCH_SIZE` cap; the 256 row is retained as the corner that
motivated it. `proofBytes` is 768 B / `publicValues` 256 B regardless of
batch or field count.

**Why the cap is 128.** At num_fields=16 the per-field chained reencryption
makes the `ArithEq` trace large enough that batch 256 overflows the 32 GB GPU
under the default schedule (deterministic SIGKILL during inner-proof
generation). `cargo-zisk prove --minimal-memory` reschedules witness storage
and holds the footprint at a ~31.3 GB peak, proving+verifying in ~289 s — but
that is within ~0.7 GB of the ceiling with no softer knob left, so any future
circuit growth would push batch 256 over with no recovery path. We capped
`MAX_BATCH_SIZE` at 128, which proves comfortably. `--minimal-memory` stays
wired as a backstop (auto-escalated on retry; force from the first attempt
with `ZISK_MINIMAL_MEMORY=1`): it only reschedules witness storage — it
doesn't change the circuit, constraints, or the proven statement, so the
result still verifies and soundness is unaffected. The speed cost is small: a
matched A/B on one batch-128 num_fields=16 input measured 138.4 s plain vs
142.1 s with `--minimal-memory` (+2.7%); on a lighter input it was +0.7%.

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
