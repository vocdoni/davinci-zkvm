#!/usr/bin/env bash
# Parses chain-bench-*.log files produced by run.sh into a markdown
# report (RESULTS.md in the same directory, also echoed to stdout).
set -uo pipefail

OUT_DIR="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/results}"
REPORT="$OUT_DIR/RESULTS.md"

logs=$(ls "$OUT_DIR"/chain-bench-*.log 2>/dev/null | sort -t- -k3 -n)
if [ -z "$logs" ]; then
  echo "no chain-bench-*.log files in $OUT_DIR" >&2
  exit 1
fi

field() { grep -m1 -oP "$2" "$1" 2>/dev/null || echo "-"; }

gpu=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -1 || echo "unknown GPU")

{
  echo "# Chained-mode benchmark results"
  echo
  echo "- date: $(date +%F)"
  echo "- GPU: $gpu (single instance, batches and folds serialized)"
  echo "- driver: TestChainBenchmark — ballot inputs (Groth16 proofs, signatures,"
  echo "  census proofs) are pre-generated and cached before the clock starts;"
  echo "  the timed section covers proving the election once the votes exist."
  echo
  echo "| votes | batch | fold every | folds | stark avg | fold avg | finalize | service total | service v/s | wall total | wall v/s | on-chain verify |"
  echo "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"
  for log in $logs; do
    votes=$(field "$log" 'votes=\K[0-9]+')
    batch=$(field "$log" 'batch_size=\K[0-9]+')
    fold_every=$(field "$log" 'fold_every=\K[0-9]+')
    folds=$(field "$log" 'folds=\K[0-9]+')
    stark_avg=$(field "$log" 'batch STARK proves: total \S+ +avg \K\S+')
    fold_avg=$(field "$log" 'folds: total \S+ +avg \K\S+')
    finalize=$(field "$log" 'finalize \(CP verify \+ PLONK wrap\): \K\S+')
    svc_total=$(field "$log" 'service-side total: \K\S+')
    svc_vps=$(field "$log" 'service-side total: .*\(\K[0-9.]+')
    wall_total=$(field "$log" 'wall total \(incl client side\): \K\S+')
    wall_vps=$(field "$log" 'wall total \(incl client side\): .*\(\K[0-9.]+')
    verify=$(field "$log" 'on-chain verify \(simulated\): \K\S+')
    if ! grep -q '^--- PASS' "$log"; then
      stark_avg="FAILED"
    fi
    echo "| $votes | $batch | $fold_every | $folds | $stark_avg | $fold_avg | $finalize | $svc_total | $svc_vps | $wall_total | $wall_vps | $verify |"
  done
  echo
  echo "Notes:"
  echo
  echo "- service total = batch STARK proves + folds + finalize (the GPU-bound part)."
  echo "- wall total adds client-side sequencer work (state tree updates, HTTP)."
  echo "- ballot generation is excluded: it happens on voters' devices, not in the"
  echo "  sequencer's critical path."
  echo "- the first fold of each run includes the bootstrap fold that teaches the"
  echo "  sequencer the aggregator vk, so it costs roughly twice a steady-state fold."
  echo "- finalize = Chaum-Pedersen verification + dual SMT inclusion + PLONK wrap;"
  echo "  it is a per-election constant, independent of vote count."
} > "$REPORT"

cat "$REPORT"
