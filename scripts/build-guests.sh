#!/usr/bin/env bash
# Build the ZisK guests and copy the ELFs into */elf/.
# Usage: scripts/build-guests.sh [circuit|circuit-aggregator|circuit-results ...]
#
# Panic locations embed source paths in the ELF, so the repo root and
# $CARGO_HOME are remapped to fixed prefixes: the bytes (and program vks) do
# not depend on where the tree or the cargo cache live. cargo-zisk appends its
# own flags after ours (RUSTFLAGS or CARGO_ENCODED_RUSTFLAGS), it does not
# replace them. The other half is the in-package circuit-primitives symlink
# in each guest (see its Cargo.toml).
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
cargo_home=${CARGO_HOME:-$HOME/.cargo}

remaps=("--remap-path-prefix=$root=/davinci-zkvm")
# rustc uses the last matching remap: cargo home goes last in case it sits
# inside the checkout.
for p in "$cargo_home" "$(cd "$cargo_home" 2>/dev/null && pwd -P || echo "$cargo_home")"; do
  remaps+=("--remap-path-prefix=$p=/cargo")
done

if [[ -n ${CARGO_ENCODED_RUSTFLAGS:-} ]]; then
  CARGO_ENCODED_RUSTFLAGS+=$(printf '\x1f%s' "${remaps[@]}")
  export CARGO_ENCODED_RUSTFLAGS
else
  # RUSTFLAGS is split on whitespace.
  for r in "${remaps[@]}"; do
    [[ $r != *[[:space:]]* ]] || { echo "path with whitespace: $r" >&2; exit 1; }
  done
  RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }${remaps[*]}"
  export RUSTFLAGS
fi

declare -A bin=(
  [circuit]=davinci-zkvm-circuit:circuit.elf
  [circuit-aggregator]=davinci-zkvm-aggregator:aggregator.elf
  [circuit-results]=davinci-zkvm-results:results.elf
)

guests=("$@")
[[ ${#guests[@]} -gt 0 ]] || guests=(circuit circuit-aggregator circuit-results)

for g in "${guests[@]}"; do
  [[ -n ${bin[$g]:-} ]] || { echo "unknown guest: $g" >&2; exit 1; }
  name=${bin[$g]%%:*}
  elf=${bin[$g]#*:}
  # Must build from the guest dir: the workspace root pulls in host-only deps.
  (cd "$root/$g" && cargo-zisk build --release)
  cp "$root/$g/target/elf/riscv64ima-zisk-zkvm-elf/release/$name" "$root/$g/elf/$elf"
  sha256sum "$root/$g/elf/$elf"
done
