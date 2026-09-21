#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ZISK_VERSION here is the bare version ("1.3.0-alpha"); the ziskup CLI
# adds the leading 'v' itself. ZISK_TAG is the upstream git tag with 'v'.
ZISK_VERSION="${ZISK_VERSION:-1.3.0-alpha}"
ZISK_TAG="${ZISK_TAG:-v${ZISK_VERSION}}"
ZISK_HOME="${ZISK_HOME:-$HOME/.zisk}"
ZISK_BIN_DIR="${ZISK_BIN_DIR:-$ZISK_HOME/bin}"
# ziskup lays the keys out under ZISK_HOME; override ZISK_HOME, not these.
PROVING_KEY_PATH="$ZISK_HOME/provingKey"
PROVING_KEY_PLONK_PATH="$ZISK_HOME/provingKeySnark"
PROOF_OUTPUT_DIR="${PROOF_OUTPUT_DIR:-$REPO_ROOT/proof_output}"
LISTEN_HOST="${LISTEN_HOST:-127.0.0.1}"
LISTEN_PORT="${LISTEN_PORT:-8080}"
LISTEN_ADDR="${LISTEN_ADDR:-$LISTEN_HOST:$LISTEN_PORT}"
DAVINCI_API_URL="${DAVINCI_API_URL:-http://127.0.0.1:$LISTEN_PORT}"
INSTALL_SYSTEM_DEPS="${INSTALL_SYSTEM_DEPS:-auto}"
ADD_TO_SHELL_RC="${ADD_TO_SHELL_RC:-1}"
# RUN_SETUP: run ziskup (installs cargo-zisk + guest toolchain + STARK key).
# RUN_SETUP_TREES: build the GPU setup artifacts (ziskup already builds the
# STARK constant trees; only needed on GPU hosts).
RUN_SETUP="${RUN_SETUP:-1}"
RUN_SETUP_TREES="${RUN_SETUP_TREES:-1}"
PROVER_MODE="${PROVER_MODE:-auto}"
SELECTED_PROVER_MODE=""

log() {
  echo "[install] $*"
}

warn() {
  echo "[install][warn] $*" >&2
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[install][error] Missing required command: $1" >&2
    exit 1
  fi
}

install_system_deps() {
  local want_install=0
  case "$INSTALL_SYSTEM_DEPS" in
    1|true|yes) want_install=1 ;;
    0|false|no) want_install=0 ;;
    auto)
      if command -v apt-get >/dev/null 2>&1; then
        want_install=1
      fi
      ;;
    *)
      warn "Invalid INSTALL_SYSTEM_DEPS=$INSTALL_SYSTEM_DEPS (use auto|0|1). Skipping apt install."
      ;;
  esac

  if [[ "$want_install" -ne 1 ]]; then
    log "Skipping apt dependencies (INSTALL_SYSTEM_DEPS=$INSTALL_SYSTEM_DEPS)."
    return 0
  fi

  if ! command -v apt-get >/dev/null 2>&1; then
    warn "apt-get not available; skipping system packages."
    return 0
  fi

  local apt_prefix=""
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
      apt_prefix="sudo"
    else
      warn "Not root and sudo unavailable; cannot install apt packages."
      return 0
    fi
  fi

  # Prebuilt cargo-zisk-gpu is statically linked against the CUDA runtime,
  # so no CUDA toolkit / nasm / cmake / protobuf / libclang here — just what
  # the service crate needs to build and what the prover needs at runtime.
  log "Installing Ubuntu packages required by the prover and the service build..."
  ${apt_prefix} apt-get update
  ${apt_prefix} apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    build-essential \
    pkg-config \
    libssl-dev \
    libopenmpi-dev \
    openmpi-bin \
    libgomp1 \
    libsodium-dev \
    nodejs \
    npm
}

# `cargo-zisk prove --plonk --verify-proof` shells out to `snarkjs plonk verify`.
install_snarkjs() {
  if command -v snarkjs >/dev/null 2>&1; then
    return 0
  fi
  need_cmd npm
  local sudo_prefix=""
  if [[ "${EUID:-$(id -u)}" -ne 0 ]] && command -v sudo >/dev/null 2>&1; then
    sudo_prefix="sudo"
  fi
  log "Installing snarkjs (used by the prover's own PLONK verification)"
  ${sudo_prefix} npm install -g snarkjs@0.7.6
}

ensure_path() {
  mkdir -p "$ZISK_BIN_DIR"
  export PATH="$ZISK_BIN_DIR:$PATH"
}

detect_prover_mode() {
  case "$PROVER_MODE" in
    gpu|cpu)
      SELECTED_PROVER_MODE="$PROVER_MODE"
      ;;
    auto)
      if command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi -L >/dev/null 2>&1; then
        SELECTED_PROVER_MODE="gpu"
      else
        SELECTED_PROVER_MODE="cpu"
      fi
      ;;
    *)
      warn "Invalid PROVER_MODE=$PROVER_MODE (use auto|gpu|cpu). Falling back to auto."
      PROVER_MODE="auto"
      detect_prover_mode
      return
      ;;
  esac

  log "Selected prover mode: $SELECTED_PROVER_MODE (requested: $PROVER_MODE)"
}

run_ziskup() {
  if [[ "$RUN_SETUP" != "1" ]]; then
    log "Skipping ziskup (RUN_SETUP=$RUN_SETUP)"
    return 0
  fi

  # ziskup installs everything in user mode into $ZISK_DIR (defaults to
  # ~/.zisk): the cargo-zisk binaries, the ZisK guest Rust toolchain
  # (linked as rustup toolchain 'zisk'), the STARK proving key, and it
  # builds the STARK constant trees itself.
  local mode_flag="--cpu"
  if [[ "$SELECTED_PROVER_MODE" == "gpu" ]]; then
    mode_flag="--gpu"
  fi

  local ziskup_url="https://raw.githubusercontent.com/0xPolygonHermez/zisk/${ZISK_TAG}/ziskup/ziskup"
  local tmp_ziskup
  tmp_ziskup="$(mktemp -t ziskup.XXXXXX)"
  log "Downloading ziskup for ${ZISK_TAG} from ${ziskup_url}"
  curl -fL "$ziskup_url" -o "$tmp_ziskup"
  chmod +x "$tmp_ziskup"

  log "Running ziskup -v ${ZISK_VERSION} ${mode_flag} --provingkey -y"
  ZISK_DIR="$ZISK_HOME" "$tmp_ziskup" -v "$ZISK_VERSION" "$mode_flag" --provingkey -y

  # In user mode ziskup will not accept --with-snark; the PLONK key ships
  # via a separate subcommand.
  log "Running ziskup setup_snark (installs the PLONK proving key)"
  ZISK_DIR="$ZISK_HOME" "$tmp_ziskup" setup_snark

  rm -f "$tmp_ziskup"

  "$ZISK_BIN_DIR/cargo-zisk" --version
}

build_davinci_bins() {
  log "Building davinci service + input generator"
  (cd "$REPO_ROOT" && cargo build --release -p davinci-zkvm-service -p davinci-zkvm-input-gen)

  if [[ -f "$REPO_ROOT/target/release/davinci-zkvm" ]]; then
    cp "$REPO_ROOT/target/release/davinci-zkvm" "$ZISK_BIN_DIR/davinci-zkvm"
  fi
  if [[ -f "$REPO_ROOT/target/release/gen-input" ]]; then
    cp "$REPO_ROOT/target/release/gen-input" "$ZISK_BIN_DIR/gen-input"
  fi
}

# ZisK ships a Circom-generated final.so that requests an executable stack.
# Modern Linux refuses to grant it at dlopen time, so drop the X bit in the
# PT_GNU_STACK program header. Idempotent — safe to re-run.
patch_final_so() {
  local final_so="$PROVING_KEY_PLONK_PATH/final/final.so"
  if [[ ! -f "$final_so" ]]; then
    return 0
  fi
  if ! readelf -lW "$final_so" 2>/dev/null | grep -q "GNU_STACK.* RWE"; then
    return 0
  fi
  log "Patching $final_so to drop executable stack flag"
  python3 - "$final_so" <<'PYEOF'
import struct, sys
path = sys.argv[1]
with open(path, "r+b") as f:
    data = f.read()
    e_phoff = struct.unpack("<Q", data[32:40])[0]
    e_phentsize = struct.unpack("<H", data[54:56])[0]
    e_phnum = struct.unpack("<H", data[56:58])[0]
    PT_GNU_STACK = 0x6474e551
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack("<II", data[off:off+8])
        if p_type == PT_GNU_STACK:
            f.seek(off + 4)
            f.write(struct.pack("<I", p_flags & ~0x1))
            break
PYEOF
}

# ziskup builds the constant trees; check-setup -g adds the GPU const layouts
# (*.const_gpu) and the recursivef (PLONK) trees. The prover would generate
# them lazily on the first job, this just moves the cost here. GPU mode only.
setup_gpu_artifacts() {
  if [[ "$RUN_SETUP_TREES" != "1" ]]; then
    log "Skipping GPU setup artifacts (RUN_SETUP_TREES=$RUN_SETUP_TREES)"
    return 0
  fi
  if [[ "$SELECTED_PROVER_MODE" != "gpu" ]]; then
    return 0
  fi
  if [[ ! -d "$PROVING_KEY_PATH" ]]; then
    warn "Proving key path not found ($PROVING_KEY_PATH). Skipping check-setup."
    return 0
  fi
  if [[ ! -d "$PROVING_KEY_PLONK_PATH" ]]; then
    warn "PLONK proving key path not found ($PROVING_KEY_PLONK_PATH). Skipping check-setup."
    return 0
  fi

  local sentinel="$PROVING_KEY_PLONK_PATH/recursivef/recursivef.consttree_gpu"
  if [[ -f "$sentinel" ]]; then
    log "GPU setup artifacts already present (skip check-setup)"
    return 0
  fi

  log "Building GPU setup artifacts (about a minute)"
  # check-setup moved from cargo-zisk to cargo-zisk-dev in 1.3.
  # -s builds the PLONK/recursivef trees, -g selects the GPU variant.
  "$ZISK_BIN_DIR/cargo-zisk-dev" check-setup \
    -k "$PROVING_KEY_PATH" \
    -w "$PROVING_KEY_PLONK_PATH" \
    -s -g
}

write_env_file() {
  local env_file="$REPO_ROOT/.env.local.nodocker"
  cat > "$env_file" <<ENVEOF
export PATH="$ZISK_BIN_DIR:\$PATH"
export PROVING_KEY_PATH="$PROVING_KEY_PATH"
export PROVING_KEY_PLONK_PATH="$PROVING_KEY_PLONK_PATH"
export CIRCUIT_ELF_PATH="$REPO_ROOT/circuit/elf/circuit.elf"
export AGGREGATOR_ELF_PATH="$REPO_ROOT/circuit-aggregator/elf/aggregator.elf"
export CARGO_ZISK_BIN="$ZISK_BIN_DIR/cargo-zisk"
export PROOF_OUTPUT_DIR="$PROOF_OUTPUT_DIR"
export LISTEN_ADDR="$LISTEN_ADDR"
export DAVINCI_PROVER_MODE="$SELECTED_PROVER_MODE"
# ZisK MPI concurrency knobs (increase carefully; memory grows roughly per process)
export ZISK_MPI_PROCS=1
export ZISK_MPI_THREADS=0
export ZISK_MPI_BIND_TO="none"
export LD_LIBRARY_PATH="$ZISK_BIN_DIR:/usr/local/lib:\${LD_LIBRARY_PATH:-}"
export OMPI_MCA_btl="vader,self"
export OMPI_MCA_pml="ob1"
export OMPI_MCA_opal_cuda_support=0
export OMPI_MCA_btl_smcuda_use_cuda_ipc=0
export OMPI_ALLOW_RUN_AS_ROOT=1
export OMPI_ALLOW_RUN_AS_ROOT_CONFIRM=1
export DAVINCI_API_URL="$DAVINCI_API_URL"
ENVEOF
  log "Wrote runtime env file: $env_file"
}

update_shell_rc() {
  if [[ "$ADD_TO_SHELL_RC" != "1" ]]; then
    log "Skipping shell profile updates (ADD_TO_SHELL_RC=$ADD_TO_SHELL_RC)"
    return 0
  fi

  local rc_file="$HOME/.bashrc"
  local marker="# davinci-zkvm local (non-docker)"
  if ! grep -qF "$marker" "$rc_file" 2>/dev/null; then
    cat >> "$rc_file" <<RCEOF

$marker
if [ -f "$REPO_ROOT/.env.local.nodocker" ]; then
  . "$REPO_ROOT/.env.local.nodocker"
fi
RCEOF
    log "Appended environment loader to $rc_file"
  else
    log "$rc_file already contains davinci-zkvm env block"
  fi
}

main() {
  log "Starting davinci-zkvm non-Docker install"

  need_cmd rustc
  need_cmd cargo
  need_cmd go
  need_cmd git
  need_cmd make
  need_cmd curl

  install_system_deps
  install_snarkjs
  ensure_path
  detect_prover_mode
  run_ziskup
  patch_final_so
  setup_gpu_artifacts
  build_davinci_bins
  mkdir -p "$PROOF_OUTPUT_DIR"
  write_env_file
  update_shell_rc

  log "Install complete."
  cat <<EOF2

Next steps (current shell):
  source "$REPO_ROOT/.env.local.nodocker"
  "$REPO_ROOT/target/release/davinci-zkvm"

In another terminal:
  cd "$REPO_ROOT/go-sdk/tests"
  make test

EOF2
}

main "$@"
