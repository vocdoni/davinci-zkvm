#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

ZISK_VERSION="${ZISK_VERSION:-v0.18.0}"
ZISK_REPO="${ZISK_REPO:-https://github.com/0xPolygonHermez/zisk.git}"
ZISK_SRC="${ZISK_SRC:-$HOME/zisk}"
ZISK_HOME="${ZISK_HOME:-$HOME/.zisk}"
ZISK_BIN_DIR="${ZISK_BIN_DIR:-$ZISK_HOME/bin}"
CUDA_BIN="${CUDA_BIN:-/usr/local/cuda-12.8/bin}"
PROVING_KEY_PATH="${PROVING_KEY_PATH:-$ZISK_HOME/provingKey}"
PROOF_OUTPUT_DIR="${PROOF_OUTPUT_DIR:-$REPO_ROOT/proof_output}"
LISTEN_HOST="${LISTEN_HOST:-127.0.0.1}"
LISTEN_PORT="${LISTEN_PORT:-8080}"
LISTEN_ADDR="${LISTEN_ADDR:-$LISTEN_HOST:$LISTEN_PORT}"
DAVINCI_API_URL="${DAVINCI_API_URL:-http://127.0.0.1:$LISTEN_PORT}"
INSTALL_SYSTEM_DEPS="${INSTALL_SYSTEM_DEPS:-auto}"
ADD_TO_SHELL_RC="${ADD_TO_SHELL_RC:-1}"
RUN_SETUP="${RUN_SETUP:-1}"
RUN_SETUP_TREES="${RUN_SETUP_TREES:-1}"
FORCE_SETUP_DOWNLOAD="${FORCE_SETUP_DOWNLOAD:-0}"
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

  log "Installing Ubuntu packages required by Dockerfile.cuda and local GPU proving..."
  ${apt_prefix} apt-get update
  ${apt_prefix} apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    build-essential \
    pkg-config \
    libssl-dev \
    cmake \
    libgmp-dev \
    nlohmann-json3-dev \
    libsodium-dev \
    libopenmpi-dev \
    libomp-dev \
    nasm \
    libclang-dev \
    clang \
    protobuf-compiler \
    libprotobuf-dev \
    openmpi-bin \
    openmpi-common \
    libgomp1
}

ensure_path() {
  mkdir -p "$ZISK_BIN_DIR"
  export PATH="$ZISK_BIN_DIR:$PATH"
}

download_zisk_prebuilt() {
  local arch="amd64"
  local platform="linux"
  local tarball="cargo_zisk_${platform}_${arch}.tar.gz"
  local url="https://github.com/0xPolygonHermez/zisk/releases/download/${ZISK_VERSION}/${tarball}"
  local tmp_tar="/tmp/${tarball}"

  log "Downloading ZisK ${ZISK_VERSION} prebuilt binaries from ${url}"
  curl -fL "${url}" -o "${tmp_tar}"

  log "Extracting ZisK binaries to ${ZISK_HOME}"
  rm -rf "${ZISK_HOME}/bin" "${ZISK_HOME}/zisk"
  mkdir -p "${ZISK_HOME}"
  tar --ignore-zeros -xzf "${tmp_tar}" -C "${ZISK_HOME}"
  rm -f "${tmp_tar}"

  # v0.18.0+ ships cargo-zisk-gpu and cargo-zisk-cpu; create cargo-zisk symlink.
  if [[ "$SELECTED_PROVER_MODE" == "gpu" ]] && [[ -f "${ZISK_BIN_DIR}/cargo-zisk-gpu" ]]; then
    ln -sf "${ZISK_BIN_DIR}/cargo-zisk-gpu" "${ZISK_BIN_DIR}/cargo-zisk"
    log "Symlinked cargo-zisk -> cargo-zisk-gpu"
  elif [[ -f "${ZISK_BIN_DIR}/cargo-zisk-cpu" ]]; then
    ln -sf "${ZISK_BIN_DIR}/cargo-zisk-cpu" "${ZISK_BIN_DIR}/cargo-zisk"
    log "Symlinked cargo-zisk -> cargo-zisk-cpu"
  fi

  log "Installed ZisK ${ZISK_VERSION} artifacts in ${ZISK_BIN_DIR}"
  "${ZISK_BIN_DIR}/cargo-zisk" --version
}

detect_prover_mode() {
  case "$PROVER_MODE" in
    gpu|cpu)
      SELECTED_PROVER_MODE="$PROVER_MODE"
      ;;
    auto)
      if [[ -d "$CUDA_BIN" ]] && command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi -L >/dev/null 2>&1; then
        SELECTED_PROVER_MODE="gpu"
      elif command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi -L >/dev/null 2>&1 && command -v nvcc >/dev/null 2>&1; then
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

install_zisk_toolchain() {
  log "Installing ZisK Rust toolchain via cargo-zisk toolchain install"
  "$ZISK_BIN_DIR/cargo-zisk" toolchain install
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

SETUP_BUCKET="${SETUP_BUCKET:-https://storage.googleapis.com/zisk-setup}"

setup_proving_key() {
  local need_download=0
  if [[ ! -d "$PROVING_KEY_PATH" ]]; then
    need_download=1
  fi
  if [[ "$FORCE_SETUP_DOWNLOAD" == "1" ]]; then
    need_download=1
  fi

  if [[ "$RUN_SETUP" != "1" ]]; then
    log "Skipping proving key download (RUN_SETUP=$RUN_SETUP)"
    return 0
  fi

  if [[ "$need_download" -ne 1 ]]; then
    log "Proving key already present at $PROVING_KEY_PATH (skip download)"
    return 0
  fi

  local zisk_ver
  zisk_ver="$("$ZISK_BIN_DIR/cargo-zisk" --version | awk '{print $2}')"
  local major minor patch
  IFS='.' read -r major minor patch <<< "$zisk_ver"
  local setup_ver="${major}.${minor}.0"
  local key_file="zisk-provingkey-${setup_ver}.tar.gz"

  log "Downloading proving key ${key_file} from ${SETUP_BUCKET}"
  curl -L "${SETUP_BUCKET}/${key_file}" -o "/tmp/${key_file}"
  curl -L "${SETUP_BUCKET}/${key_file}.md5" -o "/tmp/${key_file}.md5"
  (cd /tmp && md5sum -c "${key_file}.md5")

  log "Installing proving key to $(dirname "$PROVING_KEY_PATH")"
  local zisk_home
  zisk_home="$(dirname "$PROVING_KEY_PATH")"
  rm -rf "$PROVING_KEY_PATH" "$zisk_home/verifyKey" "$zisk_home/cache"
  tar --ignore-zeros -xzf "/tmp/${key_file}" -C "$zisk_home"
  rm -f "/tmp/${key_file}" "/tmp/${key_file}.md5"
  log "Proving key installed."
}

setup_plonk_key() {
  local plonk_path="${PROVING_KEY_PLONK_PATH:-$(dirname "$PROVING_KEY_PATH")/provingKeySnark}"
  local need_download=0
  if [[ ! -d "$plonk_path" ]]; then
    need_download=1
  fi
  if [[ "$FORCE_SETUP_DOWNLOAD" == "1" ]]; then
    need_download=1
  fi

  if [[ "$RUN_SETUP" != "1" ]]; then
    log "Skipping PLONK proving key download (RUN_SETUP=$RUN_SETUP)"
    return 0
  fi

  if [[ "$need_download" -ne 1 ]]; then
    log "PLONK proving key already present at $plonk_path (skip download)"
    return 0
  fi

  local zisk_ver
  zisk_ver="$("$ZISK_BIN_DIR/cargo-zisk" --version | awk '{print $2}')"
  local major minor patch
  IFS='.' read -r major minor patch <<< "$zisk_ver"
  local setup_ver="${major}.${minor}.0"
  local key_file="zisk-provingkey-plonk-${setup_ver}.tar.gz"

  log "Downloading PLONK proving key ${key_file} (~22 GB) from ${SETUP_BUCKET}"
  curl -L "${SETUP_BUCKET}/${key_file}" -o "/tmp/${key_file}"
  curl -L "${SETUP_BUCKET}/${key_file}.md5" -o "/tmp/${key_file}.md5"
  (cd /tmp && md5sum -c "${key_file}.md5")

  log "Installing PLONK proving key to $(dirname "$plonk_path")"
  rm -rf "$plonk_path"
  tar --ignore-zeros -xzf "/tmp/${key_file}" -C "$(dirname "$plonk_path")"
  rm -f "/tmp/${key_file}" "/tmp/${key_file}.md5"
  log "PLONK proving key installed."

  # ZisK ships a Circom-generated final.so that requests an executable stack.
  # Modern Linux refuses to grant it at dlopen time, so flip the X bit off in
  # the PT_GNU_STACK program header (idempotent — safe to re-run).
  local final_so="$plonk_path/final/final.so"
  if [[ -f "$final_so" ]] && readelf -lW "$final_so" 2>/dev/null | grep -q "GNU_STACK.* RWE"; then
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
  fi
}

setup_const_trees() {
  if [[ "$RUN_SETUP_TREES" != "1" ]]; then
    log "Skipping constant tree build (RUN_SETUP_TREES=$RUN_SETUP_TREES)"
    return 0
  fi

  if [[ ! -d "$PROVING_KEY_PATH" ]]; then
    warn "Proving key path not found ($PROVING_KEY_PATH). Skipping check-setup."
    return 0
  fi

  local plonk_path="${PROVING_KEY_PLONK_PATH:-$(dirname "$PROVING_KEY_PATH")/provingKeySnark}"

  log "Building constant trees (this can take a long time)"
  if [[ "$SELECTED_PROVER_MODE" == "gpu" ]]; then
    "$ZISK_BIN_DIR/cargo-zisk" check-setup \
      --proving-key "$PROVING_KEY_PATH" \
      --proving-key-plonk "$plonk_path" \
      --plonk --gpu
  else
    "$ZISK_BIN_DIR/cargo-zisk" check-setup \
      --proving-key "$PROVING_KEY_PATH" \
      --proving-key-plonk "$plonk_path" \
      --plonk
  fi
}

write_env_file() {
  local env_file="$REPO_ROOT/.env.local.nodocker"
  local plonk_path="${PROVING_KEY_PLONK_PATH:-$(dirname "$PROVING_KEY_PATH")/provingKeySnark}"
  cat > "$env_file" <<ENVEOF
export PATH="$ZISK_BIN_DIR:\$PATH"
export PROVING_KEY_PATH="$PROVING_KEY_PATH"
export PROVING_KEY_PLONK_PATH="$plonk_path"
export CIRCUIT_ELF_PATH="$REPO_ROOT/circuit/elf/circuit.elf"
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
  ensure_path
  detect_prover_mode
  download_zisk_prebuilt
  install_zisk_toolchain
  build_davinci_bins
  setup_proving_key
  setup_plonk_key
  setup_const_trees
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
