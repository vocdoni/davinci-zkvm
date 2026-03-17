#!/bin/sh
set -eu

SETUP_BUCKET="${SETUP_BUCKET:-https://storage.googleapis.com/zisk-setup}"
REQUIRED_SETUP="${PROVING_KEY_PATH}/zisk/vadcop_final_compressed/vadcop_final_compressed.starkinfo.json"
SETUP_SENTINEL="${PROVING_KEY_PATH}/.setup-complete"

log() {
  echo "[entrypoint] $*"
}

warn() {
  echo "[entrypoint][warn] $*" >&2
}

download_proving_key() {
  zisk_ver="$(cargo-zisk --version | awk '{print $2}')"
  major="$(echo "$zisk_ver" | cut -d. -f1)"
  minor="$(echo "$zisk_ver" | cut -d. -f2)"
  setup_ver="${major}.${minor}.0"
  key_file="zisk-provingkey-${setup_ver}.tar.gz"
  tmp_root="$(mktemp -d)"

  log "Downloading proving key ${key_file} from ${SETUP_BUCKET}"
  curl -L "${SETUP_BUCKET}/${key_file}" -o "/tmp/${key_file}"
  curl -L "${SETUP_BUCKET}/${key_file}.md5" -o "/tmp/${key_file}.md5"
  (cd /tmp && md5sum -c "${key_file}.md5")

  mkdir -p "$PROVING_KEY_PATH"
  find "$PROVING_KEY_PATH" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
  tar --overwrite -xf "/tmp/${key_file}" -C "$tmp_root"
  if [ ! -d "$tmp_root/provingKey" ]; then
    echo "[entrypoint][error] Downloaded proving key archive does not contain provingKey/ root" >&2
    rm -rf "$tmp_root"
    exit 1
  fi
  cp -a "$tmp_root/provingKey/." "$PROVING_KEY_PATH/"
  rm -rf "$tmp_root"
  rm -f "/tmp/${key_file}" "/tmp/${key_file}.md5"
}

ensure_proving_key() {
  if [ ! -f "$REQUIRED_SETUP" ]; then
    warn "Compatible proving key not found at $PROVING_KEY_PATH; bootstrapping it now."
    download_proving_key
  fi
  if [ ! -f "$REQUIRED_SETUP" ]; then
    echo "[entrypoint][error] Missing required setup file: $REQUIRED_SETUP" >&2
    exit 1
  fi
}

ensure_const_trees() {
  if [ ! -f "$SETUP_SENTINEL" ]; then
    log "Running cargo-zisk check-setup -a (first boot or proving key changed)"
    cargo-zisk check-setup --proving-key "$PROVING_KEY_PATH" -a
    touch "$SETUP_SENTINEL"
    log "check-setup complete"
  fi
}

gpu_warmup() {
  log "GPU warmup: initializing CUDA context"
  cargo-zisk check-setup --proving-key "$PROVING_KEY_PATH" >/dev/null 2>&1 || true
}

ensure_proving_key
ensure_const_trees
gpu_warmup

exec /app/davinci-zkvm
