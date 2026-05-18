#!/usr/bin/env bash
# Run inside the key-installer container. Uses the official ziskup script
# to download both ZisK proving keys into ${ZISK_DIR} (bind-mounted from
# the host) and patches the PLONK final.so to drop its executable-stack
# flag so modern Linux will load it at prove time.
set -euo pipefail

ZISK_VERSION="${ZISK_VERSION:-0.18.0}"
ZISK_DIR="${ZISK_DIR:-/zisk}"

export HOME="${HOME:-/root}"

mkdir -p "${ZISK_DIR}"

log() { echo "[install-keys] $*"; }

# Run ziskup in --system mode so it skips the Rust toolchain install
# (we only want the proving keys, not a build environment). --owner
# root:root avoids creating a new system user inside this throwaway
# container — root already exists and runs the container. --with-snark
# pulls both the STARK and PLONK keys in one invocation.
#
# Idempotent: ziskup bails early if the requested version is already
# present at the prefix unless --force is passed.
if [ ! -d "${ZISK_DIR}/provingKey" ] || [ ! -d "${ZISK_DIR}/provingKeySnark" ]; then
    log "Running ziskup -v ${ZISK_VERSION} --system --provingkey --with-snark --cpu..."
    ziskup -v "${ZISK_VERSION}" \
        --system \
        --prefix "${ZISK_DIR}" \
        --owner root:root \
        --provingkey \
        --with-snark \
        --cpu \
        --yes
else
    log "Both proving keys already present at ${ZISK_DIR} (skipping ziskup)"
fi

# Drop the executable-stack flag on final.so. ZisK ships a Circom-generated
# shared object that requests RWE on its GNU_STACK segment; modern Linux
# refuses to grant it at dlopen time. Flip the X bit off in the
# PT_GNU_STACK program header. Idempotent.
FINAL_SO="${ZISK_DIR}/provingKeySnark/final/final.so"
if [ -f "${FINAL_SO}" ] && readelf -lW "${FINAL_SO}" 2>/dev/null | grep -q "GNU_STACK.* RWE"; then
    log "Patching ${FINAL_SO} to drop executable-stack flag..."
    python3 - "${FINAL_SO}" <<'PYEOF'
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
else
    log "final.so already patched (or not yet present)"
fi

# If the caller passed HOST_UID/HOST_GID (the host user that invoked
# `make keys`), chown the install tree to them so the host can read,
# inspect, and delete the keys without sudo. Inside the runtime
# container the cuda image still reads them fine — bind mounts don't
# care about UID alignment when the inner process runs as root.
if [ -n "${HOST_UID:-}" ] && [ -n "${HOST_GID:-}" ]; then
    log "Chowning ${ZISK_DIR} to ${HOST_UID}:${HOST_GID}..."
    chown -R "${HOST_UID}:${HOST_GID}" "${ZISK_DIR}"
fi

log "Done. Keys installed under ${ZISK_DIR}:"
log "  STARK: ${ZISK_DIR}/provingKey"
log "  PLONK: ${ZISK_DIR}/provingKeySnark"
