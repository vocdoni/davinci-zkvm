#!/usr/bin/env bash
set -euo pipefail

ZISK_VERSION="${ZISK_VERSION:-0.17.0}"
ZISK_HOME_HOST="${ZISK_HOME_HOST:-$HOME/.zisk}"
IMAGE="${ZISK_KEY_IMAGE:-nvidia/cuda:12.8.0-cudnn-devel-ubuntu24.04}"

mkdir -p "${ZISK_HOME_HOST}"

# Run official ZisK installer inside Docker while persisting ~/.zisk on the host.
# The docs say:
#   ziskup --gpu --provingkey
#   ziskup setup_snark
# For v0.17.0, setup_snark may lag the current bucket object name; if so, fall
# back to the current public PLONK key archive and extract it into ~/.zisk.
docker run --rm --gpus all \
  --ipc=host \
  --ulimit memlock=-1:-1 \
  -e DEBIAN_FRONTEND=noninteractive \
  -e ZISK_VERSION="${ZISK_VERSION}" \
  -v "${ZISK_HOME_HOST}:/root/.zisk" \
  "${IMAGE}" \
  bash -lc '
    set -euo pipefail
    apt-get update
    apt-get install -y --no-install-recommends \
      xz-utils jq curl git build-essential qemu-system libomp-dev libgmp-dev \
      nlohmann-json3-dev protobuf-compiler uuid-dev libgrpc++-dev \
      libsecp256k1-dev libsodium-dev libpqxx-dev nasm libopenmpi-dev \
      openmpi-bin openmpi-common libclang-dev clang gcc-riscv64-unknown-elf \
      ca-certificates tar gzip
    rm -rf /var/lib/apt/lists/*

    curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- \
      -y --default-toolchain stable --profile minimal
    export PATH="$PATH:/root/.cargo/bin:/root/.zisk/bin"

    mkdir -p /root/.zisk/bin
    curl -L --fail -o /root/.zisk/bin/ziskup \
      https://raw.githubusercontent.com/0xPolygonHermez/zisk/main/ziskup/ziskup
    chmod +x /root/.zisk/bin/ziskup
    if ! /root/.zisk/bin/ziskup --version "${ZISK_VERSION}" --gpu --provingkey; then
      echo "ziskup proving-key install failed; falling back to explicit official key extraction"
      cd /tmp
      curl -L --fail -o zisk-provingkey-${ZISK_VERSION}.tar.gz \
        https://storage.googleapis.com/zisk-setup/zisk-provingkey-${ZISK_VERSION}.tar.gz
      curl -L --fail -o zisk-provingkey-${ZISK_VERSION}.tar.gz.md5 \
        https://storage.googleapis.com/zisk-setup/zisk-provingkey-${ZISK_VERSION}.tar.gz.md5
      md5sum -c zisk-provingkey-${ZISK_VERSION}.tar.gz.md5
      rm -rf /root/.zisk/provingKey
      (tar -xzf zisk-provingkey-${ZISK_VERSION}.tar.gz -C /root/.zisk || \
        gzip -dc zisk-provingkey-${ZISK_VERSION}.tar.gz | tar -xf - -C /root/.zisk || true)
      test -d /root/.zisk/provingKey
      cargo-zisk check-setup -a
    fi
    cargo-zisk --version

    # Docs path. If the installer references an unavailable legacy object name,
    # install the current v0.17.0 PLONK key archive from the same official bucket.
    if ! /root/.zisk/bin/ziskup setup_snark; then
      echo "ziskup setup_snark failed; falling back to official proving-key-plonk-${ZISK_VERSION}.tar.gz"
      cd /tmp
      curl -L --fail -o proving-key-plonk-${ZISK_VERSION}.tar.gz \
        https://storage.googleapis.com/zisk-setup/proving-key-plonk-${ZISK_VERSION}.tar.gz
      rm -rf /root/.zisk/provingKeySnark
      tar -xzf proving-key-plonk-${ZISK_VERSION}.tar.gz -C /root/.zisk || \
        (gzip -dc proving-key-plonk-${ZISK_VERSION}.tar.gz | tar -xf - -C /root/.zisk)
    fi

    test -d /root/.zisk/provingKey
    test -d /root/.zisk/provingKeySnark
    du -sh /root/.zisk/provingKey /root/.zisk/provingKeySnark
  '
