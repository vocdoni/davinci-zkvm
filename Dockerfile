# ── Stage 1: Build cargo-zisk from source (CPU only, no CUDA) ─────────────────
# Uses Ubuntu 24.04 — same base as the CUDA image, avoids Debian/glibc mismatches.
FROM ubuntu:24.04 AS zisk-builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    build-essential \
    pkg-config \
    libssl-dev \
    ca-certificates \
    cmake \
    libgmp-dev \
    nlohmann-json3-dev \
    libsodium-dev \
    libopenmpi-dev \
    nasm \
    libclang-dev \
    clang \
    protobuf-compiler \
    libprotobuf-dev \
    libomp-dev \
    gcc-riscv64-unknown-elf \
    binutils-riscv64-unknown-elf \
    && rm -rf /var/lib/apt/lists/*

# Install Rust toolchain
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- \
    -y --default-toolchain stable --profile minimal
ENV PATH="/root/.cargo/bin:$PATH"

ARG ZISK_VERSION=v0.15.0

# Clone ZisK source at the pinned version
RUN git clone --depth 1 --branch ${ZISK_VERSION} \
    https://github.com/0xPolygonHermez/zisk.git /src/zisk

WORKDIR /src/zisk

# Build cargo-zisk with packed SIMD arithmetic (CPU only — no GPU feature)
# The 'packed' feature enables AVX-optimized polynomial arithmetic needed for
# correct STARK proof generation. It's included in 'gpu' but works CPU-only too.
RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    cargo build --release --features packed 2>&1 | tee /tmp/build.log

# Bundle ALL shared lib dependencies so the runtime needs no extra apt packages.
# Also bundle libgomp.so.1 explicitly — ZisK dlopen()s it at runtime via libloading
# (won't appear in ldd output since it's loaded dynamically, not via NEEDED entries).
RUN mkdir -p /libs && \
    for bin in target/release/cargo-zisk target/release/ziskemu target/release/libzisk_witness.so; do \
        ldd $bin 2>/dev/null | grep '=> /' | awk '{print $3}' | \
        while read lib; do cp -L --no-clobber "$lib" /libs/ 2>/dev/null || true; done; \
    done && \
    find /usr/lib /usr/local/lib -name "libgomp.so*" | \
        while read lib; do cp -L --no-clobber "$lib" /libs/ 2>/dev/null || true; done

# ── Stage 2: Build the service as a fully static musl binary ──────────────────
FROM rust:1.85-slim-bookworm AS service-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    musl-tools \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY input-gen/Cargo.toml input-gen/Cargo.toml
COPY service/Cargo.toml service/Cargo.toml

# Create stub sources to cache dependencies
RUN mkdir -p input-gen/src input-gen/src/bin service/src && \
    echo 'pub fn placeholder() {}' > input-gen/src/lib.rs && \
    echo 'fn main() {}' > input-gen/src/bin/gen-input.rs && \
    echo 'fn main() {}' > service/src/main.rs

ENV RUSTFLAGS="-C target-feature=+crt-static"
RUN cargo build --release --target x86_64-unknown-linux-musl \
    -p davinci-zkvm-service -p davinci-zkvm-input-gen 2>&1 || true

RUN rm -rf input-gen/src service/src
COPY input-gen/src input-gen/src
COPY service/src service/src

# Invalidate fingerprints so Cargo rebuilds from real sources
RUN find target -maxdepth 4 -path "*/release/.fingerprint/davinci*" -exec rm -rf {} + 2>/dev/null || true

ENV RUSTFLAGS="-C target-feature=+crt-static"
RUN cargo build --release --target x86_64-unknown-linux-musl \
    -p davinci-zkvm-service -p davinci-zkvm-input-gen

# ── Stage 3: Runtime image ────────────────────────────────────────────────────
# Ubuntu 24.04 matches the builder glibc so bundled libs are compatible.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    openmpi-bin \
    openmpi-common \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Static service binary — zero dynamic dependencies
COPY --from=service-builder \
    /build/target/x86_64-unknown-linux-musl/release/davinci-zkvm \
    /app/davinci-zkvm

# cargo-zisk, tools, and witness library (all built from source)
COPY --from=zisk-builder /src/zisk/target/release/cargo-zisk /usr/local/bin/cargo-zisk
COPY --from=zisk-builder /src/zisk/target/release/ziskemu    /usr/local/bin/ziskemu
COPY --from=zisk-builder /src/zisk/target/release/libzisk_witness.so \
    /usr/local/lib/libzisk_witness.so

# Bundled shared libs — all deps cargo-zisk needs, no apt required
COPY --from=zisk-builder /libs /usr/local/lib/zisk-deps

# Symlink libzisk_witness.so to where cargo-zisk looks for it
RUN mkdir -p /root/.zisk/bin && \
    ln -s /usr/local/lib/libzisk_witness.so /root/.zisk/bin/libzisk_witness.so

# Copy pre-built circuit ELF and entrypoint
COPY circuit/elf/circuit.elf /app/circuit.elf
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENV LISTEN_ADDR=0.0.0.0:8080
ENV PROVING_KEY_PATH=/proving-key
ENV CIRCUIT_ELF_PATH=/app/circuit.elf
ENV CARGO_ZISK_BIN=/usr/local/bin/cargo-zisk
ENV PROOF_OUTPUT_DIR=/proofs
ENV LD_LIBRARY_PATH=/usr/local/lib/zisk-deps:/usr/local/lib
ENV OMPI_ALLOW_RUN_AS_ROOT=1
ENV OMPI_ALLOW_RUN_AS_ROOT_CONFIRM=1
ENV OMPI_MCA_opal_cuda_support=0
ENV OMPI_MCA_btl_smcuda_use_cuda_ipc=0

EXPOSE 8080

ENTRYPOINT ["/app/entrypoint.sh"]
