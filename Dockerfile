# ── Stage 1: Build the service binary ─────────────────────────────────────────
FROM rust:1.85-slim-bookworm AS builder

WORKDIR /build

# System deps for building
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Cache dependencies: copy manifests first, then source
COPY Cargo.toml Cargo.lock ./
COPY input-gen/Cargo.toml input-gen/Cargo.toml
COPY service/Cargo.toml service/Cargo.toml

# Create stub sources to allow dependency caching
RUN mkdir -p input-gen/src input-gen/src/bin service/src && \
    echo 'pub fn placeholder() {}' > input-gen/src/lib.rs && \
    echo 'fn main() {}' > input-gen/src/bin/gen-input.rs && \
    echo 'fn main() {}' > service/src/main.rs

RUN cargo build --release -p davinci-zkvm-service -p davinci-zkvm-input-gen 2>&1 || true
RUN rm -rf input-gen/src service/src

# Copy real source
COPY input-gen/src input-gen/src
COPY service/src service/src

# Build release binaries
RUN cargo build --release -p davinci-zkvm-service -p davinci-zkvm-input-gen

# ── Stage 2: Fetch ZisK tools from release tarball ────────────────────────────
FROM debian:bookworm-slim AS zisk-tools

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ARG ZISK_VERSION=v0.15.0
RUN curl -fsSL \
    "https://github.com/0xPolygonHermez/zisk/releases/download/${ZISK_VERSION}/cargo_zisk_linux_amd64.tar.gz" \
    -o /tmp/cargo_zisk.tar.gz && \
    tar -xzf /tmp/cargo_zisk.tar.gz -C /tmp && \
    mv /tmp/bin/cargo-zisk /usr/local/bin/cargo-zisk && \
    mv /tmp/bin/ziskemu /usr/local/bin/ziskemu && \
    mv /tmp/bin/libzisk_witness.so /usr/local/lib/libzisk_witness.so && \
    chmod +x /usr/local/bin/cargo-zisk /usr/local/bin/ziskemu && \
    rm -rf /tmp/cargo_zisk.tar.gz /tmp/bin

# ── Stage 3: Runtime image ─────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy service binary
COPY --from=builder /build/target/release/davinci-zkvm /app/davinci-zkvm

# Copy ZisK tools
COPY --from=zisk-tools /usr/local/bin/cargo-zisk /usr/local/bin/cargo-zisk
COPY --from=zisk-tools /usr/local/bin/ziskemu /usr/local/bin/ziskemu
COPY --from=zisk-tools /usr/local/lib/libzisk_witness.so /usr/local/lib/libzisk_witness.so

# Copy pre-built circuit ELF
COPY circuit/elf/circuit.elf /app/circuit.elf

ENV LISTEN_ADDR=0.0.0.0:8080
ENV PROVING_KEY_PATH=/proving-key
ENV CIRCUIT_ELF_PATH=/app/circuit.elf
ENV CARGO_ZISK_BIN=/usr/local/bin/cargo-zisk
ENV PROOF_OUTPUT_DIR=/proofs
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

EXPOSE 8080

ENTRYPOINT ["/app/davinci-zkvm"]
