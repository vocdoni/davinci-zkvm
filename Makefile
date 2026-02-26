SHELL := /bin/bash

# --- Paths ---
ZISK_BIN        := $(HOME)/.zisk/bin
CARGO_ZISK      := $(ZISK_BIN)/cargo-zisk
ZISKEMU         := $(ZISK_BIN)/ziskemu

SERVICE_BIN     := target/release/davinci-zkvm
CIRCUIT_DIR     := circuit
CIRCUIT_TARGET  := riscv64ima-zisk-zkvm-elf
CIRCUIT_ELF     := $(CIRCUIT_DIR)/target/$(CIRCUIT_TARGET)/release/davinci-zkvm-circuit

DATA_DIR        := data/simple_mul_bn254
PROOFS_DIR      := $(DATA_DIR)
INPUT_BIN       := $(DATA_DIR)/aggregated_bn254/zisk_full_verify_input.bin
NPROOFS         ?= 128

PROOF_DIR       ?= proof_output
PROVING_KEY     ?= $(HOME)/.zisk/provingKey
SETUP_BUCKET    := https://storage.googleapis.com/zisk-setup

# Docker
DOCKER_IMAGE    ?= davinci-zkvm
DOCKER_TAG      ?= latest

# ZisK GPU source path (for build-zisk-gpu target)
ZISK_SRC        ?= $(HOME)/davinci-zisk/zisk
CUDA_12_8       := /usr/local/cuda-12.8/bin

.PHONY: all build build-service build-circuit gen-input run-emu \
        setup setup-trees build-zisk-gpu \
        prove \
        docker-build docker-build-cuda \
        test-integration \
        clean help

all: build  ## Default: build service

# ── Build ──────────────────────────────────────────────────────────────────────

build: build-service  ## Build the service binary

build-service:  ## Build the HTTP service binary (release)
	cargo build --release -p davinci-zkvm-service

build-circuit:  ## Rebuild the ZisK RISC-V circuit ELF (requires +zisk toolchain)
	cd $(CIRCUIT_DIR) && cargo +zisk build --release --target $(CIRCUIT_TARGET)
	cp $(CIRCUIT_ELF) $(CIRCUIT_DIR)/elf/circuit.elf
	@echo "=== Circuit ELF updated at circuit/elf/circuit.elf ==="

# ── Input generation / emulator ────────────────────────────────────────────────

gen-input:  ## Generate the ZisK binary input from test proofs (runs input-gen CLI)
	@echo "=== Generating input binary from $(PROOFS_DIR) ($(NPROOFS) proofs) ==="
	@cargo run --release -p davinci-zkvm-input-gen --bin gen-input -- \
		--proofs-dir $(PROOFS_DIR) \
		--output $(INPUT_BIN) \
		--nproofs $(NPROOFS)

run-emu: gen-input  ## Generate input and run the circuit in the ZisK emulator
	$(ZISKEMU) -e $(CIRCUIT_DIR)/elf/circuit.elf -i $(INPUT_BIN)

run-steps: gen-input  ## Run emulator with step/instance count summary
	$(CARGO_ZISK) execute \
		--elf $(CIRCUIT_DIR)/elf/circuit.elf \
		--input $(INPUT_BIN) \
		--emulator

# ── ZisK setup ─────────────────────────────────────────────────────────────────

setup:  ## Download + install the ZisK proving key (version derived from cargo-zisk)
	@ZISK_VER=$$($(CARGO_ZISK) --version | awk '{print $$2}'); \
	IFS='.' read -r major minor patch <<< "$$ZISK_VER"; \
	SETUP_VER="$${major}.$${minor}.0"; \
	KEY_FILE="zisk-provingkey-$${SETUP_VER}.tar.gz"; \
	echo "=== Downloading proving key $${KEY_FILE} ==="; \
	curl -L "$(SETUP_BUCKET)/$${KEY_FILE}" -o "/tmp/$${KEY_FILE}"; \
	curl -L "$(SETUP_BUCKET)/$${KEY_FILE}.md5" -o "/tmp/$${KEY_FILE}.md5"; \
	cd /tmp && md5sum -c "$${KEY_FILE}.md5"; \
	echo "=== Installing proving key to $(HOME)/.zisk ==="; \
	rm -rf $(PROVING_KEY) $(HOME)/.zisk/verifyKey $(HOME)/.zisk/cache; \
	tar --overwrite -xf "/tmp/$${KEY_FILE}" -C "$(HOME)/.zisk"; \
	rm -f "/tmp/$${KEY_FILE}" "/tmp/$${KEY_FILE}.md5"; \
	echo "=== Proving key installed. Run 'make setup-trees' next. ==="

setup-trees:  ## Build constant tree files required for full proving
	@if [ ! -d "$(PROVING_KEY)" ]; then \
		echo "ERROR: Proving key not found at $(PROVING_KEY). Run 'make setup' first."; exit 1; \
	fi
	@echo "=== Building constant trees ==="
	$(CARGO_ZISK) check-setup --proving-key $(PROVING_KEY) -a
	@echo "=== Constant trees built ==="

# ── ZisK GPU binary build ───────────────────────────────────────────────────────

build-zisk-gpu:  ## Rebuild cargo-zisk with CUDA 12.8 GPU support (RTX 5000 / Blackwell sm_120)
	@echo "=== Building ZisK with GPU support (CUDA 12.8) ==="
	@if [ ! -d "$(CUDA_12_8)" ]; then \
		echo "ERROR: CUDA 12.8 not found at $(CUDA_12_8)"; exit 1; \
	fi
	@export PATH=$(CUDA_12_8):$$PATH; \
	PSTARK=$$(ls -d $(HOME)/.cargo/git/checkouts/pil2-proofman-*/*/pil2-stark 2>/dev/null | head -1); \
	if [ -z "$$PSTARK" ]; then echo "ERROR: pil2-stark not found in cargo cache"; exit 1; fi; \
	echo "=== Rebuilding libstarksgpu.a with CUDA 12.8 ==="; \
	cd "$$PSTARK" && make clean && make -j$$(nproc) starks_lib_gpu; \
	echo "=== Building cargo-zisk ==="; \
	cd $(ZISK_SRC) && cargo clean && cargo build --release --features gpu; \
	echo "=== Deploying to ~/.zisk/bin/ ==="; \
	cp $(ZISK_SRC)/target/release/cargo-zisk $(HOME)/.zisk/bin/cargo-zisk; \
	cp $(ZISK_SRC)/target/release/libzisk_witness.so $(HOME)/.zisk/bin/libzisk_witness.so 2>/dev/null || true; \
	echo "=== Done: $$($(HOME)/.zisk/bin/cargo-zisk --version) ==="

# ── Proving ────────────────────────────────────────────────────────────────────

prove: gen-input  ## Run full ZisK proof (set PROOF_DIR= and PROVING_KEY= as needed). Reports elapsed time.
	@if [ ! -d "$(PROVING_KEY)" ]; then \
		echo "ERROR: Proving key not found at $(PROVING_KEY)"; \
		echo "Run 'make setup' then 'make setup-trees' to install it."; \
		exit 1; \
	fi
	@if [ ! -f "$(PROVING_KEY)/zisk/Zisk/airs/ArithEq/compressor/compressor.consttree" ] && \
	    [ ! -f "$(PROVING_KEY)/zisk/Zisk/airs/ArithEq/compressor/compressor.consttree_gpu" ]; then \
		echo "ERROR: Constant tree files are missing. Run 'make setup-trees'."; \
		exit 1; \
	fi
	@mkdir -p $(PROOF_DIR)
	@echo "=== ZisK prove started at $$(date) ==="
	@start=$$(date +%s); \
	$(CARGO_ZISK) prove \
		--elf $(CIRCUIT_DIR)/elf/circuit.elf \
		--input $(INPUT_BIN) \
		--proving-key $(PROVING_KEY) \
		--output-dir $(PROOF_DIR) \
		--emulator \
		--aggregation \
		--final-snark \
		--verify-proofs; \
	end=$$(date +%s); \
	echo ""; \
	echo "=== ZisK prove finished at $$(date) ==="; \
	echo "=== Total proving time: $$((end - start)) seconds ==="

# ── Docker ─────────────────────────────────────────────────────────────────────

docker-build:  ## Build CPU Docker image
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) -f Dockerfile .

docker-build-cuda:  ## Build CUDA GPU Docker image
	docker build -t $(DOCKER_IMAGE)-cuda:$(DOCKER_TAG) -f Dockerfile.cuda .

# ── Integration tests ──────────────────────────────────────────────────────────

test-integration: docker-build  ## Build Docker image and run Go integration tests
	@$(MAKE) -C integration-tests test

# ── Clean ──────────────────────────────────────────────────────────────────────

clean:  ## Remove all build artifacts, generated input, and proof output
	cargo clean
	rm -f $(INPUT_BIN)
	rm -rf $(PROOF_DIR)

# ── Help ───────────────────────────────────────────────────────────────────────

help:  ## Show this help
	@echo "davinci-zkvm Makefile targets:"
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*##"}{ printf "  %-20s %s\n", $$1, $$2 }'
