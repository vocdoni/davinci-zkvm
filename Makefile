SHELL := /bin/bash

REPO_ROOT := $(CURDIR)

# ── Docker-driven setup (default path for fresh installs) ─────────────────
#
# All Docker targets read the same env vars docker-compose does. Override
# any of these on the command line or in a .env file at the repo root.

ZISK_TAG         ?= v0.18.0
ZISK_VERSION     ?= 0.18.0
ZISK_KEYS_DIR    ?= $(REPO_ROOT)/zisk-keys
LISTEN_PORT      ?= 8080
API_URL          ?= http://127.0.0.1:$(LISTEN_PORT)

COMPOSE          := ZISK_TAG=$(ZISK_TAG) ZISK_VERSION=$(ZISK_VERSION) \
                    ZISK_KEYS_DIR=$(ZISK_KEYS_DIR) LISTEN_PORT=$(LISTEN_PORT) \
                    HOST_UID=$(shell id -u) HOST_GID=$(shell id -g) \
                    docker compose

# ── Local non-Docker passthroughs (for development on the build host) ─────

LOCAL_ENV_FILE   := $(REPO_ROOT)/.env.local.nodocker
LOCAL_BIN        := $(REPO_ROOT)/target/release/davinci-zkvm
LOCAL_LISTEN_HOST ?= 127.0.0.1
INSTALL_SYSTEM_DEPS ?= auto
RUN_SETUP        ?= 1
RUN_SETUP_TREES  ?= 1
ADD_TO_SHELL_RC  ?= 1
PROVING_KEY_PATH ?= $(HOME)/.zisk/provingKey
PROVING_KEY_PLONK_PATH ?= $(HOME)/.zisk/provingKeySnark
PROVER_MODE      ?= auto
ZISK_MPI_PROCS   ?=
ZISK_MPI_THREADS ?=
ZISK_MPI_BIND_TO ?=

.PHONY: help \
        keys build up down restart logs status test shell clean install all \
        local-setup local-run local-test benchmark benchmark-report

# ──────────────────────────────────────────────────────────────────────────
# Default
# ──────────────────────────────────────────────────────────────────────────

help: ## Show available targets
	@echo "davinci-zkvm — Docker-driven setup"
	@echo ""
	@echo "Quick start on a fresh CUDA host:"
	@echo "  make install          → download proving keys + build runtime image"
	@echo "  make up               → start the prover service"
	@echo "  make test             → run the Go integration test suite"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*##"}{ printf "  %-14s %s\n", $$1, $$2 }'

# ──────────────────────────────────────────────────────────────────────────
# Docker workflow (primary)
# ──────────────────────────────────────────────────────────────────────────

install: keys build ## Download keys + build the runtime image (one-shot setup)

keys: ## Download both ZisK proving keys via ziskup into $(ZISK_KEYS_DIR)
	@mkdir -p $(ZISK_KEYS_DIR)
	@echo "=== Downloading ZisK proving keys into $(ZISK_KEYS_DIR) ==="
	@echo "    This takes 10–30 min depending on bandwidth (~37 GB)."
	$(COMPOSE) --profile setup build key-installer
	$(COMPOSE) --profile setup run --rm key-installer

build: ## Build the CUDA prover image
	$(COMPOSE) --profile cuda build

up: ## Start the prover service (first boot builds GPU consttrees, ~10 min)
	@if [ ! -d $(ZISK_KEYS_DIR)/provingKey ] || [ ! -d $(ZISK_KEYS_DIR)/provingKeySnark ]; then \
		echo "Proving keys missing at $(ZISK_KEYS_DIR). Run 'make keys' first."; \
		exit 1; \
	fi
	$(COMPOSE) --profile cuda up -d
	@echo "=== Service starting. Tail logs with 'make logs'. ==="

down: ## Stop the prover service
	$(COMPOSE) --profile cuda down

restart: down up ## Restart the prover service

logs: ## Tail the prover service logs
	$(COMPOSE) --profile cuda logs -f --tail=100

status: ## Show service container status
	$(COMPOSE) --profile cuda ps

shell: ## Open an interactive shell inside the running prover container
	$(COMPOSE) --profile cuda exec davinci-zkvm bash

test: ## Run the Go integration test suite against the running service
	@if ! curl -sf $(API_URL)/health >/dev/null 2>&1; then \
		echo "Service not reachable at $(API_URL). Run 'make up' first."; \
		exit 1; \
	fi
	cd go-sdk/tests && DAVINCI_API_URL=$(API_URL) $(MAKE) test

benchmark: ## Run the chained-mode benchmark sweep (see benchmark/README.md)
	@if ! curl -sf $(API_URL)/health >/dev/null 2>&1; then \
		echo "Service not reachable at $(API_URL). Run 'make up' first."; \
		exit 1; \
	fi
	DAVINCI_API_URL=$(API_URL) ./benchmark/run.sh

benchmark-report: ## Regenerate benchmark/results/RESULTS.md from existing logs
	./benchmark/run.sh report

clean: ## Stop service and remove proofs volume (KEEPS proving keys)
	$(COMPOSE) --profile cuda down -v

all: install up test ## Full pipeline: install → up → test

# ──────────────────────────────────────────────────────────────────────────
# Local non-Docker workflow (for developers building from source)
# ──────────────────────────────────────────────────────────────────────────

local-setup: ## Install ZisK + build davinci-zkvm on the host (no Docker)
	LISTEN_HOST=$(LOCAL_LISTEN_HOST) \
	LISTEN_PORT=$(LISTEN_PORT) \
	INSTALL_SYSTEM_DEPS=$(INSTALL_SYSTEM_DEPS) \
	RUN_SETUP=$(RUN_SETUP) \
	RUN_SETUP_TREES=$(RUN_SETUP_TREES) \
	ADD_TO_SHELL_RC=$(ADD_TO_SHELL_RC) \
	PROVING_KEY_PATH=$(PROVING_KEY_PATH) \
	PROVING_KEY_PLONK_PATH=$(PROVING_KEY_PLONK_PATH) \
	ZISK_VERSION=$(ZISK_VERSION) \
	PROVER_MODE=$(PROVER_MODE) \
	./scripts/install.sh

local-run: ## Run the host-built service binary
	@if [ ! -f "$(LOCAL_ENV_FILE)" ] || [ ! -x "$(LOCAL_BIN)" ]; then \
		echo "Missing local setup artifacts. Run: make local-setup"; \
		exit 1; \
	fi
	@bash -lc 'set -euo pipefail; \
		source "$(LOCAL_ENV_FILE)"; \
		export LISTEN_ADDR="$(LOCAL_LISTEN_HOST):$(LISTEN_PORT)"; \
		export DAVINCI_API_URL="http://$(LOCAL_LISTEN_HOST):$(LISTEN_PORT)"; \
		exec "$(LOCAL_BIN)"'

local-test: ## Run the integration tests against a host-built service
	@bash -lc 'set -euo pipefail; \
		cd "$(REPO_ROOT)"; \
		source "$(LOCAL_ENV_FILE)"; \
		export LISTEN_ADDR="$(LOCAL_LISTEN_HOST):$(LISTEN_PORT)"; \
		export DAVINCI_API_URL="http://$(LOCAL_LISTEN_HOST):$(LISTEN_PORT)"; \
		"$(LOCAL_BIN)" >.davinci-service.log 2>&1 & \
		SVC_PID=$$!; \
		trap "kill $$SVC_PID 2>/dev/null || true" EXIT; \
		for i in $$(seq 1 120); do \
			curl -sf "$$DAVINCI_API_URL/health" >/dev/null 2>&1 && break; \
			sleep 1; \
		done; \
		cd go-sdk/tests && DAVINCI_API_URL="$$DAVINCI_API_URL" $(MAKE) test'

.DEFAULT_GOAL := help
