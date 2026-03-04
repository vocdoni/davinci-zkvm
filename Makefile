SHELL := /bin/bash

REPO_ROOT := $(CURDIR)
ENV_FILE := $(REPO_ROOT)/.env.local.nodocker
SERVICE_BIN := $(REPO_ROOT)/target/release/davinci-zkvm

LISTEN_HOST ?= 127.0.0.1
LISTEN_PORT ?= 8080

# install.sh passthroughs (kept intentionally small)
INSTALL_SYSTEM_DEPS ?= auto
RUN_SETUP ?= 1
RUN_SETUP_TREES ?= 1
ADD_TO_SHELL_RC ?= 1
PROVING_KEY_PATH ?= $(HOME)/.zisk/provingKey
ZISK_VERSION ?= v0.15.0
PROVER_MODE ?= auto
ZISK_MPI_PROCS ?=
ZISK_MPI_THREADS ?=
ZISK_MPI_BIND_TO ?=

.PHONY: all setup run test help

all: setup test ## Full local setup + integration tests

setup: ## Install/build everything for non-Docker local runs
	LISTEN_HOST=$(LISTEN_HOST) \
	LISTEN_PORT=$(LISTEN_PORT) \
	INSTALL_SYSTEM_DEPS=$(INSTALL_SYSTEM_DEPS) \
	RUN_SETUP=$(RUN_SETUP) \
	RUN_SETUP_TREES=$(RUN_SETUP_TREES) \
	ADD_TO_SHELL_RC=$(ADD_TO_SHELL_RC) \
	PROVING_KEY_PATH=$(PROVING_KEY_PATH) \
	ZISK_VERSION=$(ZISK_VERSION) \
	PROVER_MODE=$(PROVER_MODE) \
	./install.sh

run: ## Run the HTTP service locally
	@if [ ! -f "$(ENV_FILE)" ]; then \
		echo "Missing $(ENV_FILE). Run: make setup"; \
		exit 1; \
	fi
	@if [ ! -x "$(SERVICE_BIN)" ]; then \
		echo "Missing $(SERVICE_BIN). Run: make setup"; \
		exit 1; \
	fi
	@bash -lc 'set -euo pipefail; \
		source "$(ENV_FILE)"; \
		export LISTEN_ADDR="$(LISTEN_HOST):$(LISTEN_PORT)"; \
		export DAVINCI_API_URL="http://$(LISTEN_HOST):$(LISTEN_PORT)"; \
		if [ -n "$(ZISK_MPI_PROCS)" ]; then export ZISK_MPI_PROCS="$(ZISK_MPI_PROCS)"; fi; \
		if [ -n "$(ZISK_MPI_THREADS)" ]; then export ZISK_MPI_THREADS="$(ZISK_MPI_THREADS)"; fi; \
		if [ -n "$(ZISK_MPI_BIND_TO)" ]; then export ZISK_MPI_BIND_TO="$(ZISK_MPI_BIND_TO)"; fi; \
		exec "$(SERVICE_BIN)"'

test: ## Run integration tests locally (starts/stops service automatically)
	@bash -lc 'set -euo pipefail; \
		cd "$(REPO_ROOT)"; \
		if [ ! -f "$(ENV_FILE)" ] || [ ! -x "$(SERVICE_BIN)" ]; then \
			echo "Setup artifacts missing. Running make setup..."; \
			LISTEN_HOST=$(LISTEN_HOST) \
			LISTEN_PORT=$(LISTEN_PORT) \
			INSTALL_SYSTEM_DEPS=$(INSTALL_SYSTEM_DEPS) \
			RUN_SETUP=$(RUN_SETUP) \
			RUN_SETUP_TREES=$(RUN_SETUP_TREES) \
			ADD_TO_SHELL_RC=$(ADD_TO_SHELL_RC) \
			PROVING_KEY_PATH=$(PROVING_KEY_PATH) \
			ZISK_VERSION=$(ZISK_VERSION) \
			PROVER_MODE=$(PROVER_MODE) \
			./install.sh; \
		fi; \
		source "$(ENV_FILE)"; \
		export LISTEN_ADDR="$(LISTEN_HOST):$(LISTEN_PORT)"; \
		export DAVINCI_API_URL="http://$(LISTEN_HOST):$(LISTEN_PORT)"; \
		if [ -n "$(ZISK_MPI_PROCS)" ]; then export ZISK_MPI_PROCS="$(ZISK_MPI_PROCS)"; fi; \
		if [ -n "$(ZISK_MPI_THREADS)" ]; then export ZISK_MPI_THREADS="$(ZISK_MPI_THREADS)"; fi; \
		if [ -n "$(ZISK_MPI_BIND_TO)" ]; then export ZISK_MPI_BIND_TO="$(ZISK_MPI_BIND_TO)"; fi; \
		LOG_FILE="$(REPO_ROOT)/.davinci-service.log"; \
		"$(SERVICE_BIN)" >"$$LOG_FILE" 2>&1 & \
		SVC_PID=$$!; \
		cleanup(){ \
			if kill -0 "$$SVC_PID" 2>/dev/null; then \
				kill "$$SVC_PID" 2>/dev/null || true; \
				wait "$$SVC_PID" 2>/dev/null || true; \
			fi; \
		}; \
		trap cleanup EXIT; \
		for i in $$(seq 1 120); do \
			if curl -sf "$$DAVINCI_API_URL/health" >/dev/null 2>&1; then \
				echo "Service ready at $$DAVINCI_API_URL"; \
				break; \
			fi; \
			if [ "$$i" -eq 120 ]; then \
				echo "Service did not become healthy in time. Last logs:"; \
				tail -n 200 "$$LOG_FILE" || true; \
				exit 1; \
			fi; \
			sleep 1; \
		done; \
		cd go-sdk/tests; \
		if [ "$${DAVINCI_PROVER_MODE:-gpu}" = "gpu" ]; then \
			DAVINCI_API_URL="$$DAVINCI_API_URL" make test; \
		else \
			echo "CPU mode detected: running lightweight tests (no proving)."; \
			DAVINCI_API_URL="$$DAVINCI_API_URL" make test-unit; \
		fi'

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*##"}{ printf "  %-10s %s\n", $$1, $$2 }'
