SHELL := /bin/bash

API_URL          ?= http://localhost:8080
COMPOSE_FILE     ?= ../../docker-compose.yml
COMPOSE_PROJECT  ?= davinci-zkvm-test
PROVING_KEY_PATH ?= $(HOME)/.zisk/provingKey
PROFILE          ?= cuda

# Repo root relative to this directory
REPO_ROOT        := $(realpath $(dir $(COMPOSE_FILE)))

.PHONY: test test-unit test-full test-full-cpu \
        docker-build docker-build-cpu docker-up docker-up-cpu docker-down docker-logs \
        clean help

# Run ALL integration tests (requires GPU service with proving support)
test:  ## Run all integration tests (CUDA GPU, requires running service)
	DAVINCI_API_URL=$(API_URL) go test -v -timeout 30m ./...

# Run lightweight tests only (health, validation, 404 — no proving)
test-unit:  ## Run lightweight tests (no proving required)
	DAVINCI_API_URL=$(API_URL) DAVINCI_SKIP_PROVING=1 \
	    go test -v -timeout 60s -run "TestHealth|TestInvalid|TestJobNotFound" ./...

# Docker

docker-build:  ## Build the CUDA GPU image
	docker build -t davinci-zkvm-cuda:latest -f $(REPO_ROOT)/Dockerfile.cuda $(REPO_ROOT)

docker-build-cpu:  ## Build the CPU-only image
	docker build -t davinci-zkvm:latest -f $(REPO_ROOT)/Dockerfile $(REPO_ROOT)

define WAIT_HEALTHY
@echo "=== Waiting for service at $(API_URL) ==="; \
for i in $$(seq 1 60); do \
	if curl -sf $(API_URL)/health > /dev/null 2>&1; then \
		echo "=== Service ready ==="; exit 0; \
	fi; \
	echo "Waiting... ($$i/60)"; sleep 5; \
done; \
echo "=== Service did not start in time ==="; exit 1
endef

docker-up:  ## Build and start the CUDA GPU service
	PROVING_KEY_PATH=$(PROVING_KEY_PATH) \
	    docker compose -f $(COMPOSE_FILE) --profile cuda -p $(COMPOSE_PROJECT) up -d --build
	$(WAIT_HEALTHY)

docker-up-cpu:  ## Build and start the CPU-only service
	PROVING_KEY_PATH=$(PROVING_KEY_PATH) \
	    docker compose -f $(COMPOSE_FILE) --profile cpu -p $(COMPOSE_PROJECT) up -d --build
	$(WAIT_HEALTHY)

docker-down:  ## Stop all running services
	docker compose -f $(COMPOSE_FILE) --profile cuda --profile cpu -p $(COMPOSE_PROJECT) down

docker-logs:  ## Show logs for the running service
	docker compose -f $(COMPOSE_FILE) --profile $(PROFILE) -p $(COMPOSE_PROJECT) logs -f

test-full: docker-up  ## Build, start GPU service, run all tests, stop
	$(MAKE) test; \
	EXIT_CODE=$$?; \
	$(MAKE) docker-down; \
	exit $$EXIT_CODE

test-full-cpu: docker-up-cpu  ## Build, start CPU service, run lightweight tests, stop
	$(MAKE) test-unit; \
	EXIT_CODE=$$?; \
	$(MAKE) docker-down; \
	exit $$EXIT_CODE

clean:  ## Remove test binaries
	rm -f *.test

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | \
	    awk 'BEGIN{FS=":.*##"}{ printf "  %-20s %s\n", $$1, $$2 }'
