SHELL := /bin/bash

API_URL          ?= http://localhost:8080
COMPOSE_FILE     ?= ../docker-compose.yml
COMPOSE_PROJECT  ?= davinci-zkvm-test
PROVING_KEY_PATH ?= $(HOME)/.zisk/provingKey
# Profile selects which service variant to run: cuda (default) or cpu
PROFILE          ?= cuda

.PHONY: test test-unit test-full test-full-cpu \
        docker-build docker-up docker-up-cpu docker-down docker-logs \
        clean help

# ── Test targets ──────────────────────────────────────────────────────────────

# Run ALL integration tests (requires GPU service with proving support)
test:  ## Run all integration tests (CUDA GPU, requires running service)
DAVINCI_API_URL=$(API_URL) go test -v -timeout 30m ./...

# Run lightweight tests only (works with both CPU and GPU services)
test-unit:  ## Run lightweight tests (health, validation, 404 — no proving)
DAVINCI_API_URL=$(API_URL) DAVINCI_SKIP_PROVING=1 \
    go test -v -timeout 60s -run "TestHealth|TestInvalid|TestJobNotFound" ./...

# ── Docker build targets ──────────────────────────────────────────────────────

docker-build:  ## Build the CUDA GPU image
docker build -t davinci-zkvm-cuda:latest -f ../Dockerfile.cuda ..

docker-build-cpu:  ## Build the CPU-only image (API only, no proving)
docker build -t davinci-zkvm:latest -f ../Dockerfile ..

# ── Docker run targets ────────────────────────────────────────────────────────

# Wait for health endpoint then exit success/fail
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

docker-up-cpu:  ## Build and start the CPU-only service (API only)
PROVING_KEY_PATH=$(PROVING_KEY_PATH) \
    docker compose -f $(COMPOSE_FILE) --profile cpu -p $(COMPOSE_PROJECT) up -d --build
$(WAIT_HEALTHY)

docker-down:  ## Stop all running services
docker compose -f $(COMPOSE_FILE) --profile cuda --profile cpu -p $(COMPOSE_PROJECT) down

docker-logs:  ## Show logs for the running service
docker compose -f $(COMPOSE_FILE) --profile $(PROFILE) -p $(COMPOSE_PROJECT) logs -f

# ── Full integration test workflows ──────────────────────────────────────────

# Full cycle (GPU): build → start → all tests → stop
test-full: docker-up  ## Build, start GPU service, run all tests, stop
$(MAKE) test; \
EXIT_CODE=$$?; \
$(MAKE) docker-down; \
exit $$EXIT_CODE

# Full cycle (CPU): build → start → lightweight tests → stop
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
