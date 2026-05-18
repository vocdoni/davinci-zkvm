SHELL := /bin/bash

API_URL          ?= http://localhost:8080
COMPOSE_FILE     ?= ../../docker-compose.yml
COMPOSE_PROJECT  ?= davinci-zkvm-test
PROVING_KEY_PATH ?= $(HOME)/.zisk/provingKey
PROVING_KEY_PLONK_PATH ?= $(HOME)/.zisk/provingKeySnark

REPO_ROOT := $(realpath $(dir $(COMPOSE_FILE)))

.PHONY: test test-unit test-full docker-build docker-up docker-down docker-logs clean help

# Run the full integration test suite (requires a running GPU service).
test:  ## Run all integration tests against the service at $(API_URL).
	DAVINCI_API_URL=$(API_URL) go test -v -timeout 30m ./...

# Run only the lightweight tests (health, validation, 404 — no proving).
test-unit:  ## Run lightweight tests that do not require proving.
	DAVINCI_API_URL=$(API_URL) DAVINCI_SKIP_PROVING=1 \
	    go test -v -timeout 60s -run "TestHealth|TestInvalid|TestJobNotFound" ./...

# Docker orchestration

docker-build:  ## Build the davinci-zkvm CUDA image.
	docker build -t davinci-zkvm-cuda:latest -f $(REPO_ROOT)/Dockerfile.cuda $(REPO_ROOT)

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

docker-up:  ## Build and start the davinci-zkvm service.
	PROVING_KEY_PATH=$(PROVING_KEY_PATH) PROVING_KEY_PLONK_PATH=$(PROVING_KEY_PLONK_PATH) \
	    docker compose -f $(COMPOSE_FILE) --profile cuda -p $(COMPOSE_PROJECT) up -d --build
	$(WAIT_HEALTHY)

docker-down:  ## Stop the running service.
	docker compose -f $(COMPOSE_FILE) --profile cuda -p $(COMPOSE_PROJECT) down

docker-logs:  ## Tail the running service's logs.
	docker compose -f $(COMPOSE_FILE) --profile cuda -p $(COMPOSE_PROJECT) logs -f

test-full: docker-up  ## Build, start the service, run all tests, stop.
	$(MAKE) test; EXIT_CODE=$$?; $(MAKE) docker-down; exit $$EXIT_CODE

clean:  ## Remove test binaries.
	rm -f *.test

help:  ## Show this help.
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | \
	    awk 'BEGIN{FS=":.*##"}{ printf "  %-20s %s\n", $$1, $$2 }'
