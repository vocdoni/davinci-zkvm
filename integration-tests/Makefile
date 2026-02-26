SHELL := /bin/bash

API_URL          ?= http://localhost:8080
COMPOSE_FILE     ?= ../docker-compose.yml
COMPOSE_PROJECT  ?= davinci-zkvm-test
PROVING_KEY_PATH ?= $(HOME)/.zisk/provingKey

.PHONY: test test-unit docker-build docker-up docker-down docker-logs clean help

# Run all integration tests (requires service to be running)
test:  ## Run integration tests against running service
	DAVINCI_API_URL=$(API_URL) go test -v -timeout 30m ./...

# Run lightweight tests only (no full proving, fast)
test-unit:  ## Run lightweight tests (health, validation, 404)
	DAVINCI_API_URL=$(API_URL) DAVINCI_SKIP_PROVING=1 go test -v -timeout 60s -run "TestHealth|TestInvalid|TestJobNotFound" ./...

# Build Docker image
docker-build:  ## Build the CPU Docker image
	docker build -t davinci-zkvm:latest -f ../Dockerfile ..

# Build CUDA Docker image
docker-build-cuda:  ## Build the CUDA GPU Docker image
	docker build -t davinci-zkvm-cuda:latest -f ../Dockerfile.cuda ..

# Start the service (CPU)
docker-up: docker-build  ## Build and start the service (CPU)
	PROVING_KEY_PATH=$(PROVING_KEY_PATH) \
	docker compose -f $(COMPOSE_FILE) -p $(COMPOSE_PROJECT) up -d
	@echo "=== Waiting for service to be healthy ==="
	@for i in $$(seq 1 30); do \
		if curl -sf $(API_URL)/health > /dev/null 2>&1; then \
			echo "=== Service is ready at $(API_URL) ==="; \
			break; \
		fi; \
		echo "Waiting... ($$i/30)"; \
		sleep 2; \
	done

# Start the service (CUDA GPU)
docker-up-cuda: docker-build-cuda  ## Build and start the service (CUDA GPU)
	PROVING_KEY_PATH=$(PROVING_KEY_PATH) \
	docker compose -f ../docker-compose.cuda.yml -p $(COMPOSE_PROJECT) up -d
	@echo "=== Waiting for service to be healthy ==="
	@for i in $$(seq 1 60); do \
		if curl -sf $(API_URL)/health > /dev/null 2>&1; then \
			echo "=== Service is ready at $(API_URL) ==="; \
			break; \
		fi; \
		echo "Waiting... ($$i/60)"; \
		sleep 5; \
	done

# Stop the service
docker-down:  ## Stop the service
	docker compose -f $(COMPOSE_FILE) -p $(COMPOSE_PROJECT) down

# Show service logs
docker-logs:  ## Show service logs
	docker compose -f $(COMPOSE_FILE) -p $(COMPOSE_PROJECT) logs -f

# Full integration test workflow: build → start → test → stop
test-full: docker-up  ## Build, start, test, stop (full integration test cycle)
	$(MAKE) test; \
	EXIT_CODE=$$?; \
	$(MAKE) docker-down; \
	exit $$EXIT_CODE

clean:  ## Remove test binaries
	rm -f *.test

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*##"}{ printf "  %-20s %s\n", $$1, $$2 }'
