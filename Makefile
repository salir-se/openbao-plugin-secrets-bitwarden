BINARY          := openbao-plugin-secrets-bitwarden
PKG             := ./cmd/$(BINARY)
BIN_DIR         := bin
VERSION         ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS         := -s -w -X main.version=$(VERSION)
COVER_PROFILE   := coverage.out
COVER_THRESHOLD ?= 95.0

.DEFAULT_GOAL := build

.PHONY: build
build: ## Build a static plugin binary into bin/
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/$(BINARY) $(PKG)

.PHONY: test
test: ## Run unit tests with the race detector
	go test -race -count=1 ./...

.PHONY: cover
cover: ## Run unit tests with coverage; fail below COVER_THRESHOLD percent
	go test -race -covermode=atomic -coverprofile=$(COVER_PROFILE) ./...
	./scripts/check-coverage.sh $(COVER_PROFILE) $(COVER_THRESHOLD)

.PHONY: test-integration
test-integration: ## Run the docker-based integration tests (OpenBao + Vaultwarden)
	./scripts/integration-test.sh

.PHONY: e2e-up
e2e-up: ## Start the e2e environment (OpenBao + plugin, Vaultwarden) and leave it running
	docker compose -f e2e/compose.yaml build
	docker compose -f e2e/compose.yaml run --rm setup

.PHONY: e2e-test
e2e-test: ## Run the end-to-end suite against a fresh e2e environment (KEEP=1 keeps it)
	./e2e/run.sh

.PHONY: e2e-shell
e2e-shell: ## Shell with the bao and bw CLIs, connected to the e2e environment
	docker compose -f e2e/compose.yaml run --rm tools

.PHONY: e2e-down
e2e-down: ## Remove the e2e containers and volumes
	docker compose -f e2e/compose.yaml --profile tools down --volumes --remove-orphans

.PHONY: lint
lint: ## gofmt check, go vet, and golangci-lint when installed
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt needed on:"; echo "$$unformatted"; exit 1; \
	fi
	go vet ./...
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed; skipped (https://golangci-lint.run)"; \
	fi

.PHONY: sha256
sha256: build ## Print the binary's SHA-256 (needed for `bao plugin register`)
	@sha256sum $(BIN_DIR)/$(BINARY) | cut -d' ' -f1

.PHONY: clean
clean: ## Remove build and test artefacts
	rm -rf $(BIN_DIR) dist $(COVER_PROFILE) coverage.html

.PHONY: help
help: ## List targets
	@grep -E '^[a-zA-Z0-9_-]+:.*## ' $(MAKEFILE_LIST) | awk -F ':.*## ' '{printf "  %-18s %s\n", $$1, $$2}'
