GO ?= go
GOTOOLCHAIN ?= local
export GOTOOLCHAIN

TOOLS := golangci-lint gosec govulncheck
GOLANGCI_LINT_VERSION ?= v2.11.4
GOSEC_VERSION ?= v2.25.0
GOVULNCHECK_VERSION ?= v1.2.0
FUZZTIME ?= 5s

.PHONY: help tools fmt lint vuln gosec test test-race coverage openapi-check test-vectors-check crypto-inventory deployment-profile-check collections-check fuzz-smoke sdk-generate sdk-check docs-check release-acceptance compose-up compose-down migrate postgres-integration-test redis-integration-test fast-check finalize clean

help: ## Show help
	@awk 'BEGIN {FS=":.*## "}; /^[a-zA-Z0-9_.-]+:.*## / { printf "  %-16s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

tools: ## Install local QA tools
	@$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	@$(GO) install github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION)
	@$(GO) install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

fmt: ## Format Go files
	@$(GO) fmt ./...

lint: tools ## Run golangci-lint
	@golangci-lint run ./...

vuln: tools ## Run govulncheck
	@govulncheck -show verbose ./...

gosec: tools ## Run gosec
	@gosec -exclude-dir=.refs -exclude-dir=.trash ./...

test: ## Run unit tests
	@$(GO) test ./...

test-race: ## Run race tests
	@$(GO) test ./... -race -count=1

coverage: ## Run tests with coverage
	@$(GO) test ./... -coverprofile=coverage.out
	@$(GO) tool cover -func=coverage.out

openapi-check: ## Validate OpenAPI source and route contract smoke tests
	@test -f openapi.yaml
	@$(GO) test ./internal/adapters/httpapi -run 'TestOpenAPI|TestRoute'

test-vectors-check: ## Validate committed public audit test vectors
	@$(GO) test ./internal/provider -run TestProviderSignatureVectors

crypto-inventory: ## Check crypto inventory evidence exists
	@grep -q "Webhook-Signature" openapi.yaml
	@grep -q "HMAC-SHA256" docs/operations.md
	@grep -q "envelope encryption" docs/operations.md

deployment-profile-check: ## Check deployment profile evidence and non-claims
	@grep -q "/readyz" openapi.yaml
	@grep -q "no FIPS/NIST/CMVP certification" docs/operations.md
	@test -f deploy/kubernetes/kustomization.yaml
	@test -f deploy/kubernetes/secret.example.yaml
	@grep -q "runAsNonRoot: true" deploy/kubernetes/api-deployment.yaml
	@grep -q "WEBHOOKERY_DATABASE_URL" deploy/kubernetes/secret.example.yaml
	@test -x scripts/release_acceptance.sh
	@test -x scripts/backup_postgres.sh
	@test -x scripts/restore_postgres.sh
	@grep -q "backup_postgres.sh" docs/operations.md
	@grep -q "restore_postgres.sh" docs/operations.md

collections-check: ## Check committed API client collections
	@test -f collections/postman/webhookery.postman_collection.json
	@test -f collections/bruno/Webhookery/bruno.json
	@grep -q "collection/v2.1.0/collection.json" collections/postman/webhookery.postman_collection.json
	@grep -q "/v1/events" collections/bruno/Webhookery/events-list.bru
	@grep -q "/v1/audit-chain:verify" collections/bruno/Webhookery/audit-chain-verify.bru

fuzz-smoke: ## Run short CI-safe fuzz/property smoke tests
	@$(GO) test ./internal/canonicaljson -run '^$$' -fuzz=Fuzz -fuzztime=$(FUZZTIME)
	@$(GO) test ./internal/adapters/httpapi -run '^$$' -fuzz=Fuzz -fuzztime=$(FUZZTIME)
	@$(GO) test ./pkg/verifier -run '^$$' -fuzz=Fuzz -fuzztime=$(FUZZTIME)
	@$(GO) test ./internal/random -run '^$$' -fuzz=Fuzz -fuzztime=$(FUZZTIME)

release-acceptance: ## Run v3.3 release acceptance evidence checks
	@scripts/release_acceptance.sh

sdk-generate: ## Refresh committed SDK-ready artifacts from OpenAPI
	@cp openapi.yaml sdk/openapi.yaml
	@printf '%s\n' "SDK artifacts refreshed from openapi.yaml"

sdk-check: ## Validate committed SDK artifacts are present and aligned
	@test -f sdk/openapi.yaml
	@cmp -s openapi.yaml sdk/openapi.yaml
	@test -f sdk/README.md
	@test -f pkg/client/client.go
	@$(GO) test ./pkg/client

docs-check: ## Run non-mutating documentation-adjacent checks
	@$(MAKE) openapi-check
	@$(MAKE) test-vectors-check
	@$(MAKE) sdk-check
	@$(MAKE) crypto-inventory
	@$(MAKE) deployment-profile-check
	@$(MAKE) collections-check

compose-up: ## Start local dependencies and API
	@docker compose up --build

compose-down: ## Stop local dependencies
	@docker compose down --remove-orphans

migrate: ## Run Postgres migrations using DATABASE_URL
	@$(GO) run ./cmd/whcp migrate -dir migrations up

postgres-integration-test: ## Run live Postgres migration and store integration tests
	@test -n "$$RANDONNEE_TEST_DATABASE_URL" || (printf '%s\n' "RANDONNEE_TEST_DATABASE_URL is required; start postgres with docker compose up -d postgres" >&2; exit 2)
	@$(GO) test ./internal/adapters/postgres -run 'TestPostgres|TestMigration' -count=1

redis-integration-test: ## Run live Redis edge-store integration tests
	@test -n "$$RANDONNEE_TEST_REDIS_ADDR" || (printf '%s\n' "RANDONNEE_TEST_REDIS_ADDR is required; start redis with docker compose up -d redis" >&2; exit 2)
	@$(GO) test ./internal/adapters/redisstore -run 'TestRedisStoreIntegration' -count=1

fast-check: ## Run non-mutating checks
	@$(GO) test ./...
	@$(MAKE) openapi-check
	@$(MAKE) test-vectors-check
	@$(MAKE) crypto-inventory
	@$(MAKE) deployment-profile-check
	@$(MAKE) collections-check
	@$(MAKE) sdk-check

finalize: ## Thorough validity check
	@$(MAKE) fmt
	@$(MAKE) lint
	@$(MAKE) vuln
	@$(MAKE) gosec
	@$(MAKE) test
	@$(MAKE) test-race
	@$(MAKE) openapi-check
	@$(MAKE) test-vectors-check
	@$(MAKE) crypto-inventory
	@$(MAKE) deployment-profile-check
	@$(MAKE) collections-check
	@$(MAKE) sdk-check

clean: ## Clean local test artifacts
	@$(GO) clean -testcache
	@rm -f coverage.out
