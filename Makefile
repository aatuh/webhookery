GO ?= go
GOTOOLCHAIN ?= local
export GOTOOLCHAIN

TOOLS := golangci-lint gosec govulncheck
GOLANGCI_LINT_VERSION ?= v2.11.4
GOSEC_VERSION ?= v2.25.0
GOVULNCHECK_VERSION ?= v1.2.0
FUZZTIME ?= 5s

.PHONY: help tools fmt lint vuln gosec test test-race coverage openapi-check test-vectors-check provider-conformance-check crypto-inventory deployment-profile-check collections-check documentation-structure-check static-site-check meta-files-check fuzz-smoke perf-smoke sdk-generate sdk-check docs-check release-acceptance rc-check compose-up compose-down migrate live-postgres-check postgres-integration-test redis-integration-test fast-check finalize clean

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

provider-conformance-check: ## Validate provider conformance matrix and local vectors
	@scripts/provider_conformance_check.sh

crypto-inventory: ## Check crypto inventory evidence exists
	@grep -q "Webhook-Signature" openapi.yaml
	@grep -q "HMAC-SHA256" docs/operations.md
	@grep -q "envelope encryption" docs/operations.md

deployment-profile-check: ## Check deployment profile evidence and non-claims
	@grep -q "/readyz" openapi.yaml
	@grep -q "no FIPS/NIST/CMVP certification" docs/operations.md
	@test -f docs/deployment.md
	@test -f deploy/kubernetes/kustomization.yaml
	@test -f deploy/kubernetes/secret.example.yaml
	@test -f deploy/kubernetes/networkpolicy.example.yaml
	@test -f deploy/helm/webhookery/Chart.yaml
	@test -f deploy/helm/webhookery/values.yaml
	@test -f deploy/helm/webhookery/values-production.example.yaml
	@test -f deploy/observability/prometheus-rules.example.yaml
	@test -f deploy/terraform/webhookery-helm/main.tf
	@test -f deploy/terraform/webhookery-helm/README.md
	@terraform fmt -check -recursive deploy/terraform
	@grep -q "runAsNonRoot: true" deploy/kubernetes/api-deployment.yaml
	@grep -q "runAsNonRoot: true" deploy/helm/webhookery/values.yaml
	@grep -q "WEBHOOKERY_DATABASE_URL" deploy/kubernetes/secret.example.yaml
	@grep -q "WEBHOOKERY_DATABASE_URL" deploy/helm/webhookery/values.yaml
	@grep -q "helm_release" deploy/terraform/webhookery-helm/main.tf
	@grep -q "docs/deployment.md" deploy/kubernetes/README.md
	@grep -q "networkpolicy.example.yaml" deploy/kubernetes/README.md
	@grep -q "docs/deployment.md" deploy/helm/webhookery/README.md
	@grep -q "values-production.example.yaml" deploy/helm/webhookery/README.md
	@grep -q "docs/deployment.md" deploy/terraform/webhookery-helm/README.md
	@grep -q "not accepted as module variables" deploy/terraform/webhookery-helm/README.md
	@test -x scripts/release_acceptance.sh
	@test -x scripts/backup_postgres.sh
	@test -x scripts/restore_postgres.sh
	@grep -q "backup_postgres.sh" docs/operations.md
	@grep -q "restore_postgres.sh" docs/operations.md

collections-check: ## Check committed API client collections
	@test -f collections/README.md
	@test -f collections/postman/webhookery.postman_collection.json
	@test -f collections/bruno/Webhookery/bruno.json
	@grep -q "Postman" collections/README.md
	@grep -q "Bruno" collections/README.md
	@grep -q "Webhook-Signature" collections/README.md
	@grep -q "collection/v2.1.0/collection.json" collections/postman/webhookery.postman_collection.json
	@grep -q "/v1/events" collections/bruno/Webhookery/events-list.bru
	@grep -q "/v1/audit-chain:verify" collections/bruno/Webhookery/audit-chain-verify.bru

documentation-structure-check: ## Check canonical documentation structure
	@test -f CHANGELOG.md
	@test -f docs/index.md
	@test -f docs/evaluator-quickstart.md
	@test -f docs/demo-media-checklist.md
	@test -f docs/releases/v0.1.0-rc1.md
	@test -f docs/commercial-evaluation.md
	@test -f docs/production-readiness-review.md
	@test -f docs/support-packages.md
	@test -f docs/comparisons/build-vs-buy.md
	@test -f docs/comparisons/hookdeck.md
	@test -f docs/comparisons/svix.md
	@test -f docs/comparisons/convoy.md
	@test -f docs/articles/exactly-once-webhooks.md
	@test -f docs/articles/webhook-incident-report.md
	@test -f docs/articles/webhook-failure-modes.md
	@test -f docs/launch-copy.md
	@test -f docs/launch-metrics.md
	@test -f docs/pilot-feedback-template.md
	@test -f docs/roadmap-intake-policy.md
	@test -f docs/pilot-review-checklist.md
	@test -f docs/configuration.md
	@test -f docs/feature-behavior.md
	@test -f docs/security-promise.md
	@test -f docs/stability.md
	@test -f docs/performance-envelope.md
	@test -f docs/provider-conformance.md
	@test -f docs/provider-conformance.manifest.json
	@test -f docs/day-2-operations.md
	@test -f docs/observability.md
	@test -f docs/documentation-maintenance.md
	@test -f docs/cli.md
	@test -f docs/deployment.md
	@test -f docs/schema-migrations.md
	@test -f docs/security-review-package.md
	@test -f docs/external-review-scope.md
	@test -f docs/external-review-findings-template.md
	@test -f docs/external-review-accepted-risks.md
	@test -f docs/release-evidence-template.md
	@grep -q "Documentation Map" docs/index.md
	@grep -q "docs/evaluator-quickstart.md" README.md
	@grep -q "examples/webhook-evidence-demo" README.md
	@grep -q "site/index.html" README.md
	@grep -q "docs/commercial-evaluation.md" README.md
	@grep -q "Evaluator Quickstart" docs/evaluator-quickstart.md
	@grep -q "Demo Media Checklist" docs/demo-media-checklist.md
	@grep -q "v0.1.0-rc1" CHANGELOG.md
	@grep -q "release candidate" docs/releases/v0.1.0-rc1.md
	@grep -q "exactly-once delivery" docs/releases/v0.1.0-rc1.md
	@grep -q "provider-side event completeness" docs/releases/v0.1.0-rc1.md
	@grep -q "Commercial Evaluation" docs/commercial-evaluation.md
	@grep -q "Production Readiness Review" docs/production-readiness-review.md
	@grep -q "Support Packages" docs/support-packages.md
	@grep -q "Build Vs Buy" docs/comparisons/build-vs-buy.md
	@grep -q "Verification date: 2026-05-27" docs/comparisons/hookdeck.md
	@grep -q "Verification date: 2026-05-27" docs/comparisons/svix.md
	@grep -q "Verification date: 2026-05-27" docs/comparisons/convoy.md
	@grep -q "Exactly-Once Webhooks" docs/articles/exactly-once-webhooks.md
	@grep -q "Building A Webhook Incident Report" docs/articles/webhook-incident-report.md
	@grep -q "Webhook Failure Modes" docs/articles/webhook-failure-modes.md
	@grep -q "Launch Copy Templates" docs/launch-copy.md
	@grep -q "Launch Metrics Plan" docs/launch-metrics.md
	@grep -q "Pilot Feedback Template" docs/pilot-feedback-template.md
	@grep -q "Roadmap Intake Policy" docs/roadmap-intake-policy.md
	@grep -q "Pilot Review Checklist" docs/pilot-review-checklist.md
	@grep -q "Configuration Reference" docs/configuration.md
	@grep -q "Feature Behavior Reference" docs/feature-behavior.md
	@grep -q "Security Promise" docs/security-promise.md
	@grep -q "Stability And Compatibility Policy" docs/stability.md
	@grep -q "Performance Envelope" docs/performance-envelope.md
	@grep -q "Provider Conformance Matrix" docs/provider-conformance.md
	@grep -q "Day-2 Operations Guide" docs/day-2-operations.md
	@grep -q "Observability Examples" docs/observability.md
	@grep -q "Provider Claim Freshness" docs/documentation-maintenance.md
	@grep -q "Documentation Review Checklist" docs/documentation-maintenance.md
	@grep -q "CLI" docs/cli.md
	@grep -q "Deployment Posture" docs/deployment.md
	@grep -q "Schema And Migration Operations" docs/schema-migrations.md
	@grep -q "docs/security-promise.md" docs/documentation-maintenance.md
	@grep -q "External Review Scope Template" docs/external-review-scope.md
	@grep -q "External Review Findings Template" docs/external-review-findings-template.md
	@grep -q "External Review Accepted Risks" docs/external-review-accepted-risks.md

static-site-check: ## Check static landing page assets
	@test -f site/index.html
	@test -f site/styles.css
	@grep -q "Self-hosted webhook evidence infrastructure" site/index.html
	@grep -q "Try the self-hosted quickstart" site/index.html
	@grep -q "Request commercial evaluation" site/index.html
	@grep -q "Review commercial options" site/index.html
	@grep -q "No exactly-once delivery claim" site/index.html
	@! grep -qi "<script" site/index.html

meta-files-check: ## Check governance, licensing, and release-evidence metadata
	@test -f LICENSE
	@grep -q "GNU AFFERO GENERAL PUBLIC LICENSE" LICENSE
	@test -f COMMERCIAL.md
	@test -f SECURITY.md
	@test -f SUPPORT.md
	@test -f CONTRIBUTING.md
	@test -f GOVERNANCE.md
	@test -f TRADEMARKS.md
	@test -f RELEASE_EVIDENCE.md
	@test -f docs/release-evidence-template.md
	@test -f docs/security-review-package.md
	@test -f .dockerignore
	@test -f .golangci.yml
	@grep -q "AGPL-3.0-only" COMMERCIAL.md
	@grep -q "AGPL-3.0-only" CONTRIBUTING.md
	@grep -q "https://www.linkedin.com/in/aatu-harju" SECURITY.md
	@grep -q "Do not include" SECURITY.md
	@grep -q "webhook secrets" SECURITY.md
	@grep -q "raw payloads" SECURITY.md
	@grep -q "no exactly-once delivery" RELEASE_EVIDENCE.md
	@grep -q "no provider-side event completeness" RELEASE_EVIDENCE.md
	@grep -q "compliance" RELEASE_EVIDENCE.md
	@grep -q "live third-party provider" docs/release-evidence-template.md
	@grep -q "make live-postgres-check" README.md
	@grep -q "make live-postgres-check" docs/operations.md
	@grep -q "make live-postgres-check" docs/release-evidence-template.md
	@grep -q "not a certification" RELEASE_EVIDENCE.md
	@grep -q ".refs" .dockerignore
	@grep -q "release-evidence" .dockerignore
	@grep -q "backups" .dockerignore
	@grep -q "gosec" .golangci.yml
	@grep -q "bodyclose" .golangci.yml
	@grep -q "contextcheck" .golangci.yml
	@git ls-files --cached --others --exclude-standard .dockerignore | grep -qx ".dockerignore" || (printf '%s\n' ".dockerignore must be trackable" >&2; exit 1)
	@git ls-files --cached --others --exclude-standard .golangci.yml | grep -qx ".golangci.yml" || (printf '%s\n' ".golangci.yml must be trackable" >&2; exit 1)

fuzz-smoke: ## Run short CI-safe fuzz/property smoke tests
	@$(GO) test ./internal/canonicaljson -run '^$$' -fuzz=Fuzz -fuzztime=$(FUZZTIME)
	@$(GO) test ./internal/adapters/httpapi -run '^$$' -fuzz=Fuzz -fuzztime=$(FUZZTIME)
	@$(GO) test ./pkg/verifier -run '^$$' -fuzz=Fuzz -fuzztime=$(FUZZTIME)
	@$(GO) test ./internal/random -run '^$$' -fuzz=Fuzz -fuzztime=$(FUZZTIME)

perf-smoke: ## Run DB-backed local performance smoke and write sanitized evidence
	@scripts/perf_smoke.sh

release-acceptance: ## Run v3.3 release acceptance evidence checks
	@scripts/release_acceptance.sh

rc-check: ## Run release-candidate core product acceptance checks
	@scripts/rc_acceptance.sh

sdk-generate: ## Refresh committed SDK-ready artifacts from OpenAPI
	@cp openapi.yaml sdk/openapi.yaml
	@printf '%s\n' "SDK artifacts refreshed from openapi.yaml"

sdk-check: ## Validate committed SDK artifacts are present and aligned
	@test -f sdk/openapi.yaml
	@cmp -s openapi.yaml sdk/openapi.yaml
	@test -f sdk/README.md
	@test -f pkg/client/client.go
	@$(GO) test ./pkg/client
	@test -f sdk/python/webhookery/__init__.py
	@PYTHONPATH=sdk/python python3 -m unittest discover -s sdk/python/tests
	@test -f sdk/typescript/src/index.ts
	@tsc -p sdk/typescript/tsconfig.json
	@node --test sdk/typescript/test/client.test.mjs

docs-check: ## Run non-mutating documentation-adjacent checks
	@$(MAKE) openapi-check
	@$(MAKE) test-vectors-check
	@$(MAKE) provider-conformance-check
	@$(MAKE) sdk-check
	@$(MAKE) crypto-inventory
	@$(MAKE) deployment-profile-check
	@$(MAKE) collections-check
	@$(MAKE) documentation-structure-check
	@$(MAKE) static-site-check
	@$(MAKE) meta-files-check

compose-up: ## Start local dependencies and API
	@docker compose up --build

compose-down: ## Stop local dependencies
	@docker compose down --remove-orphans

migrate: ## Run Postgres migrations using DATABASE_URL
	@$(GO) run ./cmd/whcp migrate -dir migrations up

live-postgres-check: ## Run the live Postgres quality gate using WEBHOOKERY_TEST_DATABASE_URL
	@test -n "$$WEBHOOKERY_TEST_DATABASE_URL" || (printf '%s\n' "WEBHOOKERY_TEST_DATABASE_URL is required; start postgres with docker compose up -d postgres" >&2; exit 2)
	@$(GO) test ./internal/adapters/postgres -run 'TestPostgres|TestMigration' -count=1

postgres-integration-test: live-postgres-check ## Compatibility alias for live-postgres-check

redis-integration-test: ## Run live Redis edge-store integration tests
	@test -n "$$WEBHOOKERY_TEST_REDIS_ADDR" || (printf '%s\n' "WEBHOOKERY_TEST_REDIS_ADDR is required; start redis with docker compose up -d redis" >&2; exit 2)
	@$(GO) test ./internal/adapters/redisstore -run 'TestRedisStoreIntegration' -count=1

fast-check: ## Run non-mutating checks
	@$(GO) test ./...
	@$(MAKE) openapi-check
	@$(MAKE) test-vectors-check
	@$(MAKE) crypto-inventory
	@$(MAKE) deployment-profile-check
	@$(MAKE) collections-check
	@$(MAKE) documentation-structure-check
	@$(MAKE) static-site-check
	@$(MAKE) meta-files-check
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
	@$(MAKE) documentation-structure-check
	@$(MAKE) static-site-check
	@$(MAKE) meta-files-check
	@$(MAKE) sdk-check

clean: ## Clean local test artifacts
	@$(GO) clean -testcache
	@rm -f coverage.out
