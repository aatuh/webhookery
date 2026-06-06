GO ?= go
GOTOOLCHAIN ?= local
export GOTOOLCHAIN

TOOLS := golangci-lint gosec govulncheck
GOLANGCI_LINT_VERSION ?= v2.11.4
GOSEC_VERSION ?= v2.25.0
GOVULNCHECK_VERSION ?= v1.2.0
FUZZTIME ?= 5s
COVERAGE_MIN ?= 50.0
COVERAGE_DB_MIN ?= 76.0

.PHONY: help tools fmt lint vuln gosec test test-race coverage coverage-check coverage-db coverage-db-check openapi-check openapi-reference-generate openapi-reference-check test-vectors-check provider-conformance-check provider-proof-check crypto-inventory deployment-profile-check collections-check documentation-structure-check failure-drills-check demo-media-check static-site-check meta-files-check release-assets-check fuzz-smoke perf-smoke demo-media restore-drill sdk-generate sdk-check docs-check release-acceptance rc-check compose-up compose-down migrate live-postgres-check postgres-integration-test redis-integration-test fast-check finalize clean

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

coverage-check: ## Enforce the local coverage floor
	@$(GO) test ./... -coverprofile=coverage.out >/dev/null
	@total="$$( $(GO) tool cover -func=coverage.out | awk '/^total:/ { gsub("%", "", $$3); print $$3 }' )"; \
	awk -v total="$$total" -v min="$(COVERAGE_MIN)" 'BEGIN { if ((total + 0) < (min + 0)) { printf "coverage %.1f%% is below %.1f%%\n", total, min > "/dev/stderr"; exit 1 } }'; \
	printf 'coverage %.1f%% meets %.1f%% floor\n' "$$total" "$(COVERAGE_MIN)"

coverage-db: ## Run DB-backed coverage using WEBHOOKERY_TEST_DATABASE_URL
	@test -n "$$WEBHOOKERY_TEST_DATABASE_URL" || (printf '%s\n' "WEBHOOKERY_TEST_DATABASE_URL is required; start postgres with docker compose up -d postgres" >&2; exit 2)
	@$(GO) test -p 1 ./... -coverprofile=coverage-db.out
	@$(GO) tool cover -func=coverage-db.out

coverage-db-check: ## Enforce the DB-backed coverage floor
	@test -n "$$WEBHOOKERY_TEST_DATABASE_URL" || (printf '%s\n' "WEBHOOKERY_TEST_DATABASE_URL is required; start postgres with docker compose up -d postgres" >&2; exit 2)
	@$(GO) test -p 1 ./... -coverprofile=coverage-db.out >/dev/null
	@total="$$( $(GO) tool cover -func=coverage-db.out | awk '/^total:/ { gsub("%", "", $$3); print $$3 }' )"; \
	awk -v total="$$total" -v min="$(COVERAGE_DB_MIN)" 'BEGIN { if ((total + 0) < (min + 0)) { printf "DB-backed coverage %.1f%% is below %.1f%%\n", total, min > "/dev/stderr"; exit 1 } }'; \
	printf 'DB-backed coverage %.1f%% meets %.1f%% floor\n' "$$total" "$(COVERAGE_DB_MIN)"

openapi-check: ## Validate OpenAPI source and route contract smoke tests
	@test -f openapi.yaml
	@$(GO) test ./internal/adapters/httpapi -run 'TestOpenAPI|TestRoute'

openapi-reference-generate: ## Regenerate rendered OpenAPI reference artifacts
	@$(GO) run ./scripts/openapi_reference.go \
		-input openapi.yaml \
		-html docs/openapi/index.html \
		-matrix docs/reference/api-contract-matrix.md \
		-summary docs/reference/openapi.md

openapi-reference-check: ## Validate rendered OpenAPI reference artifacts are current
	@tmp_dir="$$(mktemp -d)"; \
	trap 'rm -rf "$$tmp_dir"' EXIT; \
	$(GO) run ./scripts/openapi_reference.go \
		-input openapi.yaml \
		-html "$$tmp_dir/index.html" \
		-matrix "$$tmp_dir/api-contract-matrix.md" \
		-summary "$$tmp_dir/openapi.md"; \
	cmp -s "$$tmp_dir/index.html" docs/openapi/index.html || (printf '%s\n' "docs/openapi/index.html is stale; run make openapi-reference-generate" >&2; exit 1); \
	cmp -s "$$tmp_dir/api-contract-matrix.md" docs/reference/api-contract-matrix.md || (printf '%s\n' "docs/reference/api-contract-matrix.md is stale; run make openapi-reference-generate" >&2; exit 1); \
	cmp -s "$$tmp_dir/openapi.md" docs/reference/openapi.md || (printf '%s\n' "docs/reference/openapi.md is stale; run make openapi-reference-generate" >&2; exit 1)

test-vectors-check: ## Validate committed public audit test vectors
	@$(GO) test ./internal/provider -run TestProviderSignatureVectors

provider-conformance-check: ## Validate provider conformance matrix and local vectors
	@scripts/provider_conformance_check.sh

provider-proof-check: ## Validate manual live-provider proof guide freshness
	@scripts/provider_proof_check.sh

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
	@test -x scripts/restore_drill.sh
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
	@test -f docs/reference/source-of-truth.md
	@test -f docs/reference/openapi.md
	@test -f docs/openapi/index.html
	@test -f docs/reference/api-contract-matrix.md
	@test -f docs/reference/release-evidence-index.md
	@test -f docs/reference/release-validation.md
	@test -f docs/evaluator-quickstart.md
	@test -f docs/why-webhookery.md
	@test -f docs/evidence-bundle-profiles.md
	@test -f docs/use-cases/stripe-payment-investigation.md
	@test -f docs/use-cases/github-automation-webhooks.md
	@test -f docs/use-cases/shopify-order-webhooks.md
	@test -f docs/use-cases/internal-integration-replay.md
	@test -f docs/demo-media-checklist.md
	@test -f docs/releases/v0.1.0-rc1.md
	@test -f docs/releases/v0.2.0-pilot.md
	@test -f docs/release-evidence-sample.md
	@test -f docs/production-rc-checklist.md
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
	@test -f docs/articles/self-hosted-webhook-gateway-architecture.md
	@test -f docs/articles/webhook-security-review-checklist.md
	@test -f docs/launch-copy.md
	@test -f docs/launch-metrics.md
	@test -f docs/customer-discovery-notes-template.md
	@test -f docs/pilot-feedback-template.md
	@test -f docs/roadmap-intake-policy.md
	@test -f docs/pilot-review-checklist.md
	@test -f .github/ISSUE_TEMPLATE/evaluator-feedback.yml
	@test -f docs/configuration.md
	@test -f docs/feature-behavior.md
	@test -f docs/security-promise.md
	@test -f docs/error-codes.md
	@test -f docs/stability.md
	@test -f docs/performance-envelope.md
	@test -f docs/provider-conformance.md
	@test -f docs/provider-conformance.manifest.json
	@test -f docs/provider-proof-manifest.json
	@test -f docs/providers/stripe.md
	@test -f docs/providers/github.md
	@test -f docs/providers/shopify.md
	@test -f docs/live-provider-proof/stripe.md
	@test -f docs/live-provider-proof/github.md
	@test -f docs/live-provider-proof/shopify.md
	@test -f docs/live-provider-proof/stripe-redaction-policy.md
	@test -f docs/live-provider-proof/samples/stripe-incident-report.redacted.md
	@test -f docs/live-provider-proof/samples/github-incident-report.redacted.md
	@test -f docs/live-provider-proof/samples/shopify-incident-report.redacted.md
	@test -f docs/day-2-operations.md
	@test -f docs/observability.md
	@test -f docs/failure-drills.md
	@test -f docs/documentation-maintenance.md
	@test -f docs/cli.md
	@test -f docs/deployment.md
	@test -f docs/schema-migrations.md
	@test -f docs/security-review-package.md
	@test -f docs/external-review-package.md
	@test -f docs/external-review-scope.md
	@test -f docs/external-review-findings-template.md
	@test -f docs/external-review-accepted-risks.md
	@test -f docs/release-evidence-template.md
	@test -f release/current.json
	@grep -q "Documentation Map" docs/index.md
	@grep -q "Source Of Truth" docs/reference/source-of-truth.md
	@grep -q "OpenAPI Reference" docs/reference/openapi.md
	@grep -q "Webhookery API Contract Matrix" docs/reference/api-contract-matrix.md
	@grep -q "Release Evidence Index" docs/reference/release-evidence-index.md
	@grep -q "Release Validation" docs/reference/release-validation.md
	@grep -q "webhookery-current-release.v1" release/current.json
	@grep -q "Why Webhookery" docs/why-webhookery.md
	@grep -q "Evidence Bundle Profiles" docs/evidence-bundle-profiles.md
	@grep -q "Stripe Payment Investigation" docs/use-cases/stripe-payment-investigation.md
	@grep -q "GitHub Automation Webhooks" docs/use-cases/github-automation-webhooks.md
	@grep -q "Shopify Order Webhooks" docs/use-cases/shopify-order-webhooks.md
	@grep -q "Internal Integration Replay" docs/use-cases/internal-integration-replay.md
	@grep -q "docs/evaluator-quickstart.md" README.md
	@grep -q "docs/why-webhookery.md" README.md
	@grep -q "docs/reference/api-contract-matrix.md" README.md
	@grep -q "docs/reference/release-evidence-index.md" README.md
	@grep -q "release/current.json" README.md
	@grep -q "docs/evidence-bundle-profiles.md" README.md
	@grep -q "examples/webhook-evidence-demo" README.md
	@grep -q "site/index.html" README.md
	@grep -q "docs/commercial-evaluation.md" README.md
	@grep -q "docs/production-rc-checklist.md" README.md
	@grep -q "docs/releases/v0.2.0-pilot.md" README.md
	@grep -q "docs/customer-discovery-notes-template.md" README.md
	@grep -q "Evaluator Quickstart" docs/evaluator-quickstart.md
	@grep -q "Demo Media Checklist" docs/demo-media-checklist.md
	@grep -q "v0.1.0-rc1" CHANGELOG.md
	@grep -q "release candidate" docs/releases/v0.1.0-rc1.md
	@grep -q "exactly-once delivery" docs/releases/v0.1.0-rc1.md
	@grep -q "provider-side event completeness" docs/releases/v0.1.0-rc1.md
	@grep -q "v0.2.0 Pilot Readiness Checklist" docs/releases/v0.2.0-pilot.md
	@grep -q "make provider-proof-check" docs/releases/v0.2.0-pilot.md
	@grep -q "raw payload bodies" .github/ISSUE_TEMPLATE/evaluator-feedback.yml
	@grep -q "roadmap-intake-policy.md" .github/ISSUE_TEMPLATE/evaluator-feedback.yml
	@grep -q "no secrets" .github/ISSUE_TEMPLATE/evaluator-feedback.yml
	@grep -q "Commercial Evaluation" docs/commercial-evaluation.md
	@grep -q "Production Readiness Review" docs/production-readiness-review.md
	@grep -q "Support Packages" docs/support-packages.md
	@grep -q "Build Vs Buy" docs/comparisons/build-vs-buy.md
	@grep -q "Verification date: 2026-06-04" docs/comparisons/hookdeck.md
	@grep -q "Verification date: 2026-06-04" docs/comparisons/svix.md
	@grep -q "Verification date: 2026-06-04" docs/comparisons/convoy.md
	@grep -q "Exactly-Once Webhooks" docs/articles/exactly-once-webhooks.md
	@grep -q "Building A Webhook Incident Report" docs/articles/webhook-incident-report.md
	@grep -q "Webhook Failure Modes" docs/articles/webhook-failure-modes.md
	@grep -q "Self-Hosted Webhook Gateway Architecture" docs/articles/self-hosted-webhook-gateway-architecture.md
	@grep -q "Webhook Security Review Checklist" docs/articles/webhook-security-review-checklist.md
	@grep -q "Release Evidence Sample" docs/release-evidence-sample.md
	@grep -q "Production RC Checklist" docs/production-rc-checklist.md
	@grep -q "Launch Copy Templates" docs/launch-copy.md
	@grep -q "Launch Metrics Plan" docs/launch-metrics.md
	@grep -q "Customer Discovery Notes Template" docs/customer-discovery-notes-template.md
	@grep -q "Pilot Feedback Template" docs/pilot-feedback-template.md
	@grep -q "Roadmap Intake Policy" docs/roadmap-intake-policy.md
	@grep -q "Pilot Review Checklist" docs/pilot-review-checklist.md
	@grep -q "Configuration Reference" docs/configuration.md
	@grep -q "WEBHOOKERY_PILOT_ALLOW_RECEIVER_CHECK" docs/configuration.md
	@grep -q "Feature Behavior Reference" docs/feature-behavior.md
	@grep -q "Security Promise" docs/security-promise.md
	@grep -q "WEBHOOKERY_PROVIDER_SIGNATURE_INVALID" docs/error-codes.md
	@grep -q "Stability And Compatibility Policy" docs/stability.md
	@grep -q "Performance Envelope" docs/performance-envelope.md
	@grep -q "Provider Conformance Matrix" docs/provider-conformance.md
	@grep -q "docs/live-provider-proof/stripe.md" README.md
	@grep -q "docs/live-provider-proof/github.md" README.md
	@grep -q "docs/live-provider-proof/shopify.md" README.md
	@grep -q "docs/live-provider-proof/stripe.md" docs/evaluator-quickstart.md
	@grep -q "docs/live-provider-proof/github.md" docs/evaluator-quickstart.md
	@grep -q "docs/live-provider-proof/shopify.md" docs/evaluator-quickstart.md
	@grep -q "Stripe Operator Guide" docs/providers/stripe.md
	@grep -q "GitHub Operator Guide" docs/providers/github.md
	@grep -q "Shopify Operator Guide" docs/providers/shopify.md
	@grep -q "not provider certification" docs/live-provider-proof/stripe.md
	@grep -q "not provider certification" docs/live-provider-proof/github.md
	@grep -q "not provider certification" docs/live-provider-proof/shopify.md
	@grep -q "provider-proof-v1" docs/provider-proof-manifest.json
	@grep -q "Day-2 Operations Guide" docs/day-2-operations.md
	@grep -q "Observability Examples" docs/observability.md
	@grep -q "Failure Drills" docs/failure-drills.md
	@grep -q "Provider Claim Freshness" docs/documentation-maintenance.md
	@grep -q "Documentation Review Checklist" docs/documentation-maintenance.md
	@grep -q "CLI" docs/cli.md
	@grep -q "doctor pilot --no-network" docs/cli.md
	@grep -q "Pilot Doctor Runbook" docs/operations.md
	@grep -q "Deployment Posture" docs/deployment.md
	@grep -q "Schema And Migration Operations" docs/schema-migrations.md
	@grep -q "docs/security-promise.md" docs/documentation-maintenance.md
	@grep -q "External Review Scope Template" docs/external-review-scope.md
	@grep -q "External Review Package" docs/external-review-package.md
	@grep -q "External Review Findings Template" docs/external-review-findings-template.md
	@grep -q "External Review Accepted Risks" docs/external-review-accepted-risks.md

failure-drills-check: ## Check failure-drill scripts and sanitized plan generation
	@sh -n scripts/failure_drills.sh
	@sh -n scripts/demo_media.sh
	@sh -n scripts/restore_drill.sh
	@test -x scripts/failure_drills.sh
	@test -x scripts/demo_media.sh
	@test -x scripts/restore_drill.sh
	@scripts/failure_drills.sh list | grep -q "downstream-receiver-fails"
	@tmp_dir="$$(mktemp -d)"; scripts/failure_drills.sh plan --output "$$tmp_dir" >/dev/null; grep -q "postgres-unavailable-before-capture" "$$tmp_dir/failure-drills.md"; rm -rf "$$tmp_dir"

demo-media-check: ## Check demo media script and sanitized outline generation
	@sh -n scripts/demo_media.sh
	@test -x scripts/demo_media.sh
	@tmp_dir="$$(mktemp -d)"; scripts/demo_media.sh plan --output "$$tmp_dir" >/dev/null; grep -q "Webhookery Demo Media Script" "$$tmp_dir/demo-script.md"; grep -q "Do not record" "$$tmp_dir/demo-script.md"; rm -rf "$$tmp_dir"

static-site-check: ## Check static landing page assets
	@test -f site/index.html
	@test -f site/styles.css
	@test -f .github/workflows/site-pages.yml
	@grep -q "Self-hosted webhook evidence infrastructure" site/index.html
	@grep -q "Try the self-hosted quickstart" site/index.html
	@grep -q "Request commercial evaluation" site/index.html
	@grep -q "Review commercial options" site/index.html
	@grep -q "No exactly-once delivery claim" site/index.html
	@grep -q "github-pages" .github/workflows/site-pages.yml
	@! grep -qi "<script" site/index.html

meta-files-check: ## Check governance, licensing, and release-evidence metadata
	@test -f LICENSE
	@grep -q "GNU AFFERO GENERAL PUBLIC LICENSE" LICENSE
	@test -f COMMERCIAL.md
	@test -f SECURITY.md
	@test -f SUPPORT.md
	@test -f CONTRIBUTING.md
	@test -f GOVERNANCE.md
	@test -f CODE_OF_CONDUCT.md
	@test -f CODEOWNERS
	@test -f TRADEMARKS.md
	@test -f RELEASE_EVIDENCE.md
	@test -x scripts/release_assets.sh
	@test -f .github/dependabot.yml
	@test -f .github/pull_request_template.md
	@test -f .github/ISSUE_TEMPLATE.md
	@test -f .github/ISSUE_TEMPLATE/config.yml
	@test -f .github/ISSUE_TEMPLATE/bug_report.yml
	@test -f .github/ISSUE_TEMPLATE/docs.yml
	@test -f .github/ISSUE_TEMPLATE/feature_request.yml
	@test -f .github/ISSUE_TEMPLATE/production_support.yml
	@test -f .github/ISSUE_TEMPLATE/evaluator-feedback.yml
	@test -f .github/workflows/ci.yml
	@test -f .github/workflows/security.yml
	@test -f .github/workflows/integration.yml
	@test -f .github/workflows/fuzz.yml
	@test -f .github/workflows/release.yml
	@test -f .github/workflows/codeql.yml
	@test -f .github/workflows/scorecard.yml
	@test -f .github/workflows/scorecard-sarif.yml
	@test -f docs/release-evidence-template.md
	@test -f docs/security-review-package.md
	@test -f .dockerignore
	@test -f .golangci.yml
	@grep -q "AGPL-3.0-only" COMMERCIAL.md
	@grep -q "AGPL-3.0-only" CONTRIBUTING.md
	@grep -q "Contributor Covenant" CODE_OF_CONDUCT.md
	@grep -q "@aatuh" CODEOWNERS
	@grep -q "https://www.linkedin.com/in/aatu-harju" SECURITY.md
	@grep -q "Do not include" SECURITY.md
	@grep -q "webhook secrets" SECURITY.md
	@grep -q "raw payloads" SECURITY.md
	@grep -q "no exactly-once delivery" RELEASE_EVIDENCE.md
	@grep -q "no provider-side event completeness" RELEASE_EVIDENCE.md
	@grep -q "compliance" RELEASE_EVIDENCE.md
	@grep -q "live third-party provider" docs/release-evidence-template.md
	@grep -q "make live-postgres-check" README.md
	@grep -q "doctor pilot --no-network" README.md
	@grep -q "actions/workflows/ci.yml/badge.svg" README.md
	@grep -q "actions/workflows/security.yml/badge.svg" README.md
	@grep -q "actions/workflows/integration.yml/badge.svg" README.md
	@grep -q "actions/workflows/fuzz.yml/badge.svg" README.md
	@grep -q "actions/workflows/codeql.yml/badge.svg" README.md
	@grep -q "actions/workflows/scorecard.yml/badge.svg" README.md
	@grep -q "local%20coverage-50%25+" README.md
	@grep -q "db%20coverage-76%25+" README.md
	@op_count="$$(grep -c '^[[:space:]]*operationId:' openapi.yaml)"; grep -q "OpenAPI-$${op_count}%20operations" README.md
	@grep -q "make live-postgres-check" docs/operations.md
	@grep -q "make live-postgres-check" docs/release-evidence-template.md
	@grep -q "not a certification" RELEASE_EVIDENCE.md
	@grep -q ".refs" .dockerignore
	@grep -q "release-evidence" .dockerignore
	@grep -q "backups" .dockerignore
	@grep -q "live-proof-private" .dockerignore
	@grep -q "launch-metrics-private" .dockerignore
	@grep -q "live-proof-private" .gitignore
	@grep -q "launch-metrics-private" .gitignore
	@grep -q "gomod" .github/dependabot.yml
	@grep -q "github-actions" .github/dependabot.yml
	@grep -q "docker" .github/dependabot.yml
	@grep -q "terraform" .github/dependabot.yml
	@grep -q "CodeQL Analyze" .github/workflows/codeql.yml
	@grep -q "security-events: write" .github/workflows/codeql.yml
	@grep -q "OpenSSF Scorecard" .github/workflows/scorecard.yml
	@grep -q "OpenSSF Scorecard SARIF" .github/workflows/scorecard-sarif.yml
	@grep -q "security-events: write" .github/workflows/scorecard-sarif.yml
	@grep -q "scripts/release_assets.sh" .github/workflows/release.yml
	@grep -q "gh release upload" .github/workflows/release.yml
	@grep -q "make coverage-check" .github/workflows/ci.yml
	@grep -q "make coverage-check" .github/workflows/release.yml
	@grep -q "make coverage-db-check" .github/workflows/integration.yml
	@grep -q "make coverage-db-check" .github/workflows/release.yml
	@grep -q "webhookery-release-manifest.json" scripts/release_assets.sh
	@grep -q "webhookery-release-provenance.intoto.jsonl" scripts/release_assets.sh
	@grep -q "release asset summary" scripts/release_assets.sh
	@grep -q "No-secrets confirmation" .github/ISSUE_TEMPLATE/bug_report.yml
	@grep -q "No-secrets confirmation" .github/ISSUE_TEMPLATE/production_support.yml
	@grep -q "exactly-once delivery" .github/ISSUE_TEMPLATE/docs.yml
	@grep -q "arbitrary code plugins" .github/ISSUE_TEMPLATE/feature_request.yml
	@grep -q "Sensitive Data Check" .github/pull_request_template.md
	@grep -q "gosec" .golangci.yml
	@grep -q "bodyclose" .golangci.yml
	@grep -q "contextcheck" .golangci.yml
	@git ls-files --cached --others --exclude-standard .dockerignore | grep -qx ".dockerignore" || (printf '%s\n' ".dockerignore must be trackable" >&2; exit 1)
	@git ls-files --cached --others --exclude-standard .golangci.yml | grep -qx ".golangci.yml" || (printf '%s\n' ".golangci.yml must be trackable" >&2; exit 1)

release-assets-check: ## Smoke-test release asset packaging metadata
	@bash -n scripts/release_assets.sh
	@tmp_dir="$$(mktemp -d)"; \
	trap 'rm -rf "$$tmp_dir"' EXIT; \
	WEBHOOKERY_RELEASE_ASSET_PLATFORMS=linux/amd64 scripts/release_assets.sh v0.0.0-local "$$tmp_dir" "$$(git rev-parse HEAD)" >/dev/null; \
	test -f "$$tmp_dir/webhookery_v0.0.0-local_linux_amd64.tar.gz"; \
	test -f "$$tmp_dir/SHA256SUMS"; \
	test -f "$$tmp_dir/openapi.yaml"; \
	test -f "$$tmp_dir/openapi.sha256"; \
	test -f "$$tmp_dir/migrations.sha256"; \
	test -f "$$tmp_dir/release-check-summary.txt"; \
	test -f "$$tmp_dir/webhookery-release-manifest.json"; \
	test -f "$$tmp_dir/webhookery-release-provenance.json"; \
	test -f "$$tmp_dir/webhookery-release-provenance.intoto.jsonl"; \
	(cd "$$tmp_dir" && sha256sum -c SHA256SUMS >/dev/null); \
	grep -q "webhookery-release-manifest.v1" "$$tmp_dir/webhookery-release-manifest.json"; \
	grep -q "not exactly-once delivery proof" "$$tmp_dir/webhookery-release-manifest.json"

fuzz-smoke: ## Run short CI-safe fuzz/property smoke tests
	@$(GO) test ./internal/canonicaljson -run '^$$' -fuzz=Fuzz -fuzztime=$(FUZZTIME)
	@$(GO) test ./internal/adapters/httpapi -run '^$$' -fuzz=Fuzz -fuzztime=$(FUZZTIME)
	@$(GO) test ./pkg/verifier -run '^$$' -fuzz=Fuzz -fuzztime=$(FUZZTIME)
	@$(GO) test ./internal/random -run '^$$' -fuzz=Fuzz -fuzztime=$(FUZZTIME)

perf-smoke: ## Run DB-backed local performance smoke and write sanitized evidence
	@scripts/perf_smoke.sh

demo-media: ## Prepare deterministic local demo media state
	@scripts/demo_media.sh run

restore-drill: ## Run destructive restore drill against WEBHOOKERY_RESTORE_DRILL_DATABASE_URL
	@scripts/restore_drill.sh

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
	@test -f sdk/examples/evidence-workflow-go/main.go
	@test -f sdk/typescript/examples/evidence-workflow.ts
	@test -f pkg/client/client.go
	@$(GO) test ./pkg/client
	@$(GO) test ./sdk/examples/evidence-workflow-go
	@test -f sdk/python/webhookery/__init__.py
	@PYTHONPATH=sdk/python python3 -m unittest discover -s sdk/python/tests
	@test -f sdk/typescript/src/index.ts
	@tsc -p sdk/typescript/tsconfig.json
	@node --test sdk/typescript/test/client.test.mjs

docs-check: ## Run non-mutating documentation-adjacent checks
	@$(MAKE) openapi-check
	@$(MAKE) openapi-reference-check
	@$(MAKE) test-vectors-check
	@$(MAKE) provider-conformance-check
	@$(MAKE) provider-proof-check
	@$(MAKE) sdk-check
	@$(MAKE) crypto-inventory
	@$(MAKE) deployment-profile-check
	@$(MAKE) collections-check
	@$(MAKE) documentation-structure-check
	@$(MAKE) failure-drills-check
	@$(MAKE) demo-media-check
	@$(MAKE) static-site-check
	@$(MAKE) meta-files-check
	@$(MAKE) release-assets-check

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
	@$(MAKE) openapi-reference-check
	@$(MAKE) test-vectors-check
	@$(MAKE) crypto-inventory
	@$(MAKE) deployment-profile-check
	@$(MAKE) collections-check
	@$(MAKE) documentation-structure-check
	@$(MAKE) failure-drills-check
	@$(MAKE) demo-media-check
	@$(MAKE) static-site-check
	@$(MAKE) meta-files-check
	@$(MAKE) release-assets-check
	@$(MAKE) sdk-check

finalize: ## Thorough validity check
	@$(MAKE) fmt
	@$(MAKE) lint
	@$(MAKE) vuln
	@$(MAKE) gosec
	@$(MAKE) test
	@$(MAKE) test-race
	@$(MAKE) openapi-check
	@$(MAKE) openapi-reference-check
	@$(MAKE) test-vectors-check
	@$(MAKE) crypto-inventory
	@$(MAKE) deployment-profile-check
	@$(MAKE) collections-check
	@$(MAKE) documentation-structure-check
	@$(MAKE) failure-drills-check
	@$(MAKE) demo-media-check
	@$(MAKE) static-site-check
	@$(MAKE) meta-files-check
	@$(MAKE) release-assets-check
	@$(MAKE) sdk-check

clean: ## Clean local test artifacts
	@$(GO) clean -testcache
	@rm -f coverage.out coverage-db.out
