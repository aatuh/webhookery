#!/usr/bin/env sh
set -eu

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"

# Keep release acceptance's baseline gate non-live and deterministic. Workflows
# may provide WEBHOOKERY_TEST_DATABASE_URL for later RC/performance checks; do
# not let the broad package test fan out DB-backed E2E migrations in parallel.
WEBHOOKERY_TEST_DATABASE_URL= WEBHOOKERY_RC_RESTORE_DATABASE_URL= make fast-check

test -f LICENSE
test -f CHANGELOG.md
grep -q "GNU AFFERO GENERAL PUBLIC LICENSE" LICENSE
test -f COMMERCIAL.md
test -f SECURITY.md
test -f SUPPORT.md
test -f CONTRIBUTING.md
test -f GOVERNANCE.md
test -f TRADEMARKS.md
test -f RELEASE_EVIDENCE.md
test -f docs/release-evidence-template.md
test -f docs/release-evidence-sample.md
test -f docs/production-rc-checklist.md
test -f docs/releases/v0.1.0-rc1.md
test -f docs/security-review-package.md
test -f docs/external-review-package.md
test -f docs/external-review-scope.md
test -f docs/external-review-findings-template.md
test -f docs/external-review-accepted-risks.md
test -f docs/provider-conformance.md
test -f docs/provider-conformance.manifest.json
test -f docs/provider-proof-manifest.json
test -f docs/providers/stripe.md
test -f docs/providers/github.md
test -f docs/providers/shopify.md
test -f docs/live-provider-proof/stripe.md
test -f docs/live-provider-proof/github.md
test -f docs/live-provider-proof/shopify.md
test -f docs/live-provider-proof/stripe-redaction-policy.md
test -f docs/live-provider-proof/samples/stripe-incident-report.redacted.md
test -f docs/live-provider-proof/samples/github-incident-report.redacted.md
test -f docs/live-provider-proof/samples/shopify-incident-report.redacted.md
test -f docs/evaluator-quickstart.md
test -f examples/webhook-evidence-demo/run.sh
test -f site/index.html
test -f docs/commercial-evaluation.md
test -f docs/production-readiness-review.md
test -f docs/support-packages.md
test -f docs/comparisons/build-vs-buy.md
test -f docs/articles/exactly-once-webhooks.md
test -f docs/articles/self-hosted-webhook-gateway-architecture.md
test -f docs/articles/webhook-security-review-checklist.md
test -f docs/launch-copy.md
test -f docs/launch-metrics.md
test -f docs/customer-discovery-notes-template.md
test -f docs/pilot-feedback-template.md
test -f docs/roadmap-intake-policy.md
test -f docs/pilot-review-checklist.md
test -f .dockerignore
test -f .golangci.yml
grep -q "AGPL-3.0-only" COMMERCIAL.md
grep -q "v0.1.0-rc1" CHANGELOG.md
grep -q "release candidate" docs/releases/v0.1.0-rc1.md
grep -q "make rc-check" docs/releases/v0.1.0-rc1.md
grep -q "fake/local providers" docs/releases/v0.1.0-rc1.md
grep -q "exactly-once delivery" docs/releases/v0.1.0-rc1.md
grep -q "provider-side event completeness" docs/releases/v0.1.0-rc1.md
grep -q "AGPL-3.0-only" CONTRIBUTING.md
grep -q "https://www.linkedin.com/in/aatu-harju" SECURITY.md
grep -q "webhook secrets" SECURITY.md
grep -q "raw payloads" SECURITY.md
grep -q "no exactly-once delivery" RELEASE_EVIDENCE.md
grep -q "no provider-side event completeness" RELEASE_EVIDENCE.md
grep -q "compliance" RELEASE_EVIDENCE.md
grep -q "not a certification" RELEASE_EVIDENCE.md
grep -q "live third-party provider" docs/release-evidence-template.md
grep -q "Release Evidence Sample" docs/release-evidence-sample.md
grep -q "Production RC Checklist" docs/production-rc-checklist.md
grep -q "exactly-once delivery" docs/production-rc-checklist.md
grep -q "External Review" docs/release-evidence-template.md
grep -q "Branch Protection" docs/release-evidence-template.md
grep -q "External Review Package" docs/external-review-package.md
grep -q "accepted_risk" docs/external-review-accepted-risks.md
grep -q "External Review Scope Template" docs/external-review-scope.md
grep -q "External Review Findings Template" docs/external-review-findings-template.md
grep -q "Provider Conformance Matrix" docs/provider-conformance.md
grep -q "no provider-side completeness guarantee" docs/provider-conformance.md
grep -q "docs/live-provider-proof/stripe.md" docs/provider-conformance.md
grep -q "docs/live-provider-proof/github.md" docs/provider-conformance.md
grep -q "docs/live-provider-proof/shopify.md" docs/provider-conformance.md
grep -q "not provider certification" docs/live-provider-proof/stripe.md
grep -q "not provider certification" docs/live-provider-proof/github.md
grep -q "not provider certification" docs/live-provider-proof/shopify.md
grep -q "provider-proof-v1" docs/provider-proof-manifest.json
grep -q "Evaluator Quickstart" docs/evaluator-quickstart.md
grep -q "webhook evidence demo" examples/webhook-evidence-demo/README.md
grep -q "Self-hosted webhook evidence infrastructure" site/index.html
grep -q "EUR 490-1,000" docs/commercial-evaluation.md
grep -q "Production Readiness Review" docs/production-readiness-review.md
grep -q "Support Packages" docs/support-packages.md
grep -q "Build Vs Buy" docs/comparisons/build-vs-buy.md
grep -q "Exactly-Once Webhooks" docs/articles/exactly-once-webhooks.md
grep -q "Self-Hosted Webhook Gateway Architecture" docs/articles/self-hosted-webhook-gateway-architecture.md
grep -q "Webhook Security Review Checklist" docs/articles/webhook-security-review-checklist.md
grep -q "Launch Copy Templates" docs/launch-copy.md
grep -q "Launch Metrics Plan" docs/launch-metrics.md
grep -q "Customer Discovery Notes Template" docs/customer-discovery-notes-template.md
grep -q "Pilot Feedback Template" docs/pilot-feedback-template.md
grep -q "Roadmap Intake Policy" docs/roadmap-intake-policy.md
grep -q "Pilot Review Checklist" docs/pilot-review-checklist.md
grep -q ".refs" .dockerignore
grep -q "release-evidence" .dockerignore
grep -q "backups" .dockerignore

test -f Dockerfile
test -f docker-compose.yml
test -f deploy/kubernetes/kustomization.yaml
test -f deploy/kubernetes/networkpolicy.example.yaml
test -f deploy/helm/webhookery/Chart.yaml
test -f deploy/helm/webhookery/values-production.example.yaml
test -f deploy/observability/prometheus-rules.example.yaml
test -f deploy/terraform/webhookery-helm/main.tf
grep -q "runAsNonRoot: true" deploy/kubernetes/api-deployment.yaml
grep -q "runAsNonRoot: true" deploy/helm/webhookery/values.yaml
grep -q "helm_release" deploy/terraform/webhookery-helm/main.tf
test -f .env.example
test -f .api.env.example
test -f collections/postman/webhookery.postman_collection.json
test -f collections/bruno/Webhookery/bruno.json
test -x scripts/backup_postgres.sh
test -x scripts/integration_evidence.sh
test -x scripts/restore_postgres.sh
grep -q "backup_postgres.sh" docs/operations.md
grep -q "restore_postgres.sh" docs/operations.md
grep -q "Production Doctor" docs/operations.md
grep -q "doctor production" README.md
grep -q "blocker" docs/operations.md
grep -q "warning" docs/operations.md
grep -q "WEBHOOKERY_SECRET_BOX_MODE=aws-kms" docs/operations.md
grep -q "WEBHOOKERY_RAW_STORAGE_MODE=s3" docs/operations.md
grep -q "Production RC Checklist" docs/operations.md
grep -q "Upgrade And Restore Drill" docs/operations.md
grep -q "Incident Triage" docs/operations.md
grep -q "Explicit Non-Goals" docs/operations.md
grep -q "Production RC Readiness" README.md
grep -q "make rc-check" README.md
grep -q "make live-postgres-check" README.md
grep -q "make live-postgres-check" docs/operations.md
grep -q "make live-postgres-check" docs/release-evidence-template.md
test -f docs/day-2-operations.md
test -f docs/observability.md
grep -q "Day-2 Operations Guide" docs/day-2-operations.md
grep -q "Observability Examples" docs/observability.md
grep -q "networkpolicy.example.yaml" docs/deployment.md
grep -q "prometheus-rules.example.yaml" docs/deployment.md
grep -q "make perf-smoke" .github/workflows/integration.yml
grep -q "make provider-conformance-check" .github/workflows/integration.yml
grep -q "make perf-smoke" .github/workflows/release.yml
grep -q "Branch protection status" .github/workflows/release.yml

make provider-conformance-check
make provider-proof-check

if [ -n "${WEBHOOKERY_TEST_DATABASE_URL:-}" ]; then
  make live-postgres-check
fi

printf '%s\n' "release acceptance checks passed"
