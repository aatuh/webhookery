#!/usr/bin/env sh
set -eu

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"

make fast-check

test -f LICENSE
grep -q "GNU AFFERO GENERAL PUBLIC LICENSE" LICENSE
test -f COMMERCIAL.md
test -f SECURITY.md
test -f SUPPORT.md
test -f CONTRIBUTING.md
test -f GOVERNANCE.md
test -f TRADEMARKS.md
test -f RELEASE_EVIDENCE.md
test -f docs/release-evidence-template.md
test -f docs/security-review-package.md
test -f .dockerignore
test -f .golangci.yml
grep -q "AGPL-3.0-only" COMMERCIAL.md
grep -q "AGPL-3.0-only" CONTRIBUTING.md
grep -q "https://www.linkedin.com/in/aatu-harju" SECURITY.md
grep -q "webhook secrets" SECURITY.md
grep -q "raw payloads" SECURITY.md
grep -q "no exactly-once delivery" RELEASE_EVIDENCE.md
grep -q "no provider-side event completeness" RELEASE_EVIDENCE.md
grep -q "compliance" RELEASE_EVIDENCE.md
grep -q "not a certification" RELEASE_EVIDENCE.md
grep -q "live third-party provider" docs/release-evidence-template.md
grep -q ".refs" .dockerignore
grep -q "release-evidence" .dockerignore
grep -q "backups" .dockerignore

test -f Dockerfile
test -f docker-compose.yml
test -f deploy/kubernetes/kustomization.yaml
test -f deploy/helm/webhookery/Chart.yaml
test -f deploy/terraform/webhookery-helm/main.tf
grep -q "runAsNonRoot: true" deploy/kubernetes/api-deployment.yaml
grep -q "runAsNonRoot: true" deploy/helm/webhookery/values.yaml
grep -q "helm_release" deploy/terraform/webhookery-helm/main.tf
test -f .env.example
test -f .api.env.example
test -f collections/postman/webhookery.postman_collection.json
test -f collections/bruno/Webhookery/bruno.json
test -x scripts/backup_postgres.sh
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

if [ -n "${RANDONNEE_TEST_DATABASE_URL:-}" ]; then
  make postgres-integration-test
fi

printf '%s\n' "release acceptance checks passed"
