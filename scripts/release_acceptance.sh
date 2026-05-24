#!/usr/bin/env sh
set -eu

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"

make fast-check

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

if [ -n "${RANDONNEE_TEST_DATABASE_URL:-}" ]; then
  make postgres-integration-test
fi

printf '%s\n' "release acceptance checks passed"
