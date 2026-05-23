#!/usr/bin/env sh
set -eu

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"

make fast-check

test -f Dockerfile
test -f docker-compose.yml
test -f deploy/kubernetes/kustomization.yaml
test -f deploy/helm/webhookery/Chart.yaml
grep -q "runAsNonRoot: true" deploy/kubernetes/api-deployment.yaml
grep -q "runAsNonRoot: true" deploy/helm/webhookery/values.yaml
test -f .env.example
test -f .api.env.example
test -f collections/postman/webhookery.postman_collection.json
test -f collections/bruno/Webhookery/bruno.json
test -x scripts/backup_postgres.sh
test -x scripts/restore_postgres.sh
grep -q "backup_postgres.sh" docs/operations.md
grep -q "restore_postgres.sh" docs/operations.md

if [ -n "${RANDONNEE_TEST_DATABASE_URL:-}" ]; then
  make postgres-integration-test
fi

printf '%s\n' "release acceptance checks passed"
