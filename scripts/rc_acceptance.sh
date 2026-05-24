#!/usr/bin/env sh
set -eu

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"

say() {
  printf '%s\n' "rc-check: $*"
}

require_file() {
  if [ ! -f "$1" ]; then
    printf '%s\n' "rc-check: required file is missing: $1" >&2
    exit 2
  fi
}

require_executable() {
  if [ ! -x "$1" ]; then
    printf '%s\n' "rc-check: required executable is missing or not executable: $1" >&2
    exit 2
  fi
}

say "checking release-candidate prerequisites"
require_file Makefile
require_file go.mod
require_file openapi.yaml
require_file sdk/openapi.yaml
require_file Dockerfile
require_file docker-compose.yml
require_file docs/operations.md
require_file .api.env.example
require_executable scripts/release_acceptance.sh
require_executable scripts/backup_postgres.sh
require_executable scripts/restore_postgres.sh

say "running fast repository checks"
make fast-check

say "running release acceptance evidence checks"
make release-acceptance

say "running targeted production-core tests"
go test ./cmd/whcp ./internal/adapters/httpapi ./internal/adapters/postgres ./internal/app ./internal/worker ./internal/provider ./internal/ssrf ./internal/evidence ./pkg/client ./pkg/verifier

if [ -n "${RANDONNEE_TEST_DATABASE_URL:-}" ]; then
  say "running postgres integration checks"
  make postgres-integration-test
  say "running db-backed rc e2e checks"
  go test ./internal/e2e -run TestRCE2E -count=1
else
  say "RANDONNEE_TEST_DATABASE_URL is not set; skipping db-backed rc e2e checks"
fi

if [ -n "${WEBHOOKERY_RC_RESTORE_DATABASE_URL:-}" ]; then
  say "running restore drill against WEBHOOKERY_RC_RESTORE_DATABASE_URL"
  WEBHOOKERY_RESTORE_DRILL_DATABASE_URL="$WEBHOOKERY_RC_RESTORE_DATABASE_URL" go test ./internal/e2e -run TestRCRestoreDrill -count=1
else
  say "WEBHOOKERY_RC_RESTORE_DATABASE_URL is not set; skipping destructive restore drill"
fi

say "release-candidate acceptance checks passed"
