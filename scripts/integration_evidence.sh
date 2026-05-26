#!/usr/bin/env sh
set -eu

out_dir="${1:-integration-evidence}"
mkdir -p "$out_dir"

migration_count="$(find migrations -type f -name '*.up.sql' | wc -l | tr -d ' ')"
live_postgres_outcome="${LIVE_POSTGRES_CHECK_OUTCOME:-${POSTGRES_INTEGRATION_OUTCOME:-unknown}}"
rc_outcome="${RC_CHECK_OUTCOME:-unknown}"
restore_status="${RESTORE_DRILL_STATUS:-skipped_not_configured}"

{
  printf '%s\n' "# Webhookery Integration Evidence"
  printf '\n'
  printf '%s\n' "- Commit: ${GITHUB_SHA:-local}"
  printf '%s\n' "- Workflow: ${GITHUB_WORKFLOW:-local-integration}"
  printf '%s\n' "- Run ID: ${GITHUB_RUN_ID:-local}"
  printf '\n'
  printf '%s\n' "## Checks"
  printf '%s\n' "- Postgres migrations discovered: ${migration_count}"
  printf '%s\n' "- make live-postgres-check: ${live_postgres_outcome}"
  printf '%s\n' "- DB-backed make rc-check: ${rc_outcome}"
  printf '%s\n' "- DB-backed RC E2E: covered by make rc-check when WEBHOOKERY_TEST_DATABASE_URL is set"
  printf '%s\n' "- Restore drill: ${restore_status}"
  printf '\n'
  printf '%s\n' "## Sanitization"
  printf '%s\n' "- Database URLs, credentials, raw payload bodies, webhook signatures, provider tokens, and customer data are intentionally omitted."
  printf '%s\n' "- Local CI uses disposable Postgres and fake receivers/providers only; no live third-party provider or cloud calls are required."
} > "$out_dir/integration-evidence.md"
