#!/usr/bin/env sh
set -eu

out_dir="${1:-integration-evidence}"
mkdir -p "$out_dir"

migration_count="$(find migrations -type f -name '*.up.sql' | wc -l | tr -d ' ')"
live_postgres_outcome="${LIVE_POSTGRES_CHECK_OUTCOME:-${POSTGRES_INTEGRATION_OUTCOME:-unknown}}"
rc_outcome="${RC_CHECK_OUTCOME:-unknown}"
restore_status="${RESTORE_DRILL_STATUS:-skipped_not_configured}"
perf_smoke_outcome="${PERF_SMOKE_OUTCOME:-unknown}"
provider_conformance_outcome="${PROVIDER_CONFORMANCE_OUTCOME:-unknown}"
branch_protection_status="${BRANCH_PROTECTION_STATUS:-not_checked_by_workflow}"
external_review_status="${EXTERNAL_REVIEW_STATUS:-not_completed_or_not_attached}"

if [ -d tmp/perf-smoke ]; then
  mkdir -p "$out_dir/perf-smoke"
  cp tmp/perf-smoke/perf-smoke.json "$out_dir/perf-smoke/" 2>/dev/null || true
  cp tmp/perf-smoke/perf-smoke.md "$out_dir/perf-smoke/" 2>/dev/null || true
fi

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
  printf '%s\n' "- make perf-smoke: ${perf_smoke_outcome}"
  printf '%s\n' "- make provider-conformance-check: ${provider_conformance_outcome}"
  printf '%s\n' "- DB-backed RC E2E: covered by make rc-check when WEBHOOKERY_TEST_DATABASE_URL is set"
  printf '%s\n' "- Restore drill: ${restore_status}"
  printf '%s\n' "- Branch protection status: ${branch_protection_status}"
  printf '%s\n' "- External review status: ${external_review_status}"
  printf '\n'
  printf '%s\n' "## Maturity Evidence"
  printf '%s\n' "- Performance artifacts: $([ -d "$out_dir/perf-smoke" ] && printf 'attached' || printf 'not_attached')"
  printf '%s\n' "- Failure drill coverage: DB-backed make rc-check includes local fake receiver/provider drills only"
  printf '%s\n' "- Provider conformance: ${provider_conformance_outcome}"
  printf '%s\n' "- Accepted risk status: ${ACCEPTED_RISK_STATUS:-not_attached}"
  printf '\n'
  printf '%s\n' "## Sanitization"
  printf '%s\n' "- Database URLs, credentials, raw payload bodies, webhook signatures, provider tokens, and customer data are intentionally omitted."
  printf '%s\n' "- Local CI uses disposable Postgres and fake receivers/providers only; no live third-party provider or cloud calls are required."
} > "$out_dir/integration-evidence.md"
