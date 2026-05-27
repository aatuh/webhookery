#!/usr/bin/env sh
set -eu

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
cd "$repo_root"

say() {
  printf '%s\n' "demo: $*"
}

if [ -z "${WEBHOOKERY_TEST_DATABASE_URL:-}" ]; then
  printf '%s\n' "demo: WEBHOOKERY_TEST_DATABASE_URL is required" >&2
  printf '%s\n' "demo: start local postgres with: docker compose up -d postgres" >&2
  printf '%s\n' "demo: then export WEBHOOKERY_TEST_DATABASE_URL='postgres://webhookery:webhookery@localhost:5432/webhookery?sslmode=disable'" >&2
  exit 2
fi

say "running local webhook evidence demo"
say "provider ingest to signed delivery"
go test ./internal/e2e -run '^TestRCE2EProviderIngestToSignedDelivery$' -count=1

say "invalid signature quarantine"
go test ./internal/e2e -run '^TestRCE2EInvalidProviderSignatureQuarantinesWithoutRouting$' -count=1

say "retry, DLQ release, and replay modes"
go test ./internal/e2e -run '^TestRCE2ERetryExhaustionDLQReleaseAndReplayModes$' -count=1

say "retention, export, and audit-chain permission gates"
go test ./internal/e2e -run '^TestRCE2EEvidenceLifecycleRetentionExportAndPermissionGates$' -count=1

say "completed"
