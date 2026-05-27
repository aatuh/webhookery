#!/usr/bin/env sh
set -eu

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)"
cd "$repo_root"

say() {
  printf '%s\n' "demo: $*"
}

if [ -z "${WEBHOOKERY_TEST_DATABASE_URL:-}" ]; then
  printf '%s\n' "demo: WEBHOOKERY_TEST_DATABASE_URL is required" >&2
  printf '%s\n' "demo: start local postgres with: docker compose up -d postgres" >&2
  printf '%s\n' "demo: then export WEBHOOKERY_TEST_DATABASE_URL='postgres://webhookery:change-me@localhost:5432/webhookery?sslmode=disable'" >&2
  exit 2
fi

say "running local webhook evidence demo"
output_dir="${WEBHOOKERY_DEMO_OUTPUT_DIR:-examples/webhook-evidence-demo/output}"
case "$output_dir" in
  /*) ;;
  *) output_dir="$repo_root/$output_dir" ;;
esac
if [ "$output_dir" = "$repo_root" ]; then
  printf '%s\n' "demo: WEBHOOKERY_DEMO_OUTPUT_DIR must not be the repository root" >&2
  exit 2
fi
case "$output_dir/" in
  "$repo_root"/*) ;;
  *)
    printf '%s\n' "demo: WEBHOOKERY_DEMO_OUTPUT_DIR must be inside the repository" >&2
    exit 2
    ;;
esac
mkdir -p "$output_dir"
output_dir="$(CDPATH= cd -- "$output_dir" && pwd -P)"
if [ "$output_dir" = "$repo_root" ]; then
  printf '%s\n' "demo: WEBHOOKERY_DEMO_OUTPUT_DIR must not resolve to the repository root" >&2
  exit 2
fi
case "$output_dir/" in
  "$repo_root"/*) ;;
  *)
    printf '%s\n' "demo: WEBHOOKERY_DEMO_OUTPUT_DIR must resolve inside the repository" >&2
    exit 2
    ;;
esac
for file in incident-report.md incident-report.json evidence-manifest.json verify-output.json README.md evidence.tar.gz; do
  rm -f "$output_dir/$file"
done

say "failed payment webhook incident packet"
WEBHOOKERY_DEMO_OUTPUT_DIR="$output_dir" go test ./internal/e2e -run '^TestRCE2EFailedPaymentWebhookIncidentPacketDemo$' -count=1

say "provider ingest to signed delivery"
go test ./internal/e2e -run '^TestRCE2EProviderIngestToSignedDelivery$' -count=1

say "invalid signature quarantine"
go test ./internal/e2e -run '^TestRCE2EInvalidProviderSignatureQuarantinesWithoutRouting$' -count=1

say "retry, DLQ release, and replay modes"
go test ./internal/e2e -run '^TestRCE2ERetryExhaustionDLQReleaseAndReplayModes$' -count=1

say "retention, export, and audit-chain permission gates"
go test ./internal/e2e -run '^TestRCE2EEvidenceLifecycleRetentionExportAndPermissionGates$' -count=1

for file in incident-report.md incident-report.json evidence-manifest.json verify-output.json README.md evidence.tar.gz; do
  if [ ! -s "$output_dir/$file" ]; then
    printf '%s\n' "demo: expected output file was not generated: $output_dir/$file" >&2
    exit 1
  fi
done

say "scenario result: downstream failure recorded before replay"
say "scenario result: replay delivery succeeded after receiver recovery"
say "output: $output_dir"
say "completed"
