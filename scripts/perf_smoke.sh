#!/usr/bin/env sh
set -eu

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"

if [ -z "${WEBHOOKERY_TEST_DATABASE_URL:-}" ]; then
  printf '%s\n' "perf-smoke: WEBHOOKERY_TEST_DATABASE_URL is required; use a disposable PostgreSQL database" >&2
  exit 2
fi

out_dir="${WEBHOOKERY_PERF_OUTPUT_DIR:-tmp/perf-smoke}"
case "$out_dir" in
  /*) out_abs="$out_dir" ;;
  *) out_abs="$repo_root/$out_dir" ;;
esac
mkdir -p "$out_abs"

WEBHOOKERY_PERF_OUTPUT_DIR="$out_abs" go test ./internal/e2e -run TestPerfSmoke -count=1 -timeout=2m

printf '%s\n' "perf-smoke: wrote ${out_dir}/perf-smoke.json"
printf '%s\n' "perf-smoke: wrote ${out_dir}/perf-smoke.md"
