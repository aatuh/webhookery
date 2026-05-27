#!/usr/bin/env sh
set -eu

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"

usage() {
  cat <<'USAGE'
usage:
  scripts/demo_media.sh plan [--output DIR]
  scripts/demo_media.sh run [--output DIR]

plan writes a sanitized recording outline without running Webhookery. run
requires WEBHOOKERY_TEST_DATABASE_URL and regenerates the deterministic local
evidence demo into DIR/output.
USAGE
}

fail() {
  printf '%s\n' "demo-media: $*" >&2
  exit 2
}

validate_output_dir() {
  dir="$1"
  newline='
'
  case "$dir" in
    ""|*"$newline"*) fail "output directory is invalid" ;;
    -*) fail "output directory must not start with '-'" ;;
  esac
}

write_plan() {
  out_dir="$1"
  validate_output_dir "$out_dir"
  umask 077
  mkdir -p -- "$out_dir"
  script_file="$out_dir/demo-script.md"
  {
    printf '%s\n' "# Webhookery Demo Media Script"
    printf '\n'
    printf '%s\n' "Use only the deterministic local evidence demo and synthetic fixtures."
    printf '%s\n' "Do not record provider dashboards, customer receivers, production"
    printf '%s\n' "databases, database URLs, API keys, webhook secrets, raw signatures,"
    printf '%s\n' "raw payload bodies, private hostnames, or customer data."
    printf '\n'
    printf '%s\n' "## Recording Flow"
    printf '\n'
    printf '%s\n' "1. Show the README headline or \`site/index.html\`."
    printf '%s\n' "2. Show \`docs/security-promise.md\` durable-capture and non-claim boundaries."
    printf '%s\n' "3. Run \`make demo-media\` or show the generated \`tmp/demo-media/output\` files."
    printf '%s\n' "4. Open \`incident-report.md\`, \`evidence-manifest.json\`, and \`verify-output.json\`."
    printf '%s\n' "5. End on \`docs/commercial-evaluation.md\` or \`docs/pilot-topology.md\` for buyer-facing assets."
    printf '\n'
    printf '%s\n' "## Required Narration Boundaries"
    printf '\n'
    printf '%s\n' "- Inbound success means durable capture, not downstream business success."
    printf '%s\n' "- Delivery and replay are at-least-once."
    printf '%s\n' "- Local deterministic demo output is not live provider certification."
    printf '%s\n' "- Evidence bundles are not compliance or legal certification."
  } > "$script_file"
  cp docs/demo-media-checklist.md "$out_dir/recording-checklist.md"
  printf '%s\n' "$script_file"
}

run_demo() {
  out_dir="$1"
  validate_output_dir "$out_dir"
  if [ -z "${WEBHOOKERY_TEST_DATABASE_URL:-}" ]; then
    fail "WEBHOOKERY_TEST_DATABASE_URL is required; start docker compose postgres and export the disposable database URL"
  fi
  write_plan "$out_dir" >/dev/null
  mkdir -p -- "$out_dir/output"
  WEBHOOKERY_DEMO_OUTPUT_DIR="$out_dir/output" examples/webhook-evidence-demo/run.sh
  printf '%s\n' "demo-media: output written to $out_dir"
}

cmd="${1:-plan}"
out_dir="tmp/demo-media"
shift || true
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output)
      [ "$#" -ge 2 ] || fail "--output requires a directory"
      out_dir="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

case "$cmd" in
  plan) write_plan "$out_dir" ;;
  run) run_demo "$out_dir" ;;
  --help|-h)
    usage
    ;;
  *)
    fail "unknown command: $cmd"
    ;;
esac
