#!/usr/bin/env sh
set -eu

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"

usage() {
  cat <<'USAGE'
usage:
  scripts/failure_drills.sh list
  scripts/failure_drills.sh plan [--output DIR]
  scripts/failure_drills.sh run local-demo

The plan command writes a sanitized failure-drill checklist. The local-demo
drill requires WEBHOOKERY_TEST_DATABASE_URL and runs the deterministic local
evidence demo.
USAGE
}

fail() {
  printf '%s\n' "failure-drills: $*" >&2
  exit 2
}

validate_output_dir() {
  dir="$1"
  newline='
'
  case "$dir" in
    ""|-"$newline"*|*"$newline"*) fail "output directory is invalid" ;;
    -*) fail "output directory must not start with '-'" ;;
  esac
}

list_drills() {
  cat <<'DRILLS'
downstream-receiver-fails
downstream-recovers
invalid-signature
replay-after-dlq
postgres-unavailable-before-capture
object-storage-unavailable-s3-mode
audit-chain-verification-failure
retention-raw-payload-tombstone
DRILLS
}

write_plan() {
  out_dir="$1"
  validate_output_dir "$out_dir"
  umask 077
  mkdir -p -- "$out_dir"
  out_file="$out_dir/failure-drills.md"
  {
    printf '%s\n' "# Webhookery Failure Drills"
    printf '\n'
    printf '%s\n' "This file is a sanitized local/pilot drill plan. It omits database URLs,"
    printf '%s\n' "provider credentials, webhook secrets, raw signatures, raw payload bodies,"
    printf '%s\n' "customer data, and private receiver URLs."
    printf '\n'
    printf '%s\n' "| Drill | Safe command or setup | Expected result | Evidence |"
    printf '%s\n' "|-------|-----------------------|-----------------|----------|"
    printf '%s\n' "| downstream-receiver-fails | \`scripts/failure_drills.sh run local-demo\` | Initial downstream delivery fails and is visible before replay. | \`examples/webhook-evidence-demo/output/incident-report.md\` |"
    printf '%s\n' "| downstream-recovers | \`scripts/failure_drills.sh run local-demo\` | Replay succeeds after receiver recovery. | \`examples/webhook-evidence-demo/output/verify-output.json\` |"
    printf '%s\n' "| invalid-signature | \`scripts/failure_drills.sh run local-demo\` | Invalid signature path is persisted as evidence and not routed. | Local E2E output and incident packet references. |"
    printf '%s\n' "| replay-after-dlq | \`scripts/failure_drills.sh run local-demo\` | DLQ release creates replay work with reason evidence. | Incident report replay and DLQ sections. |"
    printf '%s\n' "| postgres-unavailable-before-capture | Stop PostgreSQL in a disposable local stack, then send a synthetic event. | Ingress does not return success before durable capture is available. | API error, readiness output, and ops notes. |"
    printf '%s\n' "| object-storage-unavailable-s3-mode | In a MinIO-only test stack, block object storage before object-backed raw payload capture. | Object-backed capture is not acknowledged when required object writes fail. | Storage drill notes and redacted API output. |"
    printf '%s\n' "| audit-chain-verification-failure | Use a disposable database copy and intentionally alter a copied audit row. | Verification reports failure; original evidence remains untouched. | \`whcp audit verify-chain\` output from the disposable copy. |"
    printf '%s\n' "| retention-raw-payload-tombstone | Run the local demo retention check or a disposable retention policy. | Raw body read returns retained/tombstoned state while metadata remains queryable. | Timeline, retention run, and audit entries. |"
    printf '\n'
    printf '%s\n' "Run destructive or failure-injection drills only against disposable local or"
    printf '%s\n' "pilot-approved resources. Record completed pilot results in"
    printf '%s\n' "\`docs/pilot-evidence-template.md\`."
  } > "$out_file"
  printf '%s\n' "$out_file"
}

run_local_demo() {
  if [ -z "${WEBHOOKERY_TEST_DATABASE_URL:-}" ]; then
    fail "WEBHOOKERY_TEST_DATABASE_URL is required for local-demo"
  fi
  examples/webhook-evidence-demo/run.sh
  for required in \
    examples/webhook-evidence-demo/output/incident-report.md \
    examples/webhook-evidence-demo/output/incident-report.json \
    examples/webhook-evidence-demo/output/evidence-manifest.json \
    examples/webhook-evidence-demo/output/verify-output.json
  do
    if [ ! -f "$required" ]; then
      fail "local-demo did not produce $required"
    fi
  done
  printf '%s\n' "failure-drills: local-demo completed"
}

cmd="${1:-}"
case "$cmd" in
  list)
    if [ "$#" -ne 1 ]; then
      usage >&2
      exit 2
    fi
    list_drills
    ;;
  plan)
    out_dir="tmp/failure-drills"
    shift
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
          fail "unknown plan argument: $1"
          ;;
      esac
    done
    write_plan "$out_dir"
    ;;
  run)
    [ "$#" -eq 2 ] || fail "usage: scripts/failure_drills.sh run local-demo"
    case "$2" in
      local-demo) run_local_demo ;;
      *) fail "unknown drill: $2" ;;
    esac
    ;;
  --help|-h|"")
    usage
    [ -n "$cmd" ] || exit 2
    ;;
  *)
    fail "unknown command: $cmd"
    ;;
esac
