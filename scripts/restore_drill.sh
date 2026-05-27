#!/usr/bin/env sh
set -eu

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"

usage() {
  cat <<'USAGE'
usage: WEBHOOKERY_DATABASE_URL=postgres://source \
       WEBHOOKERY_RESTORE_DRILL_DATABASE_URL=postgres://disposable-restore \
       scripts/restore_drill.sh [--output DIR]

The restore target is destructive. The script refuses to run unless source and
restore URLs are both set and different.
USAGE
}

fail() {
  printf '%s\n' "restore-drill: $*" >&2
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

out_dir="tmp/restore-drill"
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

source_url="${WEBHOOKERY_DATABASE_URL:-${DATABASE_URL:-}}"
restore_url="${WEBHOOKERY_RESTORE_DRILL_DATABASE_URL:-}"

[ -n "$source_url" ] || fail "WEBHOOKERY_DATABASE_URL or DATABASE_URL is required"
[ -n "$restore_url" ] || fail "WEBHOOKERY_RESTORE_DRILL_DATABASE_URL is required"
[ "$source_url" != "$restore_url" ] || fail "restore target must be different from source database"

command -v pg_dump >/dev/null 2>&1 || fail "pg_dump is required"
command -v pg_restore >/dev/null 2>&1 || fail "pg_restore is required"

validate_output_dir "$out_dir"
umask 077
mkdir -p -- "$out_dir/backups"

started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '%s\n' "restore-drill: creating source backup"
backup_path="$(WEBHOOKERY_DATABASE_URL="$source_url" scripts/backup_postgres.sh "$out_dir/backups")"

printf '%s\n' "restore-drill: restoring into disposable target"
WEBHOOKERY_DATABASE_URL="$restore_url" WEBHOOKERY_RESTORE_CONFIRM=restore scripts/restore_postgres.sh "$backup_path"

printf '%s\n' "restore-drill: applying migrations to disposable target"
WEBHOOKERY_DATABASE_URL="$restore_url" go run ./cmd/whcp migrate up

completed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
evidence_file="$out_dir/restore-drill.json"
backup_name="${backup_path##*/}"
{
  printf '%s\n' "{"
  printf '%s\n' "  \"schema_version\": \"webhookery.restore_drill.v1\","
  printf '%s\n' "  \"started_at\": \"$started_at\","
  printf '%s\n' "  \"completed_at\": \"$completed_at\","
  printf '%s\n' "  \"source_database_url_redacted\": true,"
  printf '%s\n' "  \"restore_database_url_redacted\": true,"
  printf '%s\n' "  \"backup_file\": \"$backup_name\","
  printf '%s\n' "  \"restore_target_destructive\": true,"
  printf '%s\n' "  \"migrations_applied\": true,"
  printf '%s\n' "  \"object_storage_bodies_verified\": false,"
  printf '%s\n' "  \"object_storage_note\": \"PostgreSQL restore drills do not verify S3 or MinIO object bodies.\""
  printf '%s\n' "}"
} > "$evidence_file"

printf '%s\n' "restore-drill: evidence written to $evidence_file"
