#!/usr/bin/env sh
set -eu

database_url="${WEBHOOKERY_DATABASE_URL:-${DATABASE_URL:-}}"
if [ -z "$database_url" ]; then
  printf '%s\n' "WEBHOOKERY_DATABASE_URL or DATABASE_URL is required" >&2
  exit 2
fi

dump_file="${1:-}"
if [ -z "$dump_file" ] || [ ! -f "$dump_file" ]; then
  printf '%s\n' "usage: WEBHOOKERY_RESTORE_CONFIRM=restore scripts/restore_postgres.sh <dump-file>" >&2
  exit 2
fi

if [ "${WEBHOOKERY_RESTORE_CONFIRM:-}" != "restore" ]; then
  printf '%s\n' "refusing restore without WEBHOOKERY_RESTORE_CONFIRM=restore" >&2
  exit 2
fi

pg_restore --clean --if-exists --no-owner --no-acl --dbname "$database_url" "$dump_file"
