#!/usr/bin/env sh
set -eu

database_url="${WEBHOOKERY_DATABASE_URL:-${DATABASE_URL:-}}"
if [ -z "$database_url" ]; then
  printf '%s\n' "WEBHOOKERY_DATABASE_URL or DATABASE_URL is required" >&2
  exit 2
fi

out_dir="${1:-backups}"
umask 077
mkdir -p -- "$out_dir"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
out_file="$out_dir/webhookery-${timestamp}.dump"

pg_dump --format=custom --no-owner --no-acl --dbname "$database_url" --file "$out_file"
printf '%s\n' "$out_file"
