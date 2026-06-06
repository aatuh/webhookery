#!/usr/bin/env bash
set -euo pipefail

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"

tag="${1:?usage: scripts/release_assets.sh <tag> <output-dir> [commit]}"
out_dir="${2:?usage: scripts/release_assets.sh <tag> <output-dir> [commit]}"
commit="${3:-$(git rev-parse HEAD)}"
platforms="${WEBHOOKERY_RELEASE_ASSET_PLATFORMS:-linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64}"

case "$tag" in
  v[0-9]*)
    ;;
  *)
    printf 'release tag must start with v and a digit: %s\n' "$tag" >&2
    exit 2
    ;;
esac

mkdir -p "$out_dir"
out_dir="$(cd "$out_dir" && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

build_archive() {
  local goos="$1"
  local goarch="$2"
  local binary="whcp"
  local ext=""
  if [ "$goos" = "windows" ]; then
    ext=".exe"
  fi

  local name="webhookery_${tag}_${goos}_${goarch}"
  local package_dir="$tmp_dir/$name"
  mkdir -p "$package_dir"

  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build \
    -trimpath \
    -ldflags "-s -w" \
    -o "$package_dir/${binary}${ext}" \
    ./cmd/whcp

  cp LICENSE README.md openapi.yaml "$package_dir/"
  mkdir -p "$package_dir/docs/releases"
  if [ -f "docs/releases/${tag}.md" ]; then
    cp "docs/releases/${tag}.md" "$package_dir/docs/releases/"
  fi

  if [ "$goos" = "windows" ]; then
    (cd "$tmp_dir" && zip -qr "$out_dir/${name}.zip" "$name")
  else
    tar -C "$tmp_dir" -czf "$out_dir/${name}.tar.gz" "$name"
  fi
}

for platform in $platforms; do
  goos="${platform%/*}"
  goarch="${platform#*/}"
  build_archive "$goos" "$goarch"
done

cp openapi.yaml "$out_dir/openapi.yaml"
sha256sum openapi.yaml > "$out_dir/openapi.sha256"
find migrations -type f -print0 | sort -z | xargs -0 sha256sum > "$out_dir/migrations.sha256"

if [ -f "docs/releases/${tag}.md" ]; then
  cp "docs/releases/${tag}.md" "$out_dir/release-notes.md"
else
  {
    printf '# Webhookery %s\n\n' "$tag"
    printf 'Release notes were not found under `docs/releases/%s.md`.\n' "$tag"
  } > "$out_dir/release-notes.md"
fi

{
  printf '%s\n' "Webhookery release asset summary"
  printf '%s\n' "tag=$tag"
  printf '%s\n' "commit=$commit"
  printf '%s\n' "checks=release-acceptance,provider-conformance,provider-proof,perf-smoke,rc-check"
  printf '%s\n' "non_claims=no exactly-once delivery; no provider-side completeness; no compliance certification; no live-provider acceptance unless separately recorded"
} > "$out_dir/release-check-summary.txt"

if [ -f source.spdx.json ]; then
  cp source.spdx.json "$out_dir/source.spdx.json"
fi
if [ -f image.spdx.json ]; then
  cp image.spdx.json "$out_dir/image.spdx.json"
fi
if [ -f coverage.out ]; then
  cp coverage.out "$out_dir/coverage.out"
fi
if [ -f coverage-db.out ]; then
  cp coverage-db.out "$out_dir/coverage-db.out"
fi
if [ -f release-evidence/release-evidence.md ]; then
  cp release-evidence/release-evidence.md "$out_dir/release-evidence.md"
fi
if [ -d tmp/perf-smoke ]; then
  mkdir -p "$out_dir/perf-smoke"
  cp tmp/perf-smoke/perf-smoke.* "$out_dir/perf-smoke/" 2>/dev/null || true
fi

(cd "$out_dir" && find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%P\0' | sort -z | xargs -0 sha256sum) > "$out_dir/SHA256SUMS"

python3 - "$out_dir" "$tag" "$commit" <<'PY'
import hashlib
import json
import pathlib
import sys

out_dir = pathlib.Path(sys.argv[1])
tag = sys.argv[2]
commit = sys.argv[3]

artifacts = []
for path in sorted(p for p in out_dir.iterdir() if p.is_file()):
    if path.name in {"webhookery-release-manifest.json", "webhookery-release-provenance.json", "webhookery-release-provenance.intoto.jsonl"}:
        continue
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    artifacts.append({
        "name": path.name,
        "sha256": digest,
        "size": path.stat().st_size,
    })

manifest = {
    "schema": "webhookery-release-manifest.v1",
    "tag": tag,
    "commit": commit,
    "artifacts": artifacts,
    "non_claims": [
        "not exactly-once delivery proof",
        "not provider-side event completeness proof",
        "not compliance certification",
        "not legal evidentiary certification",
        "not live-provider acceptance unless separately recorded",
    ],
}
(out_dir / "webhookery-release-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

provenance = {
    "schema": "webhookery-release-provenance.v1",
    "tag": tag,
    "commit": commit,
    "builder": "scripts/release_assets.sh",
    "materials": [
        "openapi.yaml",
        "migrations/",
        "cmd/whcp",
        "go.mod",
    ],
    "limitations": [
        "This is project release metadata, not a SLSA level claim.",
        "GitHub workflow identity and artifact digests must be verified from the published release run.",
    ],
}
(out_dir / "webhookery-release-provenance.json").write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8")

statement = {
    "_type": "https://in-toto.io/Statement/v1",
    "subject": [{"name": item["name"], "digest": {"sha256": item["sha256"]}} for item in artifacts],
    "predicateType": "https://webhookery.local/provenance/v1",
    "predicate": provenance,
}
(out_dir / "webhookery-release-provenance.intoto.jsonl").write_text(json.dumps(statement, sort_keys=True) + "\n", encoding="utf-8")
PY

(cd "$out_dir" && sha256sum webhookery-release-manifest.json webhookery-release-provenance.json webhookery-release-provenance.intoto.jsonl >> SHA256SUMS)

printf 'release assets written to %s\n' "$out_dir"
