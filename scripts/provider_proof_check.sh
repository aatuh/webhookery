#!/usr/bin/env sh
set -eu

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"

manifest="docs/provider-proof-manifest.json"

test -f "$manifest"
test -f docs/live-provider-proof/stripe.md
test -f docs/live-provider-proof/github.md
test -f docs/live-provider-proof/shopify.md
test -f docs/live-provider-proof/run-record-template.md
test -f docs/live-provider-proof/stripe-redaction-policy.md
test -f docs/live-provider-proof/samples/stripe-incident-report.redacted.md
test -f docs/live-provider-proof/samples/github-incident-report.redacted.md
test -f docs/live-provider-proof/samples/shopify-incident-report.redacted.md
test -f docs/providers/stripe.md
test -f docs/providers/github.md
test -f docs/providers/shopify.md

grep -q "not provider certification" docs/live-provider-proof/stripe.md
grep -q "not provider certification" docs/live-provider-proof/github.md
grep -q "not provider certification" docs/live-provider-proof/shopify.md
grep -q "Do not commit completed run records" docs/live-provider-proof/run-record-template.md
grep -q "not provider certification" docs/live-provider-proof/run-record-template.md
grep -q "Do not commit" docs/live-provider-proof/stripe-redaction-policy.md
grep -q "docs/live-provider-proof/stripe.md" docs/provider-conformance.md
grep -q "docs/live-provider-proof/github.md" docs/provider-conformance.md
grep -q "docs/live-provider-proof/shopify.md" docs/provider-conformance.md
grep -q "docs/live-provider-proof/run-record-template.md" docs/provider-conformance.md

python3 - "$manifest" <<'PY'
import datetime
import json
import sys
from pathlib import Path
from urllib.parse import urlparse

root = Path.cwd().resolve()
path = Path(sys.argv[1])

with path.open("r", encoding="utf-8") as fh:
    data = json.load(fh)

if data.get("schema_version") != "provider-proof-v1":
    raise SystemExit("provider proof manifest schema_version must be provider-proof-v1")
if data.get("project") != "webhookery":
    raise SystemExit("provider proof manifest project must be webhookery")
if data.get("no_live_provider_calls") is not True:
    raise SystemExit("provider proof check must not require live provider calls")

max_age_days = data.get("max_age_days")
if not isinstance(max_age_days, int) or max_age_days <= 0:
    raise SystemExit("provider proof manifest max_age_days must be a positive integer")

required_providers = {"stripe", "github", "shopify"}
proofs = data.get("proofs")
if not isinstance(proofs, list):
    raise SystemExit("provider proof manifest proofs must be an array")
providers = {item.get("provider") for item in proofs}
missing = sorted(required_providers - providers)
if missing:
    raise SystemExit(f"provider proof manifest missing providers: {missing}")

today = datetime.date.today()
for item in proofs:
    provider = item.get("provider", "<unknown>")
    if item.get("status") != "manual_external":
        raise SystemExit(f"{provider} provider proof status must be manual_external")
    checked = datetime.date.fromisoformat(item["checked_date"])
    expires = datetime.date.fromisoformat(item["expires_after"])
    if checked > today:
        raise SystemExit(f"{provider} provider proof checked_date is in the future")
    if expires < checked:
        raise SystemExit(f"{provider} provider proof expires before checked date")
    if (today - checked).days > max_age_days:
        raise SystemExit(f"{provider} provider proof metadata is older than {max_age_days} days")
    if expires < today:
        raise SystemExit(f"{provider} provider proof metadata is expired")

    for key in ("operator_guide", "proof_guide", "redaction_policy", "sample_report"):
        raw = item.get(key)
        if not raw or Path(raw).is_absolute():
            raise SystemExit(f"{provider} {key} must be a relative path")
        resolved = (root / raw).resolve()
        if root != resolved and root not in resolved.parents:
            raise SystemExit(f"{provider} {key} escapes repository root")
        if not resolved.is_file():
            raise SystemExit(f"{provider} {key} does not exist: {raw}")
        text = resolved.read_text(encoding="utf-8").lower()
        for required in ("not provider certification", "exactly-once", "provider-side"):
            if required not in text:
                raise SystemExit(f"{provider} {key} missing required non-claim text: {required}")

    sources = item.get("official_sources")
    if not isinstance(sources, list) or not sources:
        raise SystemExit(f"{provider} official_sources must be a non-empty array")
    for source in sources:
        parsed = urlparse(source)
        if parsed.scheme != "https":
            raise SystemExit(f"{provider} official source must be https: {source}")
        if provider == "stripe" and parsed.netloc != "docs.stripe.com":
            raise SystemExit(f"stripe official source must use docs.stripe.com: {source}")
        if provider == "github" and parsed.netloc != "docs.github.com":
            raise SystemExit(f"github official source must use docs.github.com: {source}")
        if provider == "shopify" and parsed.netloc != "shopify.dev":
            raise SystemExit(f"shopify official source must use shopify.dev: {source}")

    scope = item.get("scope_checked")
    if not isinstance(scope, list) or len(scope) < 2:
        raise SystemExit(f"{provider} scope_checked must list the reviewed behavior")
    non_claims = item.get("non_claims")
    if not isinstance(non_claims, list) or "not provider certification" not in non_claims:
        raise SystemExit(f"{provider} non_claims must include not provider certification")

for sample_key in ("sample_report",):
    for item in proofs:
        sample = (root / item[sample_key]).resolve()
        text = sample.read_text(encoding="utf-8")
        forbidden = [
            "sk_live_",
            "sk_test_",
            "rk_live_",
            "whsec_",
            "github_pat_",
            "ghp_",
            "shpat_",
            "shpua_",
            "shpss_",
            "shppa_",
            "Bearer ",
            "Stripe-Signature:",
            "X-Hub-Signature-256: sha256=",
            "X-Shopify-Hmac-SHA256:",
        ]
        leaked = [marker for marker in forbidden if marker in text]
        if leaked:
            raise SystemExit(f"{item['provider']} sample contains forbidden secret-shaped markers: {leaked}")
PY

printf '%s\n' "provider proof checks passed"
