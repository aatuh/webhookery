#!/usr/bin/env sh
set -eu

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"

doc="docs/provider-conformance.md"
manifest="docs/provider-conformance.manifest.json"
vector_registry="internal/provider/testdata/signature_vectors.json"

test -f "$doc"
test -f "$manifest"
test -f "$vector_registry"
test -f docs/provider-proof-manifest.json
grep -q "Provider Conformance Matrix" "$doc"
grep -q "Last official-doc verification: 2026-05-27" "$doc"
grep -q "no provider-side completeness guarantee" "$doc"
grep -q "does not call Stripe" "$doc"
grep -q "docs/live-provider-proof/stripe.md" "$doc"
grep -q "docs/live-provider-proof/github.md" "$doc"
grep -q "docs/live-provider-proof/shopify.md" "$doc"
grep -q "https://docs.stripe.com/webhooks" "$doc"
grep -q "https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries" "$doc"
grep -q "https://shopify.dev/docs/apps/build/webhooks/verify-deliveries" "$doc"
grep -q "https://api.slack.com/docs/verifying-requests-from-slack" "$doc"
grep -q "https://github.com/cloudevents/spec" "$doc"
grep -q "https://www.rfc-editor.org/info/rfc7519/" "$doc"

python3 - "$manifest" "$vector_registry" <<'PY'
import datetime
import json
import sys

path = sys.argv[1]
vector_path = sys.argv[2]
with open(path, "r", encoding="utf-8") as fh:
    data = json.load(fh)
with open(vector_path, "r", encoding="utf-8") as fh:
    vectors = json.load(fh)

expected = {"stripe", "github", "shopify", "slack", "generic-hmac", "generic-jwt", "cloudevents"}
providers = data.get("providers", [])
names = {item.get("name") for item in providers}
missing = sorted(expected - names)
if missing:
    raise SystemExit(f"provider conformance manifest missing providers: {missing}")
if data.get("no_live_provider_calls") is not True:
    raise SystemExit("provider conformance must not require live provider calls")
if data.get("signature_vector_registry") != vector_path:
    raise SystemExit("provider conformance manifest must point at internal/provider/testdata/signature_vectors.json")

checked = datetime.date.fromisoformat(data["last_official_doc_verification"])
today = datetime.date.today()
if checked > today:
    raise SystemExit("provider conformance verification date is in the future")
if (today - checked).days > 90:
    raise SystemExit("provider conformance verification date is older than 90 days")

for item in providers:
    required = ["name", "official_docs", "signature", "event_id", "event_type", "vector_tests", "limitations"]
    for key in required:
        if not item.get(key):
            raise SystemExit(f"{item.get('name', '<unknown>')} missing {key}")
    if not isinstance(item["official_docs"], list) or not isinstance(item["vector_tests"], list):
        raise SystemExit(f"{item['name']} docs and vector_tests must be arrays")
    if not item["limitations"]:
        raise SystemExit(f"{item['name']} must record limitations")

if vectors.get("schema_version") != "webhookery.provider_signature_vectors.v1":
    raise SystemExit("signature vector registry has an unexpected schema_version")
vector_items = vectors.get("vectors", [])
vector_names = {item.get("provider") for item in vector_items}
missing_vectors = sorted({"stripe", "github", "shopify", "slack"} - vector_names)
if missing_vectors:
    raise SystemExit(f"signature vector registry missing vectors: {missing_vectors}")
for item in vector_items:
    for key in ["name", "provider", "source", "checked_date", "now", "secret", "raw_body", "mutated_raw_body", "headers", "expected"]:
        if not item.get(key):
            raise SystemExit(f"signature vector missing {key}: {item.get('name', '<unknown>')}")
    datetime.date.fromisoformat(item["checked_date"])
    if item["expected"].get("verified") is not True or item["expected"].get("reason") != "ok":
        raise SystemExit(f"signature vector expected result must be explicit success: {item['name']}")
PY

grep -q "/v1/ingest/{tenant_id}/{source_id}" openapi.yaml
grep -q "stripe" openapi.yaml
grep -q "github" openapi.yaml
grep -q "shopify" openapi.yaml
grep -q "slack" openapi.yaml

go test ./internal/provider -run 'TestProviderSignatureVectors|TestNormalizeBuiltInProviderMetadata|TestCloudEventsAdapterDoesNotVerifyUnsigned|TestGenericJWTAdapter|TestDeclarativeAdapter' -count=1
go test ./pkg/verifier -run 'TestHMACSignatureUsesExactRawBytes|TestTimestampedSignatureWindow' -count=1

printf '%s\n' "provider conformance checks passed"
