# Provider Conformance Matrix

This matrix is release evidence for the provider behavior Webhookery currently
claims. It makes no provider-side completeness guarantee: providers can retry,
drop, expire, redact, or make old events unrecoverable according to their own
systems. Webhookery's promise remains durable capture before success, exact raw
byte verification, visible gaps, and explicit recovery evidence where provider
APIs permit it.

Last official-doc verification: 2026-05-27.

Machine-readable evidence lives in
`docs/provider-conformance.manifest.json`. Run:

```sh
make provider-conformance-check
```

The check uses only local deterministic vectors and documentation metadata. The
committed provider signature vector registry lives at
`internal/provider/testdata/signature_vectors.json`; each vector records its
source, checked date, headers, raw body fixture, mutated-body negative check,
and expected result. The check does not call Stripe, GitHub, Shopify, Slack,
AWS, Vault, or customer receivers.

Manual sanitized live-provider proof guides are tracked separately:

- Stripe operator guide: `docs/providers/stripe.md`
- Stripe proof guide: `docs/live-provider-proof/stripe.md`
- GitHub operator guide: `docs/providers/github.md`
- GitHub proof guide: `docs/live-provider-proof/github.md`
- Shopify operator guide: `docs/providers/shopify.md`
- Shopify proof guide: `docs/live-provider-proof/shopify.md`
- Proof freshness metadata: `docs/provider-proof-manifest.json`

Run:

```sh
make provider-proof-check
```

Those guides are external/manual evidence procedures. They are not provider
certification, do not call live providers in repository checks, and do not
store completed private proof artifacts in public source.

## Matrix

| Provider or format | Verification evidence | Timestamp or replay window | Event ID and type extraction | Replay or recovery behavior | Current limitations |
|--------------------|-----------------------|----------------------------|------------------------------|-----------------------------|---------------------|
| Stripe | `Stripe-Signature` `v1` HMAC-SHA256 over `timestamp.raw_body`; local vector in `internal/provider/testdata/signature_vectors.json`. | Five-minute tolerance aligned with Stripe's documented library default. | JSON `id` and `type`; account/API version metadata where present. | Reconciliation can compare Stripe Events API IDs and capture recovered provider-API evidence when enabled. | No provider-side completeness guarantee; recovered evidence is provider API evidence, not signed webhook evidence. |
| GitHub | `X-Hub-Signature-256` `sha256=` HMAC-SHA256 over exact raw body; local vector in `internal/provider/testdata/signature_vectors.json`. | GitHub signature validation does not define a timestamp window in the signature header. | `X-GitHub-Delivery` as delivery/event ID and `X-GitHub-Event` as type. | Reconciliation can scan repository webhook delivery APIs and request redelivery where GitHub supports it. | No raw payload is invented if GitHub does not return it; redelivery is explicit audited recovery work. |
| Shopify | `X-Shopify-Hmac-SHA256` base64 HMAC-SHA256 over the raw request body; local vector in `internal/provider/testdata/signature_vectors.json`. | Shopify verification is raw-body HMAC based; this slice does not claim a generic timestamp replay window. | `X-Shopify-Webhook-Id` as delivery ID, `X-Shopify-Topic` as type, and shop domain metadata. | Capability evidence is recorded; generic missed-event recovery is not claimed. | Resource polling is topic-specific and is not represented as universal webhook recovery. |
| Slack | `X-Slack-Signature` `v0=` HMAC-SHA256 over `v0:timestamp:raw_body`; local vector in `internal/provider/testdata/signature_vectors.json`. | Five-minute timestamp skew window. | JSON `event_id` and nested event `type`; team and app metadata where present. | Capability evidence is recorded; generic missed-event recovery is not claimed. | Slack retry-window evidence is limited; unsupported gaps are evidence, not Webhookery capture failures. |
| Generic HMAC adapter | Declarative local adapters support HMAC-SHA256 with explicit signature/timestamp headers, signed payload template, encoding, and replay window. | Configured per adapter definition. | Configured JSON extractors. | No provider recovery unless a concrete reconciliation adapter is implemented. | Declarative adapters are deterministic verification/normalization helpers, not arbitrary code plugins. |
| Generic JWT adapter | HS256 JWT bearer token with allowlisted algorithm and raw body hash claim; alg `none` is rejected. | `iat`/`exp` claims are validated by local tests. | JWT `jti` plus configured/body metadata. | No provider recovery unless a concrete reconciliation adapter is implemented. | HS256 only in the current generic JWT adapter. |
| CloudEvents | Structured and binary CloudEvents metadata can be parsed and normalized. | None by default. | CloudEvents `id`, `type`, `source`, and optional `subject`. | No provider recovery. | Unsigned CloudEvents validity does not imply trust and does not route by default. |

## Official Sources Checked

- Stripe webhooks and signature behavior:
  <https://docs.stripe.com/webhooks>
- GitHub webhook signature validation:
  <https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries>
- GitHub webhook events and delivery headers:
  <https://docs.github.com/en/webhooks/webhook-events-and-payloads>
- GitHub webhook redelivery:
  <https://docs.github.com/en/webhooks/testing-and-troubleshooting-webhooks/redelivering-webhooks>
- GitHub webhook best practices:
  <https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks>
- Shopify webhook HMAC verification:
  <https://shopify.dev/docs/apps/build/webhooks/verify-deliveries>
- Slack request signing:
  <https://api.slack.com/docs/verifying-requests-from-slack>
- CloudEvents core and JSON event format:
  <https://github.com/cloudevents/spec>
- JWT standard:
  <https://www.rfc-editor.org/info/rfc7519/>
- SSRF prevention guidance for webhook-style URLs:
  <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html>

## Evidence Boundaries

- These checks prove local parser, verifier, and normalization behavior against
  committed vectors; they do not certify live provider behavior.
- Provider APIs used for reconciliation are tested with fake local servers in
  release gates; live-provider acceptance calls are intentionally excluded.
- Unsupported provider recovery is recorded as explicit gap evidence rather
  than hidden as success.
- The conformance matrix must be rechecked before release evidence if the last
  official-doc verification date is older than 90 days.
