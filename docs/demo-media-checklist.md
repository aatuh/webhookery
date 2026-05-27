# Demo Media Checklist

Use this checklist before publishing screenshots, GIFs, short videos, or
slides made from Webhookery demos.

The approved source demo is `examples/webhook-evidence-demo/`. It uses
synthetic provider payloads and fake local evidence paths. Do not record real
providers, customer receivers, or production databases.

Prepare recording material with:

```bash
scripts/demo_media.sh plan --output tmp/demo-media
WEBHOOKERY_TEST_DATABASE_URL=postgres://... make demo-media
```

`plan` writes a sanitized script outline without running Webhookery. `make
demo-media` regenerates the local evidence demo under `tmp/demo-media/output`
and requires a disposable PostgreSQL URL.

## Before Recording

- [ ] Use a clean checkout or disposable branch.
- [ ] Run `make docs-check`.
- [ ] Run `WEBHOOKERY_TEST_DATABASE_URL=postgres://... make demo-media`
      against a disposable local PostgreSQL database.
- [ ] Use only fixture data from `examples/webhook-evidence-demo/fixtures/`.
- [ ] Set terminal scrollback low enough that old secrets cannot appear.
- [ ] Disable shell history capture if commands contain local connection URLs.
- [ ] Use a terminal profile without private hostnames, usernames, or cloud
      account names in the prompt.

## Allowed To Show

- Local fake event IDs such as `evt_demo_invoice_paid`.
- Local fake source, route, delivery, replay, DLQ, retention, and audit-chain
  evidence.
- `make rc-check`, `make release-acceptance`, and demo command output.
- `docs/security-promise.md`, `docs/provider-conformance.md`, and
  `docs/release-evidence-template.md`.
- Local placeholder URLs such as `localhost`.

## Do Not Show

- API keys.
- bearer tokens.
- session cookies.
- OAuth or OIDC tokens.
- webhook signing secrets.
- raw provider signature headers.
- private keys or client certificates.
- provider API credentials.
- database URLs with passwords.
- AWS, Vault, object-store, or cloud account credentials.
- raw customer payload bodies.
- customer PII.
- private hostnames, VPN names, or internal IP addresses.
- exploit payloads or vulnerability proof-of-concept details.

## Required On-Screen Boundaries

At least one screen or narration segment must make these boundaries clear:

- Webhookery is self-hosted software, not a hosted managed service.
- Inbound success means durable capture, not downstream business success.
- Delivery is at-least-once, not exactly once.
- Provider reconciliation cannot prove provider-side event completeness.
- Release evidence is not compliance certification.

## Suggested Recording Flow

1. Show README or the static landing page headline.
2. Run the evaluator quickstart command sequence.
3. Show the demo passing.
4. Show the release evidence and provider conformance docs.
5. End on the commercial evaluation or support path if the asset is
   buyer-facing.

## Final Review

- [ ] No secrets, credentials, raw signatures, or private payloads are visible.
- [ ] No production hostnames, internal IPs, or customer names are visible.
- [ ] The asset does not claim exactly-once delivery.
- [ ] The asset does not claim provider-side completeness.
- [ ] The asset does not claim compliance certification.
- [ ] The asset links to the current release notes and release evidence.
