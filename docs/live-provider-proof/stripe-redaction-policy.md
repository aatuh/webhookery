# Stripe Live-Proof Redaction Policy

Use this policy before sharing any Stripe live-provider proof output from
Webhookery. Do not commit completed live proof files unless they are reduced to
a sample that follows this policy.

## Remove

- Stripe API keys, restricted keys, session tokens, bearer tokens, and CLI
  authentication material.
- Stripe webhook signing secrets and any `Stripe-Signature` header values.
- Raw request bodies, raw response bodies, customer email addresses, card
  details, addresses, phone numbers, names, tax IDs, and account identifiers.
- Full downstream receiver URLs when they contain tenant names, tokens, or
  internal hostnames.
- Unhashed tenant IDs and organization IDs.
- Publicly routable proof URLs after the proof is complete.

## Allowed In Public Samples

- Provider name, event type, and redacted event ID shape.
- Timestamped step names.
- Verification result as `valid` or `invalid`.
- Hashes such as `sha256:...` for raw payload and bundle files.
- Source, endpoint, route, delivery, replay, incident, and export IDs when
  generated from a disposable local or test environment.
- Status codes, retry state, DLQ state, replay reason code, and non-secret
  error classes.
- Links to official provider documentation.

## Required Notes

Every public sample must state:

- test mode or sandbox only;
- not provider certification;
- no provider-side completeness guarantee;
- no exactly-once delivery claim;
- raw payload bodies and secrets omitted; and
- completed private evidence bundles must not be committed.

## Review

Before sharing:

1. Search for common secret prefixes and bearer tokens.
2. Search for email addresses and internal hostnames.
3. Confirm raw payload files are omitted.
4. Confirm bundle manifests contain hashes, not raw bodies.
5. Run `make provider-proof-check` after updating committed samples.
