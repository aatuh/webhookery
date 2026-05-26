# Security Promise And Non-Claims

This is the canonical Webhookery security-promise and non-claims reference.
Other docs should link here instead of repeating full caveat lists.

## Promise

Webhookery is self-hosted webhook evidence and delivery infrastructure. Its
trust promise is deliberately narrow:

- Do not return inbound success before durable capture according to the
  configured storage mode.
- Preserve raw request evidence needed for provider verification.
- Make loss boundaries, duplicates, retries, replay, retention, and audit
  evidence visible.
- Keep recovery and replay linked to original evidence without mutating
  original history.
- Treat customer-controlled outbound URLs as hostile input.
- Keep secrets, raw payload bodies, bearer/session tokens, provider
  credentials, private keys, and unnecessary PII out of logs, metrics, errors,
  UI responses, docs, release evidence, and support artifacts.

Inbound success means durable capture and verification metadata were recorded.
It does not mean downstream business processing succeeded.

## Non-Claims

Webhookery makes:

- no exactly-once delivery claim
- no provider-side event completeness guarantee
- no recovery guarantee for every provider-side event
- no multi-region active-active coordination claim
- no external timestamping claim
- no FIPS/NIST/CMVP certification claim
- no compliance certification claim
- no legal evidentiary certification claim
- no managed-service availability claim
- no live third-party provider acceptance claim for local release gates
- no claim that Redis, NATS, Kafka, or object storage is the authority for
  accepted event evidence

Release evidence, support, commercial agreements, trademarks, and governance
docs may narrow or clarify scope for a specific engagement, but they must not
silently broaden these claims.

## Documentation Rule

When adding docs, examples, release evidence, or support text:

- Link to this document for the full non-claim list.
- Use placeholders for secrets and credentials.
- Do not include raw signatures, raw payload bodies, customer data, private
  keys, real database URLs, provider credentials, bearer tokens, or session
  tokens.
- Verify provider-specific statements against official upstream docs before
  changing provider semantics. Use `docs/documentation-maintenance.md` for the
  freshness record.
