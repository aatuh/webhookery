# Why Webhookery

Webhookery is for teams that need evidence about incoming webhooks, not another
generic webhook sender.

The core question is:

> When an integration fails, can you prove what arrived, what verified, what
> was stored, what delivery attempted, what was replayed, and what evidence
> remains?

## Webhooks Fail In Boring Ways

Most webhook incidents are not novel architecture problems. They are ordinary
failure boundaries that become expensive because evidence is scattered:

- the provider sent an event but the receiver was down;
- the receiver returned success before completing business work;
- a duplicate was processed twice or hidden by a dedupe shortcut;
- a retry happened hours later and changed state again;
- an operator replayed an event without a durable reason trail; or
- raw logs expired before the support or security review started.

Webhookery keeps those boundaries explicit. Inbound success means durable
capture, not downstream business success.

## Provider Retry Is Not Your Processing Guarantee

Provider retry behavior helps, but it is not a substitute for your own
evidence model. Webhookery stores local capture, verification, dedupe, routing,
delivery, retry, DLQ, replay, retention, and audit evidence so an operator can
investigate from local records.

Provider-specific behavior belongs in the provider guides:

- `docs/providers/stripe.md`
- `docs/providers/github.md`
- `docs/providers/shopify.md`
- `docs/provider-conformance.md`

Those docs are conformance and operator evidence, not provider certification.

## Logs Are Not Evidence

Logs are useful for operations, but they are not enough for audit-grade webhook
debugging. Webhookery records:

- raw payload references and hashes;
- exact provider verification result;
- dedupe result;
- route, subscription, retry, and transformation version references;
- delivery attempts and failure classes;
- replay reason codes and free-text reasons;
- raw-payload access audit events; and
- hash-chain verification evidence.

Normal event APIs and reports return references and hashes rather than raw
payload bodies by default.

## Replay Without History Is Dangerous

Replay can repair an incident, but it can also create duplicate side effects.
Webhookery requires replay reason evidence, records the replay mode, links new
work back to the original event or delivery, and preserves the original
history. Replay is at-least-once work, not exactly-once delivery.

Use these surfaces during investigation:

```bash
whcp events search --status dlq --since 24h --api-key "$WEBHOOKERY_API_KEY"
whcp events timeline --event-id evt_... --format markdown --api-key "$WEBHOOKERY_API_KEY"
whcp incidents generate-report --incident-id inc_... --reason "support handoff" --api-key "$WEBHOOKERY_API_KEY"
whcp audit verify-bundle --file evidence.tar.gz
```

## What Webhookery Is Good For

Webhookery is a fit when you need:

- self-hosted inbound provider webhook capture;
- durable evidence before inbound success;
- provider-aware verification and dedupe evidence;
- delivery attempts, retry, DLQ, and replay history;
- auditable raw-payload access;
- evidence bundles and incident reports; and
- a PostgreSQL-first control plane for controlled self-hosted pilots.

## When Not To Use Webhookery

Do not use Webhookery when you primarily need:

- a hosted webhook sender;
- a generic event bus or workflow engine;
- a marketplace of integrations;
- multi-region active-active guarantees;
- provider certification or provider-side completeness guarantees;
- exactly-once delivery; or
- legal/compliance evidentiary certification.

For the full product promise and non-claims, use `docs/security-promise.md`.
