# Webhookery Vs Convoy

Verification date: 2026-05-27

Official sources reviewed:

- <https://convoy.mintlify.dev/docs/home/introduction>
- <https://www.getconvoy.io/docs/product-manual/sources>

This page is a buyer-fit comparison, not a claim that one product is generally
better. Product surfaces change; re-check official sources before publishing or
using this page in sales material.

## Public Positioning Summary

Convoy positions itself as an open-source, high-performance webhooks gateway
for managing webhooks end to end. Its documentation describes support for both
sending and receiving webhooks, retries, rate limiting, circuit breaking,
customer-facing dashboards, and source verification for incoming provider
events.

## Where Webhookery Differs

Webhookery is audit-first and evidence-first. It focuses on durable capture
before inbound success, raw provider evidence, provider verification metadata,
versioned configuration evidence, payload snapshots, replay reason capture,
reconciliation gap evidence, retention metadata, evidence exports, and
audit-chain verification.

Webhookery is a fit when the core question is:

> Can we reconstruct and prove what Webhookery saw, decided, delivered,
> retained, replayed, or could not recover?

Convoy may be a better fit when the core question is:

> Can we run a broad open-source webhook gateway with sending, receiving,
> dashboards, rate limiting, and gateway features?

## Evaluation Matrix

| Need | Webhookery fit | Convoy fit |
| --- | --- | --- |
| Audit-first webhook evidence and release evidence | Strong fit | Evaluate current Convoy audit/evidence features. |
| Broad open-source webhook gateway | Narrower fit | Stronger fit. |
| Incoming provider source verification | Supported with provider-specific evidence | Supported by Convoy sources with provider/config-specific verification. |
| Reproducible route/retry/transformation/payload evidence | Strong fit | Evaluate current Convoy reproducibility model. |
| Commercial license exception for private self-hosted modifications | Available by written agreement | Review Convoy's current community/enterprise terms. |

## Honest Recommendation

Evaluate Webhookery if auditability, release evidence, exact raw capture,
configuration reproducibility, and recovery proof are primary requirements.

Evaluate Convoy if you want a broader open-source webhook gateway surface and
its current sending/receiving feature set fits your needs.

Webhookery does not claim exactly-once delivery, provider-side event
completeness, compliance certification, or hosted-service availability.
