# Documentation Maintenance

This document defines how Webhookery docs stay current without turning every
page into a duplicate source of truth.

## Provider Claim Freshness

Provider behavior changes over time. Any documentation or code review that
changes provider-specific semantics must verify current official upstream docs
before changing claims about signatures, retry windows, timeout behavior,
redelivery, reconciliation, event ordering, payload shape, CloudEvents support,
or SSRF guidance.

The author of the change owns the freshness record. The reviewer owns checking
that the record is present before merge.

For each dated provider-specific claim, record:

- owner or reviewer;
- review date in `YYYY-MM-DD` format;
- official source URL;
- scope checked, such as signature verification, redelivery, retries,
  timestamp window, or SSRF guidance;
- follow-up date or release milestone for the next review.

Dated claims older than 90 days must be rechecked before they are used in
release evidence, security review material, provider adapter changes, or
operator-facing runbooks. If an official source no longer supports the claim,
update the claim in the owning canonical doc, adjust tests or behavior when
needed, and record the old claim as stale in the change description.

Historical design claims in `.initial_design.md` are not implementation proof.
Several provider behavior claims there were originally captured during planning
and include May 25, 2026 examples. Treat them as design context until current
official docs are checked and the maintained docs or implementation are updated.

## Official Source Registry

These are the current official source locations to start from. URL availability
was checked on 2026-05-26; that check does not certify every behavior claim as
current.

| Area | Official source |
|------|-----------------|
| Stripe webhooks | <https://docs.stripe.com/webhooks> |
| GitHub webhooks | <https://docs.github.com/en/webhooks/using-webhooks> |
| GitHub redelivery | <https://docs.github.com/en/webhooks/testing-and-troubleshooting-webhooks/redelivering-webhooks> |
| Shopify webhooks | <https://shopify.dev/docs/apps/build/webhooks> |
| Shopify webhook troubleshooting | <https://shopify.dev/docs/apps/build/webhooks/troubleshooting-webhooks> |
| Slack request signing | <https://api.slack.com/docs/verifying-requests-from-slack> |
| Slack Events API | <https://api.slack.com/events-api> |
| CloudEvents | <https://cloudevents.io/> |
| OWASP SSRF guidance | <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html> |

Prefer official provider documentation over blog posts, memory, generated
answers, SDK behavior, or third-party examples. When official docs conflict
with implementation behavior, describe the gap as a current limitation rather
than rewriting the docs to imply support.

## Documentation Review Checklist

Use this checklist for documentation-only changes and for code changes that
alter docs, examples, contracts, deployment profiles, or release evidence.

- Audience: name the reader and task the changed doc serves.
- Doc type: classify the change as entry point, reference, runbook, policy,
  contract, deployment profile, generated artifact, or archive.
- Source of truth: update the owning canonical file first and link from
  secondary docs instead of duplicating long tables or command catalogs.
- Implemented vs intended: do not describe planned behavior as current unless
  code, OpenAPI, migrations, deployment profiles, or scripts prove it.
- Examples: use placeholders only; do not include real credentials, raw
  signatures, raw payload bodies, private keys, customer data, or production
  database URLs.
- Commands: run the narrow relevant command, usually `make docs-check`, and
  record skipped checks with the reason.
- Provider and security claims: refresh provider-specific claims through the
  freshness rule above and link to official sources when behavior changed.
- Non-claims: keep durable capture, at-least-once delivery, no exactly-once,
  no provider-side completeness, no compliance certification, and no live-
  provider acceptance language aligned with `docs/security-promise.md`.
- Generated artifacts: keep `openapi.yaml`, `sdk/openapi.yaml`, SDK docs, and
  collections aligned when contracts or examples change.
- Evidence: do not edit audit artifacts except explicit remediation checkmarks
  or requested evidence updates.
