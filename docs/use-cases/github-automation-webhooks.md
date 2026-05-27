# GitHub Automation Webhooks

Audience: platform teams and maintainers investigating repository automation
that did not run after a GitHub webhook delivery.

## Problem

A repository event was expected to trigger automation, but the downstream
receiver did not complete the work. The operator needs to find the delivery,
verify signature evidence, inspect dedupe and delivery attempts, replay when
safe, and retain a report for maintainers.

## Workflow

Use a test repository for live proof, or the local evidence demo when no live
provider access is available.

```bash
whcp events search --provider github --delivery-id gh_del_... --api-key "$WEBHOOKERY_API_KEY"
whcp events timeline --event-id evt_... --format table --api-key "$WEBHOOKERY_API_KEY"
whcp replay-jobs create --event-id evt_... --config-mode original --reason-code operator_requested --reason "rerun automation after receiver fix" --api-key "$WEBHOOKERY_API_KEY"
whcp incidents create --title "GitHub automation webhook investigation" --reason "automation did not run" --api-key "$WEBHOOKERY_API_KEY"
whcp incidents add-event --incident-id inc_... --event-id evt_... --reason "automation receiver failure" --api-key "$WEBHOOKERY_API_KEY"
whcp incidents export --incident-id inc_... --reason "maintainer evidence handoff" --output github-automation-evidence.tar.gz --api-key "$WEBHOOKERY_API_KEY"
```

## Evidence Output

Expected evidence includes:

- provider and delivery identity metadata;
- signature verification result;
- dedupe visibility for repeated deliveries;
- delivery attempt and replay timeline entries;
- replay reason code and operator reason; and
- incident evidence bundle verification output.

Use `docs/live-provider-proof/github.md` for a sanitized live test-repository
proof path and `docs/providers/github.md` for setup details.

## Non-Claims

This workflow does not certify GitHub delivery behavior, does not prove
provider-side completeness, and does not guarantee that downstream automation
is idempotent.
