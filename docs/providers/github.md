# GitHub Operator Guide

This guide is for operators configuring GitHub as a Webhookery source. It
covers the implemented Webhookery behavior and the GitHub behavior that was
checked against official docs on 2026-06-04.

## Scope

Implemented Webhookery behavior:

- `X-Hub-Signature-256` verification using HMAC-SHA256 over the exact raw body.
- Event identity from `X-GitHub-Delivery`.
- Event type from `X-GitHub-Event`.
- Duplicate delivery IDs remain visible as evidence; redelivery can be
  separated from Webhookery replay.
- Replay creates new Webhookery delivery work linked to the original evidence.

This guide does not claim GitHub provider certification, provider-side event
completeness, ordering, exactly-once delivery, or downstream business success.
In short: this is not provider certification.

Official sources checked:

- <https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries>
- <https://docs.github.com/en/webhooks/webhook-events-and-payloads>
- <https://docs.github.com/en/webhooks/testing-and-troubleshooting-webhooks/redelivering-webhooks>
- <https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks>

## Setup

Use a disposable repository first. Do not send organization production events
or private customer payloads to proof environments.

1. Start Webhookery and set a control-plane API key:

   ```bash
   cp .env.example .env
   docker compose up --build
   export WEBHOOKERY_API_KEY=dev-bootstrap-key
   ```

2. Generate a high-entropy webhook secret and keep it in a local shell or
   secret manager. Do not put secrets in payload URLs.

   ```bash
   export WEBHOOKERY_GITHUB_WEBHOOK_SECRET='replace-with-random-local-secret'
   ```

3. Create a GitHub source:

   ```bash
   go run ./cmd/whcp sources create \
     --name github-test-repo \
     --provider github \
     --secret "$WEBHOOKERY_GITHUB_WEBHOOK_SECRET" \
     --api-key "$WEBHOOKERY_API_KEY"
   ```

4. Save the returned source ID outside commits:

   ```bash
   export WEBHOOKERY_GITHUB_SOURCE_ID=src_replace_me
   ```

5. Configure the repository webhook in GitHub:

   - Payload URL:
     `https://webhookery.example.test/v1/ingest/github/${WEBHOOKERY_GITHUB_SOURCE_ID}`
   - Content type: `application/json`
   - Secret: the value of `WEBHOOKERY_GITHUB_WEBHOOK_SECRET`
   - Events: start with `ping` and `push`
   - SSL verification: enabled for public HTTPS endpoints

For local-only proof where GitHub cannot reach `localhost`, use a temporary
webhook proxy that forwards to
`http://localhost:8080/v1/ingest/github/${WEBHOOKERY_GITHUB_SOURCE_ID}`.
Treat proxy URLs as temporary test infrastructure and remove the webhook after
the proof.

## Secret Handling

- Use a unique secret per GitHub webhook.
- Store it in Webhookery through the source secret APIs, not in docs or issue
  comments.
- Rotate the source secret if it appears in a terminal recording, screenshot,
  CI log, support artifact, or shell history you cannot control.
- Do not put API keys or tokens in the webhook payload URL.

## Signature Verification

GitHub sends `X-Hub-Signature-256` when a webhook secret is configured. The
signature starts with `sha256=` and is computed with the webhook secret and
payload body. Webhookery verifies the exact raw body and uses constant-time
comparison through the provider verification path.

The older `X-Hub-Signature` SHA-1 header is compatibility evidence only. Use
`X-Hub-Signature-256` for GitHub sources.

## Delivery Identity And Dedupe

GitHub sends `X-GitHub-Delivery` as the delivery GUID and `X-GitHub-Event` as
the event name. Webhookery uses those values for normalized provider metadata.

GitHub's redelivery flow reuses the original `X-GitHub-Delivery` value. In
Webhookery, that means a manual GitHub redelivery should be visible as a
duplicate receipt for the same provider delivery identity. Do not treat the
duplicate as erased evidence.

## Redelivery Behavior

GitHub documentation says failed deliveries can be manually redelivered from
the past three days and that GitHub does not automatically redeliver failed
deliveries. Repository redelivery through the web UI requires repository admin
access. REST API redelivery or reconciliation requires a GitHub token with the
permissions required by GitHub for that endpoint.

No GitHub token is required for the basic repository webhook ping or push proof
unless you explicitly test REST API redelivery or Webhookery reconciliation.

## Replay And Evidence Workflow

Create a disposable receiver and route before sending the test event:

```bash
export WEBHOOKERY_RECEIVER_URL='https://receiver.example.test/fail-first'

go run ./cmd/whcp endpoints validate-url \
  --url "$WEBHOOKERY_RECEIVER_URL" \
  --api-key "$WEBHOOKERY_API_KEY"

go run ./cmd/whcp endpoints create \
  --name github-proof-receiver \
  --url "$WEBHOOKERY_RECEIVER_URL" \
  --api-key "$WEBHOOKERY_API_KEY"

export WEBHOOKERY_ENDPOINT_ID=end_replace_me

go run ./cmd/whcp routes create \
  --name github-push-proof \
  --source-id "$WEBHOOKERY_GITHUB_SOURCE_ID" \
  --endpoint-id "$WEBHOOKERY_ENDPOINT_ID" \
  --event-types ping,push \
  --state draft \
  --api-key "$WEBHOOKERY_API_KEY"

export WEBHOOKERY_ROUTE_ID=rte_replace_me

go run ./cmd/whcp routes activate \
  --route-id "$WEBHOOKERY_ROUTE_ID" \
  --reason "github proof route activation" \
  --api-key "$WEBHOOKERY_API_KEY"
```

After GitHub sends `ping` or `push`, inspect and replay:

```bash
go run ./cmd/whcp events list --api-key "$WEBHOOKERY_API_KEY"
export WEBHOOKERY_EVENT_ID=evt_replace_me

go run ./cmd/whcp events timeline \
  --event-id "$WEBHOOKERY_EVENT_ID" \
  --format markdown \
  --api-key "$WEBHOOKERY_API_KEY"

go run ./cmd/whcp replay-jobs dry-run \
  --event-id "$WEBHOOKERY_EVENT_ID" \
  --config-mode original \
  --reason-code receiver_fixed \
  --reason "github proof receiver fixed before replay" \
  --api-key "$WEBHOOKERY_API_KEY"

go run ./cmd/whcp replay-jobs create \
  --event-id "$WEBHOOKERY_EVENT_ID" \
  --config-mode original \
  --reason-code receiver_fixed \
  --reason "github proof receiver fixed before replay" \
  --api-key "$WEBHOOKERY_API_KEY"
```

## Incident Packet Example

Generate a report and evidence export after replay:

```bash
go run ./cmd/whcp incidents create \
  --title "GitHub test repository webhook failed then replayed" \
  --reason "github proof investigation" \
  --api-key "$WEBHOOKERY_API_KEY"

export WEBHOOKERY_INCIDENT_ID=inc_replace_me

go run ./cmd/whcp incidents add-event \
  --incident-id "$WEBHOOKERY_INCIDENT_ID" \
  --event-id "$WEBHOOKERY_EVENT_ID" \
  --reason "attach GitHub test delivery" \
  --api-key "$WEBHOOKERY_API_KEY"

go run ./cmd/whcp incidents generate-report \
  --incident-id "$WEBHOOKERY_INCIDENT_ID" \
  --reason "github proof report" \
  --api-key "$WEBHOOKERY_API_KEY"

go run ./cmd/whcp incidents report \
  --incident-id "$WEBHOOKERY_INCIDENT_ID" \
  --format markdown \
  --output github-incident-report.private.md \
  --api-key "$WEBHOOKERY_API_KEY"
```

Keep completed live reports and bundles private. Commit only sanitized samples
such as `docs/live-provider-proof/samples/github-incident-report.redacted.md`.

## Cleanup

1. Delete the test repository webhook in GitHub.
2. Rotate or delete the Webhookery source secret.
3. Disable or delete disposable routes and endpoints with operator reasons.
4. Delete temporary webhook proxy channels.
5. Remove private reports and bundles from shared machines.

## Non-Claims

This guide does not prove:

- downstream business processing succeeded;
- GitHub will redeliver every provider-side event forever;
- global event ordering;
- exactly-once delivery;
- compliance or legal evidentiary certification; or
- safe use of production customer data in public evidence.
