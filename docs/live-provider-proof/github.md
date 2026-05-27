# GitHub Live-Provider Proof Guide

This manual guide shows how to prove a GitHub repository webhook flow through
Webhookery without committing secrets or raw repository payloads.

Status: external/manual. Completing this guide produces private evidence for a
specific environment; it is not provider certification.

Official docs checked on 2026-06-04:

- <https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries>
- <https://docs.github.com/en/webhooks/webhook-events-and-payloads>
- <https://docs.github.com/en/webhooks/testing-and-troubleshooting-webhooks/redelivering-webhooks>
- <https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks>

## What This Proves

- A real GitHub repository `ping` or `push` webhook can reach Webhookery.
- Webhookery verifies `X-Hub-Signature-256` using the raw request body.
- `X-GitHub-Delivery` is captured as the provider delivery identity.
- Manual GitHub redelivery is visible as duplicate provider delivery evidence.
- Webhookery replay and incident packet generation are linked to original
  evidence.

## What This Does Not Prove

- Provider certification or GitHub endorsement.
- Provider-side event completeness.
- Exactly-once delivery or global ordering.
- Downstream business processing success.
- Legal, regulatory, or compliance certification.

## Prerequisites

- Admin access to a disposable GitHub repository.
- Local Webhookery API and worker.
- A public HTTPS endpoint or temporary webhook proxy that forwards to local
  Webhookery.
- A disposable downstream receiver that can fail first and recover later.
- A private directory for generated reports and bundles.

No GitHub token is required for the basic ping/push proof unless you test REST
API redelivery or Webhookery reconciliation.

## 1. Prepare Webhookery

```bash
cp .env.example .env
docker compose up --build
export WEBHOOKERY_API_KEY=dev-bootstrap-key
export WEBHOOKERY_GITHUB_WEBHOOK_SECRET='replace-with-random-local-secret'
```

Create the source and save the returned source ID:

```bash
go run ./cmd/whcp sources create \
  --name github-live-proof \
  --provider github \
  --secret "$WEBHOOKERY_GITHUB_WEBHOOK_SECRET" \
  --api-key "$WEBHOOKERY_API_KEY"

export WEBHOOKERY_GITHUB_SOURCE_ID=src_replace_me
```

## 2. Configure The Repository Webhook

In the test repository, create a webhook:

- Payload URL:
  `https://webhookery.example.test/v1/ingest/github/${WEBHOOKERY_GITHUB_SOURCE_ID}`
- Content type: `application/json`
- Secret: the value of `WEBHOOKERY_GITHUB_WEBHOOK_SECRET`
- SSL verification: enabled
- Events: `ping` and `push`

For local-only proof, point GitHub at a temporary webhook proxy and forward the
proxy to:

```text
http://localhost:8080/v1/ingest/github/${WEBHOOKERY_GITHUB_SOURCE_ID}
```

Do not put API keys, bearer tokens, or secrets in the payload URL.

## 3. Configure The Failing Receiver Route

```bash
export WEBHOOKERY_RECEIVER_URL='https://receiver.example.test/fail-first'

go run ./cmd/whcp endpoints validate-url \
  --url "$WEBHOOKERY_RECEIVER_URL" \
  --api-key "$WEBHOOKERY_API_KEY"

go run ./cmd/whcp endpoints create \
  --name github-live-proof-receiver \
  --url "$WEBHOOKERY_RECEIVER_URL" \
  --api-key "$WEBHOOKERY_API_KEY"

export WEBHOOKERY_ENDPOINT_ID=end_replace_me

go run ./cmd/whcp routes create \
  --name github-live-proof-route \
  --source-id "$WEBHOOKERY_GITHUB_SOURCE_ID" \
  --endpoint-id "$WEBHOOKERY_ENDPOINT_ID" \
  --event-types ping,push \
  --state draft \
  --api-key "$WEBHOOKERY_API_KEY"

export WEBHOOKERY_ROUTE_ID=rte_replace_me

go run ./cmd/whcp routes activate \
  --route-id "$WEBHOOKERY_ROUTE_ID" \
  --reason "github live-proof route" \
  --api-key "$WEBHOOKERY_API_KEY"
```

## 4. Trigger And Capture A Delivery

Creating the webhook sends a `ping`. To trigger `push`, commit and push a
change to the disposable repository.

Then find the Webhookery event:

```bash
go run ./cmd/whcp events list --api-key "$WEBHOOKERY_API_KEY"
export WEBHOOKERY_EVENT_ID=evt_replace_me

go run ./cmd/whcp events timeline \
  --event-id "$WEBHOOKERY_EVENT_ID" \
  --format markdown \
  --api-key "$WEBHOOKERY_API_KEY"
```

Expected evidence:

- provider verification is valid;
- `X-GitHub-Delivery` is recorded as provider identity;
- `X-GitHub-Event` is recorded as event type;
- delivery to the failing receiver is recorded.

## 5. Prove Redelivery And Dedupe Shape

From the repository webhook settings, open the webhook, choose a recent
delivery from the past three days, and click redeliver. GitHub reuses the
delivery GUID for redelivery. In Webhookery, confirm that the duplicate
delivery identity remains visible:

```bash
go run ./cmd/whcp events list --api-key "$WEBHOOKERY_API_KEY"
go run ./cmd/whcp events timeline \
  --event-id "$WEBHOOKERY_EVENT_ID" \
  --format markdown \
  --api-key "$WEBHOOKERY_API_KEY"
```

Record the observed duplicate or dedupe evidence in the private incident
packet. Do not paste raw GitHub payloads into public docs or issues.

## 6. Recover And Replay

Change the receiver to return success, then run a dry-run and replay:

```bash
go run ./cmd/whcp replay-jobs dry-run \
  --event-id "$WEBHOOKERY_EVENT_ID" \
  --config-mode original \
  --reason-code receiver_fixed \
  --reason "github live-proof receiver fixed" \
  --api-key "$WEBHOOKERY_API_KEY"

go run ./cmd/whcp replay-jobs create \
  --event-id "$WEBHOOKERY_EVENT_ID" \
  --config-mode original \
  --reason-code receiver_fixed \
  --reason "github live-proof receiver fixed" \
  --api-key "$WEBHOOKERY_API_KEY"
```

If the event is in DLQ, release the DLQ entry instead:

```bash
go run ./cmd/whcp dead-letter list --api-key "$WEBHOOKERY_API_KEY"
export WEBHOOKERY_DLQ_ID=dlq_replace_me

go run ./cmd/whcp dead-letter release \
  --entry-id "$WEBHOOKERY_DLQ_ID" \
  --reason-code receiver_fixed \
  --reason "github live-proof receiver recovered" \
  --api-key "$WEBHOOKERY_API_KEY"
```

## 7. Generate A Private Incident Packet

```bash
mkdir -p live-proof-private/github

go run ./cmd/whcp incidents create \
  --title "GitHub test repository webhook failed then replayed" \
  --reason "github live-provider proof" \
  --api-key "$WEBHOOKERY_API_KEY"

export WEBHOOKERY_INCIDENT_ID=inc_replace_me

go run ./cmd/whcp incidents add-event \
  --incident-id "$WEBHOOKERY_INCIDENT_ID" \
  --event-id "$WEBHOOKERY_EVENT_ID" \
  --reason "attach GitHub proof event" \
  --api-key "$WEBHOOKERY_API_KEY"

go run ./cmd/whcp incidents generate-report \
  --incident-id "$WEBHOOKERY_INCIDENT_ID" \
  --reason "github proof report" \
  --api-key "$WEBHOOKERY_API_KEY"

go run ./cmd/whcp incidents report \
  --incident-id "$WEBHOOKERY_INCIDENT_ID" \
  --format markdown \
  --output live-proof-private/github/incident-report.private.md \
  --api-key "$WEBHOOKERY_API_KEY"

go run ./cmd/whcp incidents export \
  --incident-id "$WEBHOOKERY_INCIDENT_ID" \
  --reason "github proof bundle" \
  --output live-proof-private/github/evidence.private.tar.gz \
  --api-key "$WEBHOOKERY_API_KEY"
```

The `live-proof-private/` directory is an operator convention for local proof
artifacts. Do not commit it.

## 8. Redact A Shareable Sample

Use the same public-sample rules as
`docs/live-provider-proof/stripe-redaction-policy.md`. A committed sample
shape lives at
`docs/live-provider-proof/samples/github-incident-report.redacted.md`.

Before sharing any proof:

```bash
go run ./cmd/whcp audit verify-bundle \
  --file live-proof-private/github/evidence.private.tar.gz
make provider-proof-check
```

## Cleanup

1. Delete the test repository webhook.
2. Rotate or delete the Webhookery source secret.
3. Disable proof routes and endpoints.
4. Delete temporary webhook proxy channels.
5. Remove private proof artifacts from shared machines.

