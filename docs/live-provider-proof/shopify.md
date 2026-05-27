# Shopify Live-Provider Proof Guide

This manual guide shows how to prove a Shopify development-store webhook flow
through Webhookery without committing secrets, raw shop payloads, or customer
data.

Status: external/manual. Completing this guide produces private evidence for a
specific environment; it is not provider certification.

Official docs checked on 2026-06-04:

- <https://shopify.dev/docs/apps/build/webhooks>
- <https://shopify.dev/docs/apps/build/webhooks/delivery-structure>
- <https://shopify.dev/docs/apps/build/webhooks/verify-deliveries>
- <https://shopify.dev/docs/apps/build/webhooks/troubleshoot>

## What This Proves

- A real Shopify development-store delivery can reach Webhookery.
- Webhookery verifies `X-Shopify-Hmac-SHA256` using the raw request body.
- `X-Shopify-Webhook-Id` and `X-Shopify-Topic` are captured as provider
  metadata.
- Topic-based routing, downstream failure, replay, and incident packet
  generation are visible.
- A sanitized report can be produced without exposing raw payloads or secrets.

## What This Does Not Prove

- Provider certification or Shopify endorsement.
- Provider-side event completeness.
- Exactly-once delivery or global ordering.
- Universal missed-event recovery across every Shopify topic.
- Downstream business processing success.
- Legal, regulatory, or compliance certification.

## Prerequisites

- A Shopify development store and app.
- Local Webhookery API and worker.
- An HTTPS endpoint or temporary development tunnel that forwards to
  Webhookery.
- A disposable downstream receiver that can fail first and recover later.
- A private directory for generated reports and bundles.

## 1. Prepare Webhookery

```bash
cp .env.example .env
docker compose up --build
export WEBHOOKERY_API_KEY=dev-bootstrap-key
export WEBHOOKERY_SHOPIFY_CLIENT_SECRET='replace-with-app-client-secret'
```

Create the source and save the returned source ID:

```bash
go run ./cmd/whcp sources create \
  --name shopify-live-proof \
  --provider shopify \
  --secret "$WEBHOOKERY_SHOPIFY_CLIENT_SECRET" \
  --api-key "$WEBHOOKERY_API_KEY"

export WEBHOOKERY_SHOPIFY_SOURCE_ID=src_replace_me
```

## 2. Configure A Development-Store Subscription

Create or update a Shopify webhook subscription for a development-store topic,
for example `products/create`.

Use this URI:

```text
https://webhookery.example.test/v1/ingest/shopify/${WEBHOOKERY_SHOPIFY_SOURCE_ID}
```

For a local tunnel, forward the public tunnel URL to:

```text
http://localhost:8080/v1/ingest/shopify/${WEBHOOKERY_SHOPIFY_SOURCE_ID}
```

Do not put access tokens, API keys, or client secrets in the subscription URI.

## 3. Configure The Failing Receiver Route

```bash
export WEBHOOKERY_RECEIVER_URL='https://receiver.example.test/fail-first'

go run ./cmd/whcp endpoints validate-url \
  --url "$WEBHOOKERY_RECEIVER_URL" \
  --api-key "$WEBHOOKERY_API_KEY"

go run ./cmd/whcp endpoints create \
  --name shopify-live-proof-receiver \
  --url "$WEBHOOKERY_RECEIVER_URL" \
  --api-key "$WEBHOOKERY_API_KEY"

export WEBHOOKERY_ENDPOINT_ID=end_replace_me

go run ./cmd/whcp routes create \
  --name shopify-live-proof-route \
  --source-id "$WEBHOOKERY_SHOPIFY_SOURCE_ID" \
  --endpoint-id "$WEBHOOKERY_ENDPOINT_ID" \
  --event-types products/create \
  --state draft \
  --api-key "$WEBHOOKERY_API_KEY"

export WEBHOOKERY_ROUTE_ID=rte_replace_me

go run ./cmd/whcp routes activate \
  --route-id "$WEBHOOKERY_ROUTE_ID" \
  --reason "shopify live-proof route" \
  --api-key "$WEBHOOKERY_API_KEY"
```

## 4. Trigger And Capture A Delivery

Trigger the subscribed topic in the development store. For `products/create`,
create a disposable product.

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
- raw payload evidence is represented by IDs and hashes;
- `X-Shopify-Webhook-Id` and `X-Shopify-Topic` are visible in normalized
  metadata;
- delivery to the failing receiver is recorded.

## 5. Recover And Replay

Change the receiver to return success, then run a dry-run and replay:

```bash
go run ./cmd/whcp replay-jobs dry-run \
  --event-id "$WEBHOOKERY_EVENT_ID" \
  --config-mode original \
  --reason-code receiver_fixed \
  --reason "shopify live-proof receiver fixed" \
  --api-key "$WEBHOOKERY_API_KEY"

go run ./cmd/whcp replay-jobs create \
  --event-id "$WEBHOOKERY_EVENT_ID" \
  --config-mode original \
  --reason-code receiver_fixed \
  --reason "shopify live-proof receiver fixed" \
  --api-key "$WEBHOOKERY_API_KEY"
```

If the event is in DLQ, release the DLQ entry instead:

```bash
go run ./cmd/whcp dead-letter list --api-key "$WEBHOOKERY_API_KEY"
export WEBHOOKERY_DLQ_ID=dlq_replace_me

go run ./cmd/whcp dead-letter release \
  --entry-id "$WEBHOOKERY_DLQ_ID" \
  --reason-code receiver_fixed \
  --reason "shopify live-proof receiver recovered" \
  --api-key "$WEBHOOKERY_API_KEY"
```

## 6. Generate A Private Incident Packet

```bash
mkdir -p live-proof-private/shopify

go run ./cmd/whcp incidents create \
  --title "Shopify development-store webhook failed then replayed" \
  --reason "shopify live-provider proof" \
  --api-key "$WEBHOOKERY_API_KEY"

export WEBHOOKERY_INCIDENT_ID=inc_replace_me

go run ./cmd/whcp incidents add-event \
  --incident-id "$WEBHOOKERY_INCIDENT_ID" \
  --event-id "$WEBHOOKERY_EVENT_ID" \
  --reason "attach Shopify proof event" \
  --api-key "$WEBHOOKERY_API_KEY"

go run ./cmd/whcp incidents generate-report \
  --incident-id "$WEBHOOKERY_INCIDENT_ID" \
  --reason "shopify proof report" \
  --api-key "$WEBHOOKERY_API_KEY"

go run ./cmd/whcp incidents report \
  --incident-id "$WEBHOOKERY_INCIDENT_ID" \
  --format markdown \
  --output live-proof-private/shopify/incident-report.private.md \
  --api-key "$WEBHOOKERY_API_KEY"

go run ./cmd/whcp incidents export \
  --incident-id "$WEBHOOKERY_INCIDENT_ID" \
  --reason "shopify proof bundle" \
  --output live-proof-private/shopify/evidence.private.tar.gz \
  --api-key "$WEBHOOKERY_API_KEY"
```

The `live-proof-private/` directory is an operator convention for local proof
artifacts. Do not commit it.

## 7. Redact A Shareable Sample

Use the public-sample rules in
`docs/live-provider-proof/stripe-redaction-policy.md`. A committed sample
shape lives at
`docs/live-provider-proof/samples/shopify-incident-report.redacted.md`.

Before sharing any proof:

```bash
go run ./cmd/whcp audit verify-bundle \
  --file live-proof-private/shopify/evidence.private.tar.gz
make provider-proof-check
```

## Cleanup

1. Delete the development-store webhook subscription.
2. Rotate or delete the Webhookery source secret.
3. Disable proof routes and endpoints.
4. Delete temporary tunnel or proxy configuration.
5. Remove private proof artifacts from shared machines.

