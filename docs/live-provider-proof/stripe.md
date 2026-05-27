# Stripe Live-Provider Proof Guide

This manual guide shows how to prove a Stripe test-mode webhook flow through
Webhookery without committing secrets or live customer data.

Status: external/manual. Completing this guide produces private evidence for a
specific environment; it is not provider certification.

Official docs checked on 2026-06-04:

- <https://docs.stripe.com/webhooks>
- <https://docs.stripe.com/webhooks/signature>

## What This Proves

- A real Stripe test-mode event can reach Webhookery.
- Webhookery verifies `Stripe-Signature` using the raw request body.
- Webhookery records event timeline evidence before downstream success.
- Downstream failure, retry or DLQ, replay, and incident packet generation are
  visible.
- A sanitized report can be produced without exposing raw payloads or secrets.

## What This Does Not Prove

- Provider certification or Stripe endorsement.
- Provider-side event completeness.
- Exactly-once delivery or global ordering.
- Downstream business processing success.
- Legal, regulatory, or compliance certification.

## Prerequisites

- Stripe CLI logged into a sandbox or test-mode account.
- Local Webhookery API and worker.
- A disposable downstream receiver that can fail first and recover later.
- A private directory for generated reports and bundles.
- The redaction policy in
  `docs/live-provider-proof/stripe-redaction-policy.md`.

## 1. Prepare Webhookery

```bash
cp .env.example .env
docker compose up --build
export WEBHOOKERY_API_KEY=dev-bootstrap-key
```

Create a source with a temporary placeholder, then save the returned source ID:

```bash
go run ./cmd/whcp sources create \
  --name stripe-live-proof \
  --provider stripe \
  --secret temporary-local-placeholder \
  --api-key "$WEBHOOKERY_API_KEY"

export WEBHOOKERY_STRIPE_SOURCE_ID=src_replace_me
```

## 2. Start Stripe Test-Mode Forwarding

Run this in another shell:

```bash
stripe listen \
  --events payment_intent.succeeded,payment_intent.payment_failed \
  --forward-to "http://localhost:8080/v1/ingest/stripe/${WEBHOOKERY_STRIPE_SOURCE_ID}"
```

Copy the webhook signing secret from the `stripe listen` output into a local
shell variable, then rotate the Webhookery source. Do not commit or screenshot
the value.

```bash
export WEBHOOKERY_STRIPE_WEBHOOK_SECRET='replace-with-local-listener-secret'

go run ./cmd/whcp sources rotate-secret \
  --source-id "$WEBHOOKERY_STRIPE_SOURCE_ID" \
  --secret "$WEBHOOKERY_STRIPE_WEBHOOK_SECRET" \
  --reason "stripe live-proof listener secret" \
  --api-key "$WEBHOOKERY_API_KEY"
```

## 3. Configure The Failing Receiver Route

Use a receiver URL that returns an error before you flip it to success:

```bash
export WEBHOOKERY_RECEIVER_URL='https://receiver.example.test/fail-first'

go run ./cmd/whcp endpoints validate-url \
  --url "$WEBHOOKERY_RECEIVER_URL" \
  --api-key "$WEBHOOKERY_API_KEY"

go run ./cmd/whcp endpoints create \
  --name stripe-live-proof-receiver \
  --url "$WEBHOOKERY_RECEIVER_URL" \
  --api-key "$WEBHOOKERY_API_KEY"

export WEBHOOKERY_ENDPOINT_ID=end_replace_me

go run ./cmd/whcp routes create \
  --name stripe-live-proof-route \
  --source-id "$WEBHOOKERY_STRIPE_SOURCE_ID" \
  --endpoint-id "$WEBHOOKERY_ENDPOINT_ID" \
  --event-types payment_intent.succeeded,payment_intent.payment_failed \
  --state draft \
  --api-key "$WEBHOOKERY_API_KEY"

export WEBHOOKERY_ROUTE_ID=rte_replace_me

go run ./cmd/whcp routes activate \
  --route-id "$WEBHOOKERY_ROUTE_ID" \
  --reason "stripe live-proof route" \
  --api-key "$WEBHOOKERY_API_KEY"
```

## 4. Trigger And Capture A Test Event

```bash
stripe trigger payment_intent.succeeded
```

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
- delivery to the failing receiver is recorded;
- retry or DLQ state is visible when the receiver remains failing long enough.

## 5. Recover And Replay

Change the receiver to return success, then run a dry-run and replay:

```bash
go run ./cmd/whcp replay-jobs dry-run \
  --event-id "$WEBHOOKERY_EVENT_ID" \
  --config-mode original \
  --reason-code receiver_fixed \
  --reason "stripe live-proof receiver fixed" \
  --api-key "$WEBHOOKERY_API_KEY"

go run ./cmd/whcp replay-jobs create \
  --event-id "$WEBHOOKERY_EVENT_ID" \
  --config-mode original \
  --reason-code receiver_fixed \
  --reason "stripe live-proof receiver fixed" \
  --api-key "$WEBHOOKERY_API_KEY"
```

If the event is in DLQ, release the DLQ entry instead:

```bash
go run ./cmd/whcp dead-letter list --api-key "$WEBHOOKERY_API_KEY"
export WEBHOOKERY_DLQ_ID=dlq_replace_me

go run ./cmd/whcp dead-letter release \
  --entry-id "$WEBHOOKERY_DLQ_ID" \
  --reason-code receiver_fixed \
  --reason "stripe live-proof receiver recovered" \
  --api-key "$WEBHOOKERY_API_KEY"
```

## 6. Generate A Private Incident Packet

```bash
mkdir -p live-proof-private/stripe

go run ./cmd/whcp incidents create \
  --title "Stripe test-mode webhook failed then replayed" \
  --reason "stripe live-provider proof" \
  --api-key "$WEBHOOKERY_API_KEY"

export WEBHOOKERY_INCIDENT_ID=inc_replace_me

go run ./cmd/whcp incidents add-event \
  --incident-id "$WEBHOOKERY_INCIDENT_ID" \
  --event-id "$WEBHOOKERY_EVENT_ID" \
  --reason "attach Stripe proof event" \
  --api-key "$WEBHOOKERY_API_KEY"

go run ./cmd/whcp incidents generate-report \
  --incident-id "$WEBHOOKERY_INCIDENT_ID" \
  --reason "stripe proof report" \
  --api-key "$WEBHOOKERY_API_KEY"

go run ./cmd/whcp incidents report \
  --incident-id "$WEBHOOKERY_INCIDENT_ID" \
  --format markdown \
  --output live-proof-private/stripe/incident-report.private.md \
  --api-key "$WEBHOOKERY_API_KEY"

go run ./cmd/whcp incidents export \
  --incident-id "$WEBHOOKERY_INCIDENT_ID" \
  --reason "stripe proof bundle" \
  --output live-proof-private/stripe/evidence.private.tar.gz \
  --api-key "$WEBHOOKERY_API_KEY"
```

The `live-proof-private/` directory is an operator convention for local proof
artifacts. Do not commit it.

## 7. Redact A Shareable Sample

Use `docs/live-provider-proof/stripe-redaction-policy.md`. A committed sample
shape lives at
`docs/live-provider-proof/samples/stripe-incident-report.redacted.md`.

Before sharing any proof:

```bash
go run ./cmd/whcp audit verify-bundle \
  --file live-proof-private/stripe/evidence.private.tar.gz
make provider-proof-check
```

## Cleanup

1. Stop `stripe listen`.
2. Delete or disable the Stripe test endpoint if you created one in Workbench.
3. Rotate or delete the Webhookery source secret.
4. Disable proof routes and endpoints.
5. Remove private proof artifacts from shared machines.

