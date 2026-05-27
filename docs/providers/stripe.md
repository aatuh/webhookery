# Stripe Operator Guide

This guide is for operators configuring Stripe as a Webhookery source. It
covers the implemented Webhookery behavior and the Stripe behavior that was
checked against official docs on 2026-06-04.

## Scope

Implemented Webhookery behavior:

- `Stripe-Signature` `v1` HMAC-SHA256 verification over
  `timestamp.raw_body`.
- Five-minute timestamp tolerance for replay protection.
- Event identity from JSON `id` and event type from JSON `type`.
- Duplicate events remain visible as evidence; dedupe can suppress processing
  but must not erase receipts or raw payload metadata.
- Replay creates new delivery work linked to the original event or delivery.

This guide does not claim Stripe provider certification, provider-side event
completeness, ordering, exactly-once delivery, or downstream business success.
In short: this is not provider certification.

Official sources checked:

- <https://docs.stripe.com/webhooks>
- <https://docs.stripe.com/webhooks/signature>

## Setup

Use a disposable Stripe sandbox or test-mode account first. Do not use live
customer data for proof runs.

1. Start Webhookery and set a control-plane API key:

   ```bash
   cp .env.example .env
   docker compose up --build
   export WEBHOOKERY_API_KEY=dev-bootstrap-key
   ```

2. Create a Stripe source with a temporary placeholder. Stripe CLI signing
   secrets are printed after `stripe listen` starts, so rotate the source
   secret after the listener prints the real test secret.

   ```bash
   go run ./cmd/whcp sources create \
     --name stripe-test-mode \
     --provider stripe \
     --secret temporary-local-placeholder \
     --api-key "$WEBHOOKERY_API_KEY"
   ```

3. Save the returned source ID outside commits:

   ```bash
   export WEBHOOKERY_STRIPE_SOURCE_ID=src_replace_me
   ```

4. Start a Stripe CLI listener in another shell and forward only the event
   types needed for the proof:

   ```bash
   stripe listen \
     --events payment_intent.succeeded,payment_intent.payment_failed \
     --forward-to "http://localhost:8080/v1/ingest/stripe/${WEBHOOKERY_STRIPE_SOURCE_ID}"
   ```

5. Copy the webhook signing secret from the `stripe listen` output into a local
   shell variable. Do not paste it into docs, issues, screenshots, or commits.

   ```bash
   export WEBHOOKERY_STRIPE_WEBHOOK_SECRET='replace-with-local-listener-secret'
   go run ./cmd/whcp sources rotate-secret \
     --source-id "$WEBHOOKERY_STRIPE_SOURCE_ID" \
     --secret "$WEBHOOKERY_STRIPE_WEBHOOK_SECRET" \
     --reason "stripe test-mode listener secret" \
     --api-key "$WEBHOOKERY_API_KEY"
   ```

For a public HTTPS endpoint created in Stripe Workbench, use the same source
ID in the endpoint URL, then rotate the source to the endpoint-specific signing
secret shown by Stripe.

## Routing And Downstream Failure

Create a disposable receiver that can first return `500` and later return
`204`. Use an HTTPS endpoint for public Stripe deliveries; local CLI forwarding
can use `http://localhost`.

```bash
export WEBHOOKERY_FAILING_RECEIVER_URL='https://receiver.example.test/fail-first'

go run ./cmd/whcp endpoints validate-url \
  --url "$WEBHOOKERY_FAILING_RECEIVER_URL" \
  --api-key "$WEBHOOKERY_API_KEY"

go run ./cmd/whcp endpoints create \
  --name stripe-proof-receiver \
  --url "$WEBHOOKERY_FAILING_RECEIVER_URL" \
  --api-key "$WEBHOOKERY_API_KEY"

export WEBHOOKERY_ENDPOINT_ID=end_replace_me

go run ./cmd/whcp routes create \
  --name stripe-payment-proof \
  --source-id "$WEBHOOKERY_STRIPE_SOURCE_ID" \
  --endpoint-id "$WEBHOOKERY_ENDPOINT_ID" \
  --event-types payment_intent.succeeded,payment_intent.payment_failed \
  --state draft \
  --api-key "$WEBHOOKERY_API_KEY"

export WEBHOOKERY_ROUTE_ID=rte_replace_me

go run ./cmd/whcp routes activate \
  --route-id "$WEBHOOKERY_ROUTE_ID" \
  --reason "stripe proof route activation" \
  --api-key "$WEBHOOKERY_API_KEY"
```

## Local And Live Test Modes

Local deterministic test:

- Run `examples/webhook-evidence-demo/run.sh`.
- Inspect `examples/webhook-evidence-demo/output/incident-report.md`.
- This uses synthetic Stripe-style vectors and does not contact Stripe.

Stripe test-mode proof:

1. Keep the Stripe CLI listener running.
2. Trigger a test event:

   ```bash
   stripe trigger payment_intent.succeeded
   ```

3. Find the captured event and inspect the timeline:

   ```bash
   go run ./cmd/whcp events list --api-key "$WEBHOOKERY_API_KEY"
   export WEBHOOKERY_EVENT_ID=evt_replace_me
   go run ./cmd/whcp events timeline \
     --event-id "$WEBHOOKERY_EVENT_ID" \
     --format markdown \
     --api-key "$WEBHOOKERY_API_KEY"
   ```

The timeline should show durable capture, provider verification, route
matching, delivery attempts, and any retry or DLQ transition.

## Signature Verification

Stripe includes a timestamp in `Stripe-Signature`; Webhookery verifies the
signed timestamp and raw body before treating the event as trusted. Keep these
operating rules:

- Preserve exact raw request bytes until verification completes.
- Use the endpoint-specific signing secret for the exact listener or Stripe
  Workbench endpoint.
- Reject or quarantine missing, malformed, stale, or wrong-secret signatures.
- Keep system clocks synchronized; timestamp verification depends on current
  time.

## Duplicate Handling

Stripe can retry deliveries and manual resends can create additional inbound
attempts. Webhookery records duplicate evidence rather than hiding it. Use the
event timeline and incident report to distinguish:

- original capture evidence;
- duplicate receipts;
- dedupe suppression, when processing is suppressed;
- downstream retry attempts; and
- operator-initiated Webhookery replay.

## Retry Expectations

Stripe live-mode delivery retries can continue for up to three days with
exponential backoff. Stripe sandbox deliveries have a shorter retry pattern.
Webhookery's own downstream delivery retries are separate evidence: they record
attempts from Webhookery to your configured receiver after the provider event
has already been durably captured.

Do not collapse Stripe retry evidence and Webhookery replay evidence into one
claim. They happen on different sides of the control plane.

## Manual Recovery Limitations

Stripe manual resend is useful for proof and recovery, but it is not a
provider-side completeness guarantee. If the provider cannot redeliver an
older event, Webhookery can only report the gap unless reconciliation against
Stripe APIs is explicitly configured and records provider API evidence.

Recovered provider API evidence is not the same as signed webhook evidence.

## Replay Workflow

After the receiver is fixed, replay with an explicit reason:

```bash
go run ./cmd/whcp replay-jobs dry-run \
  --event-id "$WEBHOOKERY_EVENT_ID" \
  --config-mode original \
  --reason-code receiver_fixed \
  --reason "stripe proof receiver fixed before replay" \
  --api-key "$WEBHOOKERY_API_KEY"

go run ./cmd/whcp replay-jobs create \
  --event-id "$WEBHOOKERY_EVENT_ID" \
  --config-mode original \
  --reason-code receiver_fixed \
  --reason "stripe proof receiver fixed before replay" \
  --api-key "$WEBHOOKERY_API_KEY"
```

If the event reached DLQ, release the DLQ entry instead:

```bash
go run ./cmd/whcp dead-letter list --api-key "$WEBHOOKERY_API_KEY"
export WEBHOOKERY_DLQ_ID=dlq_replace_me
go run ./cmd/whcp dead-letter release \
  --entry-id "$WEBHOOKERY_DLQ_ID" \
  --reason-code receiver_fixed \
  --reason "stripe proof receiver recovered" \
  --api-key "$WEBHOOKERY_API_KEY"
```

## Incident Packet Example

Generate a report and evidence export after replay:

```bash
go run ./cmd/whcp incidents create \
  --title "Stripe test-mode payment webhook failed then replayed" \
  --reason "stripe proof investigation" \
  --api-key "$WEBHOOKERY_API_KEY"

export WEBHOOKERY_INCIDENT_ID=inc_replace_me

go run ./cmd/whcp incidents add-event \
  --incident-id "$WEBHOOKERY_INCIDENT_ID" \
  --event-id "$WEBHOOKERY_EVENT_ID" \
  --reason "attach Stripe test event" \
  --api-key "$WEBHOOKERY_API_KEY"

go run ./cmd/whcp incidents generate-report \
  --incident-id "$WEBHOOKERY_INCIDENT_ID" \
  --reason "stripe proof report" \
  --api-key "$WEBHOOKERY_API_KEY"

go run ./cmd/whcp incidents report \
  --incident-id "$WEBHOOKERY_INCIDENT_ID" \
  --format markdown \
  --output stripe-incident-report.private.md \
  --api-key "$WEBHOOKERY_API_KEY"

go run ./cmd/whcp incidents export \
  --incident-id "$WEBHOOKERY_INCIDENT_ID" \
  --reason "stripe proof evidence export" \
  --output stripe-incident-evidence.private.tar.gz \
  --api-key "$WEBHOOKERY_API_KEY"
```

Keep completed live reports and bundles private. Commit only sanitized samples
such as `docs/live-provider-proof/samples/stripe-incident-report.redacted.md`.

## Non-Claims

This guide does not prove:

- downstream business processing succeeded;
- Stripe will redeliver every provider-side event forever;
- global event ordering;
- exactly-once delivery;
- compliance or legal evidentiary certification; or
- safe use of production customer data in public evidence.
