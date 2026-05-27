# Observability Examples

Webhookery exposes operational state through authenticated ops APIs and public
aggregate Prometheus metrics. These examples are starting points for self-
hosted operators. They are not hosted dashboards or managed monitoring.

Public `/metrics` output intentionally avoids tenant labels. Tenant-scoped
views belong behind authenticated APIs such as `/v1/ops/metrics`,
`/v1/ops/metrics/rollups`, `/v1/alerts`, and `/v1/alert-firings`.

## Prometheus Scrape

Example scrape target:

```yaml
scrape_configs:
  - job_name: webhookery
    metrics_path: /metrics
    static_configs:
      - targets:
          - webhookery-api.webhookery.svc.cluster.local:8080
```

The example alert rules live at
`deploy/observability/prometheus-rules.example.yaml`.

## Core Metrics

| Metric | Meaning | Operator use |
|--------|---------|--------------|
| `webhookery_events_total` | Total captured canonical events. | Compare ingest volume to provider/producer expectations. |
| `webhookery_outbox_pending` | Pending durable outbox rows. | Detect worker lag or stuck routing/recovery work. |
| `webhookery_outbox_oldest_age_seconds` | Age of the oldest pending outbox row. | Primary queue-drain freshness signal. |
| `webhookery_dead_letter_open` | Open DLQ entries. | Trigger explicit retry/replay/release triage. |
| `webhookery_quarantine_open` | Open quarantine entries. | Review rejected provider evidence or unsafe requests. |
| `webhookery_endpoint_circuit_open` | Open endpoint circuits. | Identify receiver-side failure or disabled delivery paths. |
| `webhookery_audit_chain_unchained_events` | Audit events missing chain entries. | Treat as trust-boundary incident until verified. |
| `webhookery_audit_chain_verification_failures` | Audit-chain entries that fail verification. | Preserve state and investigate immediately. |
| `webhookery_audit_chain_last_anchor_age_seconds` | Age of newest local/object-store anchor. | Review anchor cadence. |
| `webhookery_deliveries{state="..."}` | Delivery counts by state. | Watch scheduled, in-progress, succeeded, and failed trends. |
| `webhookery_replay_jobs{state="..."}` | Replay job counts by state. | Ensure replay does not starve live work. |
| `webhookery_reconciliation_jobs{state="..."}` | Reconciliation jobs by state. | Track provider gap review backlog. |
| `webhookery_reconciliation_items{outcome="..."}` | Reconciliation item outcomes. | Identify failed or unrecoverable provider-side gaps. |

## Dashboard Panels

Start with these panels:

- Capture: `rate(webhookery_events_total[5m])`.
- Queue depth: `webhookery_outbox_pending`.
- Queue freshness: `webhookery_outbox_oldest_age_seconds`.
- Delivery state: `sum by (state) (webhookery_deliveries)`.
- DLQ and quarantine: `webhookery_dead_letter_open` and
  `webhookery_quarantine_open`.
- Audit chain: `webhookery_audit_chain_verification_failures` and
  `webhookery_audit_chain_unchained_events`.
- Reconciliation outcomes:
  `sum by (outcome) (webhookery_reconciliation_items)`.
- Signal egress: use authenticated alert/notification/SIEM APIs for detailed
  delivery attempts; keep public metrics aggregate-only.

## Incident Links

When an alert fires, pair dashboard data with evidence APIs:

```bash
whcp ops queues --api-key "$WEBHOOKERY_API_KEY"
whcp alerts firings --api-key "$WEBHOOKERY_API_KEY"
whcp audit verify-chain --api-key "$WEBHOOKERY_API_KEY"
whcp reconciliation jobs --api-key "$WEBHOOKERY_API_KEY"
```

Expected result: operators can determine whether the issue is capture,
storage, delivery, replay, reconciliation, audit-chain, or operational signal
egress without exposing raw payload bodies or secrets.
