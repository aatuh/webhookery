# Webhookery Helm Chart

This chart deploys the API, worker, scheduler, and optional migration job. It
does not deploy PostgreSQL or object storage; provide those as managed or
separately operated dependencies.

By default the chart expects an existing Secret named `webhookery-secrets`.
Create it through your normal cluster secret workflow with
`WEBHOOKERY_DATABASE_URL`, `WEBHOOKERY_MASTER_KEY_BASE64`, and any object-store
or bootstrap variables you use. `secret.create=true` is available for local
testing and should be fed by operator-owned values files, not committed values.

```bash
helm lint deploy/helm/webhookery
helm template webhookery deploy/helm/webhookery --set secret.name=webhookery-secrets
```
