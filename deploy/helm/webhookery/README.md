# Webhookery Helm Chart

This chart deploys the API, worker, scheduler, Service, ConfigMap, Secret
reference, and optional migration Job. Use `docs/deployment.md` for common
production posture, `docs/configuration.md` for environment variables, and
`docs/operations.md` for readiness, backup, restore, and incident procedures.

The chart does not deploy PostgreSQL, object storage, ingress, DNS, TLS
certificates, network policies, service monitors, or an external secret manager.

`values-production.example.yaml` is a hardened starting overlay with multiple
replicas, resource requests, S3-mode placeholders, and non-root security
contexts. It still expects operator-managed secrets and external dependencies.

## Prerequisites

- A Kubernetes cluster and Helm 3.
- PostgreSQL provisioned outside the chart.
- Optional S3-compatible object storage when `WEBHOOKERY_RAW_STORAGE_MODE=s3`.
- A real Kubernetes Secret containing database, master-key, object-store, and
  bootstrap values required by your deployment.
- A pinned Webhookery image available to the cluster.

## Secrets Boundary

By default, the chart expects an existing Secret named `webhookery-secrets`.
Create or sync that Secret through your normal secret-management workflow.

`secret.create=true` exists for local testing and controlled review
environments. Feed it with operator-owned values files that are not committed.
Do not put real database URLs, master keys, provider credentials, private keys,
raw signatures, raw payloads, or customer data in committed values.

## Image Pinning

The default image is the placeholder `webhookery:latest`. Override it for every
deployment:

```bash
helm upgrade --install webhookery deploy/helm/webhookery \
  --namespace webhookery \
  --create-namespace \
  --set fullnameOverride=webhookery \
  --set secret.name=webhookery-secrets \
  --set image.repository=registry.example.com/webhookery \
  --set image.tag=2026.05.25
```

Use an immutable release tag and an operator-owned image signing policy. If your
environment requires digest-only image references, update the chart values and
templates before relying on this chart for that deployment mode.

## Validate

```bash
helm lint deploy/helm/webhookery
helm template webhookery deploy/helm/webhookery \
  --set fullnameOverride=webhookery \
  --set secret.name=webhookery-secrets
helm upgrade --install webhookery deploy/helm/webhookery \
  --namespace webhookery \
  --create-namespace \
  --set fullnameOverride=webhookery \
  --set secret.name=webhookery-secrets \
  --dry-run
```

After install, wait for the migration Job and workload rollouts:

```bash
kubectl -n webhookery wait --for=condition=complete job/webhookery-migrate --timeout=120s
kubectl -n webhookery rollout status deployment/webhookery-api
kubectl -n webhookery rollout status deployment/webhookery-worker
kubectl -n webhookery rollout status deployment/webhookery-scheduler
```

## Migration Job

`migrate.enabled=true` renders a Job that runs
`migrate -dir migrations up` before the runtime workloads are considered ready.
Keep the migration image pinned to the same release as the API, worker, and
scheduler. Disable the Job only when another controlled process runs the same
migrations and records the release evidence.
