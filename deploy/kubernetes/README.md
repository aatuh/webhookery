# Kubernetes Profile

This directory is the minimal raw-manifest deployment profile for Webhookery.
Use `docs/deployment.md` for common production posture, `docs/configuration.md`
for environment variables, and `docs/operations.md` for readiness, backup,
restore, and incident procedures.

The profile deploys the API, worker, scheduler, migration Job, ConfigMap, and a
placeholder Secret shape. It does not install PostgreSQL, object storage,
ingress, DNS, TLS certificates, network policies, service monitors, or an
external secret manager.

## Prerequisites

- A Kubernetes cluster with access to the Webhookery image registry.
- PostgreSQL provisioned outside these manifests.
- Optional S3-compatible object storage when `WEBHOOKERY_RAW_STORAGE_MODE=s3`.
- A real Kubernetes Secret named `webhookery-secrets`.
- TLS or ingress handled by an operator-owned profile layer.

## Secrets Boundary

`secret.example.yaml` documents the required key names with placeholders only.
Do not apply it unchanged to a shared or production cluster, and do not commit
real database URLs, master keys, provider credentials, raw signatures, raw
payloads, or customer data.

Create the Secret through the cluster's normal secret-management workflow. For a
throwaway cluster, the equivalent shape is:

```bash
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl -n webhookery create secret generic webhookery-secrets \
  --from-literal=WEBHOOKERY_DATABASE_URL='postgres://webhookery:replace-me@postgres.example.internal:5432/webhookery?sslmode=require' \
  --from-literal=WEBHOOKERY_MASTER_KEY_BASE64='replace-with-32-byte-base64-key' \
  --from-literal=WEBHOOKERY_BOOTSTRAP_TENANT_ID='ten_prod' \
  --from-literal=WEBHOOKERY_BOOTSTRAP_API_KEY_HASH='sha256:replace-with-bootstrap-key-hash' \
  --from-literal=WEBHOOKERY_BOOTSTRAP_API_KEY_PREFIX='prod-bootstrap'
```

## Image Pinning

The checked-in manifests use `webhookery:latest` as a placeholder. Before
promotion, replace every workload image with an immutable, signed release image
through a deployment overlay or manifest patch. Keep API, worker, scheduler, and
migration Job images aligned for the same release.

## Apply And Validate

```bash
kubectl apply -k deploy/kubernetes
kubectl -n webhookery wait --for=condition=complete job/webhookery-migrate --timeout=120s
kubectl -n webhookery rollout status deployment/webhookery-api
kubectl -n webhookery rollout status deployment/webhookery-worker
kubectl -n webhookery rollout status deployment/webhookery-scheduler
kubectl -n webhookery get pods,jobs,svc
```

The API readiness endpoint is `/readyz`. The profile exposes an internal
ClusterIP Service; publish it through an operator-owned ingress or gateway.

## Migration Job

`migrate-job.yaml` runs `migrate up` with the same ConfigMap and Secret as the
runtime workloads. It uses `restartPolicy: OnFailure` and `backoffLimit: 3`.
Treat a failed migration Job as a deployment blocker: inspect the Job logs,
preserve the failed database state for analysis, and use `docs/operations.md`
before retrying against important data.
