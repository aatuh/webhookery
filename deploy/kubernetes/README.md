# Kubernetes Deployment Profile

This directory contains a minimal self-hosted Kubernetes profile for Webhookery.
It assumes PostgreSQL and any S3-compatible object storage are provisioned
outside the manifests.

Before applying, create real secrets from `secret.example.yaml`:

```bash
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl -n webhookery create secret generic webhookery-secrets \
  --from-literal=WEBHOOKERY_DATABASE_URL='postgres://...' \
  --from-literal=WEBHOOKERY_MASTER_KEY_BASE64='...' \
  --from-literal=WEBHOOKERY_BOOTSTRAP_TENANT_ID='ten_prod' \
  --from-literal=WEBHOOKERY_BOOTSTRAP_API_KEY_HASH='sha256:...' \
  --from-literal=WEBHOOKERY_BOOTSTRAP_API_KEY_PREFIX='prod-bootstrap'
```

Then apply the profile:

```bash
kubectl apply -k deploy/kubernetes
kubectl -n webhookery wait --for=condition=complete job/webhookery-migrate --timeout=120s
kubectl -n webhookery rollout status deployment/webhookery-api
kubectl -n webhookery rollout status deployment/webhookery-worker
```

The checked-in manifests use `webhookery:latest` as a placeholder image. Pin a
specific signed image digest for production and manage secrets with your
cluster's normal secret-management system. The profile does not install
PostgreSQL, ingress, TLS certificates, network policies, service monitors, or
object storage.
