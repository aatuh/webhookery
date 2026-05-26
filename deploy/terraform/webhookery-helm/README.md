# Webhookery Helm Terraform Module

This module installs the local Webhookery Helm chart through `helm_release`.
Use `docs/deployment.md` for common production posture, `docs/configuration.md`
for environment variables, and `docs/operations.md` for readiness, backup,
restore, and incident procedures.

The module is a deployment wrapper only. It does not create PostgreSQL, object
storage, ingress, DNS, TLS certificates, Kubernetes Secrets, network policies,
or external secret-manager resources.

## Prerequisites

- Terraform with the Helm provider.
- Cluster credentials for the target Kubernetes cluster.
- PostgreSQL provisioned outside this module.
- Optional S3-compatible object storage when `raw_storage_mode = "s3"`.
- A real Kubernetes Secret already present in the target namespace.
- A pinned Webhookery image available to the cluster.

## Secrets Boundary

Create the Secret through your normal secret-management workflow before applying
this module. At minimum, it should contain `WEBHOOKERY_DATABASE_URL` and
`WEBHOOKERY_MASTER_KEY_BASE64`; include object-storage and bootstrap values only
when you use those features.

Secret values are intentionally not accepted as module variables because
Terraform state is not a safe place for long-lived database URLs, master keys,
provider credentials, object-store keys, raw signatures, raw payloads, or
customer data.

## Image Pinning

Do not leave the defaults `image_repository = "webhookery"` and
`image_tag = "latest"` in promoted environments. Set the repository and an
immutable release tag explicitly:

```hcl
module "webhookery" {
  source = "../../deploy/terraform/webhookery-helm"

  namespace            = "webhookery"
  release_name         = "webhookery"
  existing_secret_name = "webhookery-secrets"

  image_repository = "registry.example.com/webhookery"
  image_tag        = "2026.05.25"
}
```

Use an operator-owned image signing policy. If your environment requires
digest-only image references, update the Helm chart and this module before
relying on them for that deployment mode.

## Validate

```bash
terraform fmt -check -recursive deploy/terraform
terraform -chdir=deploy/terraform/webhookery-helm init -backend=false
terraform -chdir=deploy/terraform/webhookery-helm validate
terraform -chdir=deploy/terraform/webhookery-helm plan
```

Run `plan` only with a workspace that is allowed to read the target cluster
state. Do not provide secret values through Terraform variables.

## Migration Job

`migrate_enabled = true` is the default. The module forwards that setting to the
Helm chart, which renders a migration Job and waits for the Helm release. Leave
the Job enabled unless another controlled migration process runs the same
migrations, blocks rollout on failure, and records release evidence.
