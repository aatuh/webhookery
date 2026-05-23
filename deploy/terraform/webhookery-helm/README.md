# Webhookery Helm Terraform Module

This module installs the local Webhookery Helm chart. It is a deployment
wrapper only: it does not create PostgreSQL, object storage, ingress, DNS, TLS
certificates, or Kubernetes Secrets.

Create the Secret through your normal secret-management workflow before
applying this module. At minimum the Secret should contain
`WEBHOOKERY_DATABASE_URL` and `WEBHOOKERY_MASTER_KEY_BASE64`; include object
storage and bootstrap values only when you use those features. Secret values are
intentionally not accepted as module variables because Terraform state is not a
safe place for long-lived database URLs, master keys, or object-store keys.

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

Validate locally:

```bash
terraform fmt -check -recursive deploy/terraform
terraform -chdir=deploy/terraform/webhookery-helm init -backend=false
terraform -chdir=deploy/terraform/webhookery-helm validate
```
