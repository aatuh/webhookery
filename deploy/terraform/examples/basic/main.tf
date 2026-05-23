terraform {
  required_version = ">= 1.5.0"
}

module "webhookery" {
  source = "../../webhookery-helm"

  namespace            = "webhookery"
  release_name         = "webhookery"
  existing_secret_name = "webhookery-secrets"
}
