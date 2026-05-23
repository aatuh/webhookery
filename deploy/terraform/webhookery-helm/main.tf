locals {
  chart_path = var.chart_path == "" ? abspath("${path.module}/../../helm/webhookery") : var.chart_path

  values = {
    replicaCount = {
      api       = var.api_replicas
      worker    = var.worker_replicas
      scheduler = var.scheduler_replicas
    }
    image = {
      repository = var.image_repository
      tag        = var.image_tag
      pullPolicy = var.image_pull_policy
    }
    service = {
      type = var.service_type
      port = var.service_port
    }
    config = {
      environment           = var.environment
      httpAddr              = var.http_addr
      logLevel              = var.log_level
      enableUI              = tostring(var.enable_ui)
      rawStorageMode        = var.raw_storage_mode
      objectStorageEndpoint = var.object_storage_endpoint
      objectStorageBucket   = var.object_storage_bucket
      objectStorageRegion   = var.object_storage_region
      objectStorageUseSSL   = tostring(var.object_storage_use_ssl)
      bootstrapTenantID     = var.bootstrap_tenant_id
      bootstrapAPIKeyPrefix = var.bootstrap_api_key_prefix
    }
    secret = {
      create = false
      name   = var.existing_secret_name
    }
    migrate = {
      enabled = var.migrate_enabled
    }
  }
}

resource "helm_release" "webhookery" {
  name             = var.release_name
  namespace        = var.namespace
  create_namespace = var.create_namespace
  chart            = local.chart_path
  wait             = true
  timeout          = var.timeout_seconds

  values = [
    yamlencode(local.values)
  ]
}
