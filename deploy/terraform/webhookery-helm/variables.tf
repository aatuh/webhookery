variable "release_name" {
  type        = string
  default     = "webhookery"
  description = "Helm release name."

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", var.release_name))
    error_message = "release_name must be a valid lowercase DNS label."
  }
}

variable "namespace" {
  type        = string
  default     = "webhookery"
  description = "Kubernetes namespace for the release."

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", var.namespace))
    error_message = "namespace must be a valid lowercase DNS label."
  }
}

variable "create_namespace" {
  type        = bool
  default     = true
  description = "Whether Helm should create the namespace."
}

variable "existing_secret_name" {
  type        = string
  default     = "webhookery-secrets"
  description = "Name of an existing Kubernetes Secret with WEBHOOKERY_DATABASE_URL, WEBHOOKERY_MASTER_KEY_BASE64, and optional object-store/bootstrap values. Secret values are intentionally not accepted by this module."

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", var.existing_secret_name))
    error_message = "existing_secret_name must be a valid lowercase DNS label."
  }
}

variable "chart_path" {
  type        = string
  default     = ""
  description = "Optional local path to the Webhookery Helm chart. Defaults to deploy/helm/webhookery in this repository."
}

variable "image_repository" {
  type        = string
  default     = "webhookery"
  description = "Container image repository."
}

variable "image_tag" {
  type        = string
  default     = "latest"
  description = "Container image tag."
}

variable "image_pull_policy" {
  type        = string
  default     = "IfNotPresent"
  description = "Kubernetes imagePullPolicy."
}

variable "api_replicas" {
  type        = number
  default     = 1
  description = "API replica count."
}

variable "worker_replicas" {
  type        = number
  default     = 1
  description = "Worker replica count."
}

variable "scheduler_replicas" {
  type        = number
  default     = 1
  description = "Scheduler replica count."
}

variable "service_type" {
  type        = string
  default     = "ClusterIP"
  description = "API Service type."
}

variable "service_port" {
  type        = number
  default     = 8080
  description = "API Service port."
}

variable "environment" {
  type        = string
  default     = "production"
  description = "WEBHOOKERY_ENVIRONMENT value."
}

variable "http_addr" {
  type        = string
  default     = ":8080"
  description = "WEBHOOKERY_HTTP_ADDR value."
}

variable "log_level" {
  type        = string
  default     = "info"
  description = "WEBHOOKERY_LOG_LEVEL value."
}

variable "enable_ui" {
  type        = bool
  default     = false
  description = "Whether to enable the minimal operator UI."
}

variable "raw_storage_mode" {
  type        = string
  default     = "postgres"
  description = "Raw payload storage mode."

  validation {
    condition     = contains(["postgres", "s3"], var.raw_storage_mode)
    error_message = "raw_storage_mode must be postgres or s3."
  }
}

variable "object_storage_endpoint" {
  type        = string
  default     = ""
  description = "S3-compatible object storage endpoint when raw_storage_mode is s3."
}

variable "object_storage_bucket" {
  type        = string
  default     = ""
  description = "S3-compatible object storage bucket when raw_storage_mode is s3."
}

variable "object_storage_region" {
  type        = string
  default     = ""
  description = "S3-compatible object storage region."
}

variable "object_storage_use_ssl" {
  type        = bool
  default     = true
  description = "Whether object storage uses TLS."
}

variable "bootstrap_tenant_id" {
  type        = string
  default     = "ten_bootstrap"
  description = "Bootstrap tenant id."
}

variable "bootstrap_api_key_prefix" {
  type        = string
  default     = ""
  description = "Bootstrap API key prefix metadata. The hash belongs in the existing Secret, not Terraform values."
}

variable "migrate_enabled" {
  type        = bool
  default     = true
  description = "Whether the Helm chart should render the migration Job."
}

variable "timeout_seconds" {
  type        = number
  default     = 300
  description = "Helm release timeout in seconds."
}
