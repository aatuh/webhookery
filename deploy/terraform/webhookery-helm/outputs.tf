output "release_name" {
  description = "Installed Helm release name."
  value       = helm_release.webhookery.name
}

output "namespace" {
  description = "Kubernetes namespace used by the release."
  value       = helm_release.webhookery.namespace
}

output "status" {
  description = "Helm release status."
  value       = helm_release.webhookery.status
}

output "api_service_name" {
  description = "API Service name rendered by the chart for the default fullname template."
  value       = "${var.release_name}-webhookery-api"
}
