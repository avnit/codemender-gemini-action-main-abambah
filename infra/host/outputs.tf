output "repository_url" {
  description = "Full Docker repository URL"
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${var.artifact_registry_repo}"
}

output "canonical_slim_image" {
  description = "Canonical image URI for consumers to pull"
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${var.artifact_registry_repo}/worker:slim"
}

output "builder_service_account_email" {
  description = "Builder service account email used by GitHub Actions deploy-worker"
  value       = google_service_account.builder_sa.email
}

output "wif_provider" {
  description = "Workload Identity Provider resource name for GitHub Actions"
  value       = "projects/${data.google_project.current.number}/locations/global/workloadIdentityPools/${var.wif_pool_name}/providers/${var.wif_provider_name}"
}

output "github_repository_variables" {
  description = "Variables to set in host GitHub repository settings (Settings -> Secrets and variables -> Actions)"
  value       = <<-EOT
    WIF_PROVIDER: projects/${data.google_project.current.number}/locations/global/workloadIdentityPools/${var.wif_pool_name}/providers/${var.wif_provider_name}
    WIF_SERVICE_ACCOUNT: ${google_service_account.builder_sa.email}
    GCP_PROJECT: ${var.project_id}
    GCP_REGION: ${var.region}
    AR_REPO: ${var.artifact_registry_repo}
  EOT
}
