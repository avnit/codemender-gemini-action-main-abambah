output "project_id" {
  description = "Consumer GCP Project ID"
  value       = var.project_id
}

output "region" {
  description = "Consumer GCP Region"
  value       = var.region
}

output "job_name" {
  description = "Cloud Run Job name"
  value       = google_cloud_run_v2_job.worker_job.name
}

output "service_account_email" {
  description = "Service account email running the worker"
  value       = google_service_account.runner_sa.email
}

output "wif_provider" {
  description = "Workload Identity Provider resource name for GitHub Actions"
  value       = "projects/${data.google_project.current.number}/locations/global/workloadIdentityPools/${var.wif_pool_name}/providers/${var.wif_provider_name}"
}

output "artifacts_bucket" {
  description = "GCS Bucket for scan artifacts"
  value       = google_storage_bucket.artifacts.name
}

output "github_action_example" {
  description = "Workflow snippet for caller repository"
  value       = <<-EOT
    uses: wiz-demo/codemender-gemini-action/.github/workflows/codemender.yml@main
    secrets: inherit
    with:
      action: scan
      project-id: "${var.project_id}"
      region: "${var.region}"
      job-name: "${google_cloud_run_v2_job.worker_job.name}"
      wiz-secret-name: "${var.wiz_secret_name}"
  EOT
}
