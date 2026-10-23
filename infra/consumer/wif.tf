# ==============================================================================
# Workload Identity Federation (GitHub Actions Authentication)
# ==============================================================================

# Data source to obtain numeric Project Number for WIF resource names
data "google_project" "current" {
  project_id = var.project_id
}

locals {
  pool_resource_name = var.create_wif ? google_iam_workload_identity_pool.github_pool[0].name : "projects/${data.google_project.current.number}/locations/global/workloadIdentityPools/${var.wif_pool_name}"
}

# Optional: Create WIF Pool (if create_wif is true)
resource "google_iam_workload_identity_pool" "github_pool" {
  count                     = var.create_wif ? 1 : 0
  project                   = var.project_id
  workload_identity_pool_id = var.wif_pool_name
  display_name              = "GitHub Actions Pool"
  description               = "Identity pool for GitHub Actions CI/CD"
}

# Optional: Create WIF Provider (if create_wif is true)
resource "google_iam_workload_identity_pool_provider" "github_provider" {
  count                              = var.create_wif ? 1 : 0
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github_pool[0].workload_identity_pool_id
  workload_identity_pool_provider_id = var.wif_provider_name
  display_name                       = "GitHub Actions Provider"

  attribute_mapping = {
    "google.subject"             = "assertion.sub"
    "attribute.actor"            = "assertion.actor"
    "attribute.repository"       = "assertion.repository"
    "attribute.repository_owner" = "assertion.repository_owner"
  }

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

# Impersonation Binding: Allows GitHub Actions from var.github_repo to act as runner_sa
resource "google_service_account_iam_member" "wif_binding" {
  service_account_id = google_service_account.runner_sa.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${local.pool_resource_name}/attribute.repository/${var.github_repo}"

  depends_on = [
    google_iam_workload_identity_pool_provider.github_provider
  ]
}
