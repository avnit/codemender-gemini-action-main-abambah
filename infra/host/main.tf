# ==============================================================================
# Google Cloud APIs Enablement (Host Infrastructure)
# ==============================================================================
resource "google_project_service" "enabled_apis" {
  for_each = toset([
    "artifactregistry.googleapis.com",
    "iam.googleapis.com",
    "run.googleapis.com"
  ])

  project                    = var.project_id
  service                    = each.key
  disable_on_destroy         = false
  disable_dependent_services = false
}

# ==============================================================================
# Artifact Registry Repository (Canonical Docker Image Distribution)
# ==============================================================================
resource "google_artifact_registry_repository" "worker_repo" {
  count         = var.create_ar_repo ? 1 : 0
  project       = var.project_id
  location      = var.region
  repository_id = var.artifact_registry_repo
  description   = "Central container repository for CodeMender Slim worker images"
  format        = "DOCKER"

  depends_on = [google_project_service.enabled_apis]
}

# ==============================================================================
# Image Pull IAM Permissions for Consumers
# ==============================================================================

# Public or Authenticated Users Read Access (Optional)
resource "google_artifact_registry_repository_iam_member" "public_reader" {
  count      = var.public_read ? 1 : 0
  project    = var.project_id
  location   = var.region
  repository = var.artifact_registry_repo
  role       = "roles/artifactregistry.reader"
  member     = "allAuthenticatedUsers"

  depends_on = [google_artifact_registry_repository.worker_repo]
}

# Specific Consumer Service Accounts or Groups Read Access
resource "google_artifact_registry_repository_iam_member" "consumer_readers" {
  for_each   = toset(var.authorized_pull_members)
  project    = var.project_id
  location   = var.region
  repository = var.artifact_registry_repo
  role       = "roles/artifactregistry.reader"
  member     = each.key

  depends_on = [google_artifact_registry_repository.worker_repo]
}

# ==============================================================================
# Builder Service Account (Builds and Pushes Images from GitHub Actions)
# ==============================================================================
resource "google_service_account" "builder_sa" {
  account_id   = var.builder_sa_name
  display_name = "CodeMender Slim Image Builder Service Account"
  project      = var.project_id

  depends_on = [google_project_service.enabled_apis]
}

# Grant Artifact Registry Writer (Allows pushing container images)
resource "google_project_iam_member" "builder_ar_writer" {
  project = var.project_id
  role    = "roles/artifactregistry.writer"
  member  = "serviceAccount:${google_service_account.builder_sa.email}"
}

# ==============================================================================
# Workload Identity Federation (GitHub Actions Authentication for Host Repo)
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

# Impersonation Binding: Allows host GitHub Actions to act as builder_sa
resource "google_service_account_iam_member" "builder_wif_binding" {
  service_account_id = google_service_account.builder_sa.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${local.pool_resource_name}/attribute.repository_owner/${var.github_owner}"

  depends_on = [
    google_iam_workload_identity_pool_provider.github_provider
  ]
}
