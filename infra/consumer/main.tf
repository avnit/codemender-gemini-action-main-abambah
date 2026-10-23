# ==============================================================================
# Google Cloud APIs Enablement (Consumer Project)
# ==============================================================================
resource "google_project_service" "enabled_apis" {
  for_each = toset([
    "run.googleapis.com",
    "secretmanager.googleapis.com",
    "aiplatform.googleapis.com",
    "logging.googleapis.com",
    "iam.googleapis.com",
    "storage.googleapis.com"
  ])

  project                    = var.project_id
  service                    = each.key
  disable_on_destroy         = false
  disable_dependent_services = false
}

# ==============================================================================
# Service Account for CodeMender Slim Worker
# ==============================================================================
resource "google_service_account" "runner_sa" {
  account_id   = var.runner_sa_name
  display_name = "CodeMender Slim Worker Service Account"
  project      = var.project_id

  depends_on = [google_project_service.enabled_apis]
}

# Secret Manager Access (Wiz API Credentials in Consumer Project)
resource "google_project_iam_member" "secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.runner_sa.email}"
}

# Vertex AI Access (Gemini Model Invocations)
resource "google_project_iam_member" "aiplatform_user" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.runner_sa.email}"
}

# Cloud Logging Writer
resource "google_project_iam_member" "logging_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.runner_sa.email}"
}

# Cloud Logging Viewer (Allows GitHub Actions runner to query execution logs)
resource "google_project_iam_member" "logging_viewer" {
  project = var.project_id
  role    = "roles/logging.viewer"
  member  = "serviceAccount:${google_service_account.runner_sa.email}"
}

# Cloud Run Developer (Allows executing Cloud Run jobs)
resource "google_project_iam_member" "run_developer" {
  project = var.project_id
  role    = "roles/run.developer"
  member  = "serviceAccount:${google_service_account.runner_sa.email}"
}

# ==============================================================================
# Cloud Storage: Ephemeral Scan Artifacts Bucket
# ==============================================================================
resource "google_storage_bucket" "artifacts" {
  name                        = "${var.project_id}-codemender-artifacts"
  location                    = var.region
  project                     = var.project_id
  uniform_bucket_level_access = true
  force_destroy               = true

  lifecycle_rule {
    condition {
      age = 1
    }
    action {
      type = "Delete"
    }
  }

  depends_on = [google_project_service.enabled_apis]
}

resource "google_storage_bucket_iam_member" "runner_sa_artifacts_user" {
  bucket = google_storage_bucket.artifacts.name
  role   = "roles/storage.objectUser"
  member = "serviceAccount:${google_service_account.runner_sa.email}"
}

# ==============================================================================
# Cloud Run v2 Job: CodeMender Slim Worker (Pulls from Host GAR)
# ==============================================================================
resource "google_cloud_run_v2_job" "worker_job" {
  name     = var.job_name
  location = var.region
  project  = var.project_id

  deletion_protection = false
  template {
    task_count = 1

    template {
      max_retries     = 2
      timeout         = "1800s"
      service_account = google_service_account.runner_sa.email

      containers {
        image = var.image_uri

        resources {
          limits = {
            cpu    = "2"
            memory = "4Gi"
          }
        }

        env {
          name  = "CM_DISABLE_SANDBOX"
          value = "true"
        }
        env {
          name  = "WIZ_SECRET_NAME"
          value = var.wiz_secret_name
        }
        env {
          name  = "PROJECT_ID"
          value = var.project_id
        }
        env {
          name  = "SCAN_ARTIFACTS_BUCKET"
          value = google_storage_bucket.artifacts.name
        }
      }
    }
  }

  lifecycle {
    ignore_changes = [
      template[0].template[0].containers[0].image
    ]
  }

  depends_on = [
    google_project_service.enabled_apis,
    google_service_account.runner_sa,
    google_storage_bucket.artifacts
  ]
}
