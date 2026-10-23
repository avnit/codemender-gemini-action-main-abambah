variable "project_id" {
  description = "The central host GCP project ID where the image repository is hosted"
  type        = string
}

variable "region" {
  description = "The Google Cloud region for the Artifact Registry repository"
  type        = string
  default     = "us-central1"
}

variable "artifact_registry_repo" {
  description = "Artifact Registry repository name for CodeMender worker images"
  type        = string
  default     = "wiz-codemender-images"
}

variable "builder_sa_name" {
  description = "Service account account ID for the image builder"
  type        = string
  default     = "codemender-slim-builder"
}

variable "github_owner" {
  description = "GitHub organization or user owner"
  type        = string
  default     = "wiz-demo"
}

variable "github_repo" {
  description = "Host GitHub repository (owner/repo) permitted to build and push images via WIF"
  type        = string
  default     = "wiz-demo/codemender-gemini-action"
}

variable "wif_pool_name" {
  description = "Workload Identity Pool name (defaults to existing codemender-pool)"
  type        = string
  default     = "codemender-pool"
}

variable "wif_provider_name" {
  description = "Workload Identity Provider name"
  type        = string
  default     = "github-provider"
}

variable "create_wif" {
  description = "Whether to create WIF pool and provider (true) or bind to existing WIF pool (false)"
  type        = bool
  default     = false
}

variable "create_ar_repo" {
  description = "Whether to create Artifact Registry repository (true) or reuse existing (false)"
  type        = bool
  default     = false
}

variable "public_read" {
  description = "Whether to allow all authenticated users to pull the image"
  type        = bool
  default     = false
}

variable "authorized_pull_members" {
  description = "List of IAM members (e.g. serviceAccount:..., group:...) granted pull access if not public"
  type        = list(string)
  default     = []
}
