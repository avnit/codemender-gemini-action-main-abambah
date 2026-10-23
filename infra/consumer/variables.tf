variable "project_id" {
  description = "Consumer Google Cloud Project ID where Cloud Run runs"
  type        = string
  default     = ""
}

variable "region" {
  description = "Google Cloud Region for the Cloud Run Job"
  type        = string
  default     = "us-central1"
}

variable "job_name" {
  description = "Cloud Run Job name for CodeMender Slim"
  type        = string
  default     = "wiz-codemender-slim"
}

variable "runner_sa_name" {
  description = "Service account account ID for the Cloud Run worker"
  type        = string
  default     = "codemender-slim-runner"
}

variable "image_uri" {
  description = "Container image URI (pulled from host Artifact Registry)"
  type        = string
  default     = ""
}

variable "wiz_secret_name" {
  description = "Secret Manager secret name containing Wiz MCP credentials"
  type        = string
  default     = "wiz-mcp-config"
}

variable "github_repo" {
  description = "GitHub repository (owner/repo) permitted to trigger jobs via Workload Identity"
  type        = string
  default     = ""
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
