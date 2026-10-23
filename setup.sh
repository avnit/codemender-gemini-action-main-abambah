#!/usr/bin/env bash
# ==============================================================================
# CodeMender Slim - Automated Interactive Setup for Google Cloud & Wiz
# ==============================================================================
# Imperative, idempotent equivalent of `infra/consumer` Terraform. Verifies
# Google Cloud API enablement, prompts securely for Wiz credentials, configures
# Secret Manager, provisions runner IAM, creates the ephemeral scan artifacts
# bucket, deploys the Cloud Run Job, and optionally wires up GitHub Workload
# Identity Federation.
# ==============================================================================
set -euo pipefail

START_TIME=$(date +%s)

# Styling & Colors (disabled if not in an interactive terminal)
if [[ -t 1 ]] && [[ "${TERM:-dumb}" != "dumb" ]]; then
  GREEN='\033[0;32m'
  RED='\033[0;31m'
  YELLOW='\033[1;33m'
  BLUE='\033[0;34m'
  CYAN='\033[0;36m'
  BOLD='\033[1m'
  DIM='\033[2m'
  RESET='\033[0m'
else
  GREEN=''
  RED=''
  YELLOW=''
  BLUE=''
  CYAN=''
  BOLD=''
  DIM=''
  RESET=''
fi

log_info()    { echo -e "${BLUE}ℹ${RESET}  $*"; }
log_success() { echo -e "${GREEN}✓${RESET}  $*"; }
log_warn()    { echo -e "${YELLOW}▲${RESET}  $*"; }
log_error()   { echo -e "${RED}✗${RESET}  $*" >&2; }
log_step()    { echo -e "\n${CYAN}${BOLD}[$1]${RESET} ${BOLD}$2${RESET}"; }

# Trims surrounding whitespace and lowercases a value.
trim_lower() {
  local v="$1"
  v="${v#"${v%%[![:space:]]*}"}"
  v="${v%"${v##*[![:space:]]}"}"
  printf '%s' "${v}" | tr '[:upper:]' '[:lower:]'
}

STEP_NUM=0
TOTAL_STEPS=7
next_step() {
  STEP_NUM=$((STEP_NUM + 1))
  log_step "${STEP_NUM}/${TOTAL_STEPS}" "$1"
}

# Safe Cleanup Trap
LIFECYCLE_FILE=""
cleanup() {
  unset WIZ_CLIENT_SECRET WIZ_CLIENT_SECRET_CONFIRM WIZ_SECRET_PAYLOAD 2>/dev/null || true
  if [[ -n "${LIFECYCLE_FILE}" ]]; then
    rm -f "${LIFECYCLE_FILE}" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

# Default Configuration Values (kept in sync with infra/consumer/variables.tf)
PROJECT_ID="${PROJECT_ID:-}"
REGION="${REGION:-}"
JOB_NAME="${JOB_NAME:-wiz-codemender-slim}"
RUNNER_SA_NAME="${RUNNER_SA_NAME:-codemender-slim-runner}"
WIZ_SECRET_NAME="${WIZ_SECRET_NAME:-wiz-mcp-config}"
IMAGE_URI_EXPLICIT=false
[[ -n "${IMAGE_URI:-}" ]] && IMAGE_URI_EXPLICIT=true
# No default: pass --image / IMAGE_URI (or enter at the prompt). --builder/--collapsed derive it
# from this project's Artifact Registry repo unless explicitly set.
IMAGE_URI="${IMAGE_URI:-}"
JOB_MAX_RETRIES="${JOB_MAX_RETRIES:-2}"
WIZ_CLIENT_ID="${WIZ_CLIENT_ID:-}"
WIZ_CLIENT_SECRET="${WIZ_CLIENT_SECRET:-}"
WIZ_DATACENTER="${WIZ_DATACENTER:-}"
# Wiz tenant env (flag/prompt only, never read from the environment). It only selects the
# MCP endpoint (https://mcp.<env>.wiz.io?mode=explicit) stored as `mcp_url` in the secret.
TENANT_ENV=""
WIZ_MCP_URL=""
NON_INTERACTIVE="${NON_INTERACTIVE:-false}"
DRY_RUN="${DRY_RUN:-false}"
CONFIGURE_WIF="${CONFIGURE_WIF:-}"
GITHUB_REPO="${GITHUB_REPO:-}"
WIF_POOL_NAME="${WIF_POOL_NAME:-codemender-pool}"
WIF_PROVIDER_NAME="${WIF_PROVIDER_NAME:-github-provider}"
WIF_ATTRIBUTE_CONDITION="${WIF_ATTRIBUTE_CONDITION:-}"
CALLER_WORKFLOW_REF="${CALLER_WORKFLOW_REF:-}"

# Builder / host resources (kept in sync with infra/host/variables.tf)
PROVISION_BUILDER="${PROVISION_BUILDER:-false}"
BUILDER_ONLY="${BUILDER_ONLY:-false}"
COLLAPSED="${COLLAPSED:-false}"
BUILDER_SA_NAME="${BUILDER_SA_NAME:-codemender-slim-builder}"
AR_REPO="${AR_REPO:-wiz-codemender-images}"
# No default: must be passed explicitly (--github-owner / GITHUB_OWNER) or entered at the prompt.
GITHUB_OWNER="${GITHUB_OWNER:-}"
PUBLIC_READ="${PUBLIC_READ:-false}"
PULL_MEMBERS=()

usage() {
  cat <<EOF
CodeMender Slim - Cloud Run & Wiz Setup

Usage: ./setup.sh [OPTIONS]

Options:
  -p, --project <PROJECT_ID>     Google Cloud Project ID (default: auto-detected from the
                                 active gcloud config / Cloud Shell session project)
  -r, --region <REGION>          Cloud Run region (default: us-central1)
  -j, --job-name <NAME>          Cloud Run Job name (default: wiz-codemender-slim)
  -s, --sa-name <NAME>           Runner Service Account name (default: codemender-slim-runner)
  --secret-name <NAME>           Secret Manager secret name (default: wiz-mcp-config)
  --datacenter <DC>              Wiz DataCenter of your tenant (e.g. us20, eu1). Required; no default
  --tenant-env <ENV>             Wiz tenant environment used to build the MCP URL
                                 https://mcp.<ENV>.wiz.io?mode=explicit (default: app)
  --image <IMAGE_URI>            Worker container image URI (pulled from host Artifact Registry).
                                 Required for consumer-only setup; no default
  --wif                          Configure GitHub Workload Identity Federation
  --github-repo <OWNER/REPO>     GitHub repository permitted to trigger jobs via WIF
  --wif-pool <NAME>              Workload Identity Pool name (default: codemender-pool)
  --wif-provider <NAME>          Workload Identity Provider name (default: github-provider)
  --attribute-condition <EXPR>   CEL condition on provider (defaults to assertion.repository_owner == '<OWNER>')
  --caller-workflow-ref <REF>    Reusable workflow ref for the printed caller snippet, e.g.
                                 <owner>/<repo>/.github/workflows/codemender.yml@main (no default)
  -y, --yes, --non-interactive   Run non-interactively using defaults / environment variables
  --dry-run                      Simulate execution without modifying Google Cloud resources
  -h, --help                     Show this help message and exit

Builder / Host Options (mirrors infra/host Terraform):
  --builder                      Provision ONLY the builder/host resources in this project:
                                 Artifact Registry repo, builder service account, and GitHub
                                 WIF for the deploy-worker pipeline (skips consumer setup)
  --collapsed                    Host + consumer in ONE project: provisions builder resources
                                 AND the consumer stack, sharing a single WIF pool/provider,
                                 with a separate builder SA and runner SA
  --builder-sa-name <NAME>       Builder Service Account name (default: codemender-slim-builder)
  --ar-repo <NAME>               Artifact Registry repository (default: wiz-codemender-images)
  --github-owner <OWNER>         GitHub org/user allowed to impersonate the builder via WIF
                                 (required with --builder / --collapsed; no default)
  --pull-member <MEMBER>         Grant image pull (roles/artifactregistry.reader), e.g.
                                 serviceAccount:service-123@serverless-robot-prod.iam.gserviceaccount.com
                                 (repeatable)
  --public-read                  Allow allAuthenticatedUsers to pull worker images

Environment Variables:
  PROJECT_ID, REGION, JOB_NAME, RUNNER_SA_NAME, WIZ_SECRET_NAME, IMAGE_URI, JOB_MAX_RETRIES,
  WIZ_CLIENT_ID, WIZ_CLIENT_SECRET, WIZ_DATACENTER, CONFIGURE_WIF, GITHUB_REPO,
  WIF_POOL_NAME, WIF_PROVIDER_NAME, CALLER_WORKFLOW_REF, NON_INTERACTIVE, DRY_RUN,
  PROVISION_BUILDER, BUILDER_ONLY, BUILDER_SA_NAME, AR_REPO, GITHUB_OWNER, PUBLIC_READ

Resources (mirrors infra/consumer Terraform):
  APIs, Secret Manager secret, runner service account + IAM, scan artifacts bucket
  (<PROJECT_ID>-codemender-artifacts), Cloud Run Job, and optional GitHub WIF binding.

EOF
}

# Parse Command-Line Arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    -p|--project)
      PROJECT_ID="$2"
      shift 2
      ;;
    -r|--region)
      REGION="$2"
      shift 2
      ;;
    -j|--job-name)
      JOB_NAME="$2"
      shift 2
      ;;
    -s|--sa-name)
      RUNNER_SA_NAME="$2"
      shift 2
      ;;
    --secret-name)
      WIZ_SECRET_NAME="$2"
      shift 2
      ;;
    --datacenter)
      WIZ_DATACENTER="$2"
      shift 2
      ;;
    --tenant-env)
      TENANT_ENV="$2"
      shift 2
      ;;
    --image)
      IMAGE_URI="$2"
      IMAGE_URI_EXPLICIT=true
      shift 2
      ;;
    --wif)
      CONFIGURE_WIF="true"
      shift
      ;;
    --github-repo)
      GITHUB_REPO="$2"
      shift 2
      ;;
    --wif-pool)
      WIF_POOL_NAME="$2"
      shift 2
      ;;
    --wif-provider)
      WIF_PROVIDER_NAME="$2"
      shift 2
      ;;
    --attribute-condition)
      WIF_ATTRIBUTE_CONDITION="$2"
      shift 2
      ;;
    --caller-workflow-ref)
      CALLER_WORKFLOW_REF="$2"
      shift 2
      ;;
    --builder)
      PROVISION_BUILDER="true"
      BUILDER_ONLY="true"
      shift
      ;;
    --collapsed)
      COLLAPSED="true"
      shift
      ;;
    --builder-sa-name)
      BUILDER_SA_NAME="$2"
      shift 2
      ;;
    --ar-repo)
      AR_REPO="$2"
      shift 2
      ;;
    --github-owner)
      GITHUB_OWNER="$2"
      shift 2
      ;;
    --pull-member)
      PULL_MEMBERS+=("$2")
      shift 2
      ;;
    --public-read)
      PUBLIC_READ="true"
      shift
      ;;
    -y|--yes|--non-interactive)
      NON_INTERACTIVE="true"
      shift
      ;;
    --dry-run)
      DRY_RUN="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      log_error "Unknown option: $1"
      usage
      exit 1
      ;;
  esac
done

[[ "${BUILDER_ONLY}" == "true" ]] && PROVISION_BUILDER="true"
if [[ "${COLLAPSED}" == "true" ]]; then
  if [[ "${BUILDER_ONLY}" == "true" ]]; then
    log_error "--builder and --collapsed are mutually exclusive (--collapsed already includes builder resources)."
    exit 1
  fi
  # Collapsed = host + consumer in one project: builder resources + consumer stack,
  # one shared WIF pool/provider, and consumer WIF always configured.
  PROVISION_BUILDER="true"
  CONFIGURE_WIF="true"
  if [[ "${BUILDER_SA_NAME}" == "${RUNNER_SA_NAME}" ]]; then
    log_error "--collapsed requires distinct service accounts, but builder and runner are both '${RUNNER_SA_NAME}'."
    exit 1
  fi
fi

if [[ "${BUILDER_ONLY}" == "true" ]]; then
  TOTAL_STEPS=3
elif [[ "${PROVISION_BUILDER}" == "true" ]]; then
  TOTAL_STEPS=8
fi

if [[ "${PROVISION_BUILDER}" == "true" ]] && [[ -z "${GITHUB_OWNER}" ]] && [[ "${NON_INTERACTIVE}" == "true" ]]; then
  log_error "--github-owner <OWNER> (or GITHUB_OWNER) is required with --builder / --collapsed in non-interactive mode."
  exit 1
fi

if [[ "${PROVISION_BUILDER}" != "true" ]] && [[ -z "${IMAGE_URI}" ]] && [[ "${NON_INTERACTIVE}" == "true" ]]; then
  log_error "--image <IMAGE_URI> (or IMAGE_URI) is required in non-interactive mode, e.g. <region>-docker.pkg.dev/<host-project>/<repo>/worker:slim."
  exit 1
fi

# ------------------------------------------------------------------------------
# Shared helper: idempotently ensure the GitHub WIF pool + OIDC provider exist
# in ${PROJECT_ID}. Reuses existing resources; only creates what is missing.
# Sets WIF_PROJECT_NUMBER and WIF_POOL_RESOURCE / WIF_PROVIDER_RESOURCE.
# ------------------------------------------------------------------------------
WIF_PROJECT_NUMBER=""
WIF_POOL_RESOURCE=""
WIF_PROVIDER_RESOURCE=""
ensure_wif_pool_provider() {
  if [[ -n "${WIF_POOL_RESOURCE}" ]]; then
    return 0
  fi
  if [[ "${DRY_RUN}" == "true" ]]; then
    WIF_PROJECT_NUMBER="1234567890"
    log_info "[DRY-RUN] Simulating WIF pool '${WIF_POOL_NAME}' / provider '${WIF_PROVIDER_NAME}' (reuse if present, create if missing)."
  else
    WIF_PROJECT_NUMBER=$(gcloud projects describe "${PROJECT_ID}" --format="value(projectNumber)")

    if ! gcloud iam workload-identity-pools describe "${WIF_POOL_NAME}" --location="global" --project="${PROJECT_ID}" >/dev/null 2>&1; then
      log_info "Creating Workload Identity Pool '${WIF_POOL_NAME}'..."
      gcloud iam workload-identity-pools create "${WIF_POOL_NAME}" \
        --location="global" \
        --project="${PROJECT_ID}" \
        --display-name="GitHub Actions Pool" \
        --description="Identity pool for GitHub Actions CI/CD" \
        --quiet >/dev/null
    else
      log_success "Reusing existing Workload Identity Pool '${WIF_POOL_NAME}'."
    fi

    if ! gcloud iam workload-identity-pools providers describe "${WIF_PROVIDER_NAME}" --workload-identity-pool="${WIF_POOL_NAME}" --location="global" --project="${PROJECT_ID}" >/dev/null 2>&1; then
      log_info "Creating Workload Identity Provider '${WIF_PROVIDER_NAME}'..."
      # Multi-tenant deployment providers (e.g. GitHub Actions) require an attribute condition referencing provider claims
      WIF_OWNER="${GITHUB_OWNER:-}"
      if [[ -z "${WIF_OWNER}" ]] && [[ -n "${GITHUB_REPO:-}" ]]; then
        WIF_OWNER="${GITHUB_REPO%%/*}"
      fi
      PROVIDER_CONDITION="${WIF_ATTRIBUTE_CONDITION:-}"
      if [[ -z "${PROVIDER_CONDITION}" ]]; then
        if [[ -n "${WIF_OWNER}" ]]; then
          PROVIDER_CONDITION="assertion.repository_owner == '${WIF_OWNER}'"
        else
          PROVIDER_CONDITION="assertion.repository_owner != ''"
        fi
      fi
      log_info "Provider attribute condition: ${PROVIDER_CONDITION}"
      gcloud iam workload-identity-pools providers create-oidc "${WIF_PROVIDER_NAME}" \
        --location="global" \
        --project="${PROJECT_ID}" \
        --workload-identity-pool="${WIF_POOL_NAME}" \
        --display-name="GitHub Actions Provider" \
        --issuer-uri="https://token.actions.githubusercontent.com" \
        --attribute-mapping="google.subject=assertion.sub,attribute.actor=assertion.actor,attribute.repository=assertion.repository,attribute.repository_owner=assertion.repository_owner" \
        --attribute-condition="${PROVIDER_CONDITION}" \
        --quiet >/dev/null
    else
      log_success "Reusing existing Workload Identity Provider '${WIF_PROVIDER_NAME}'."
    fi
  fi
  WIF_POOL_RESOURCE="projects/${WIF_PROJECT_NUMBER}/locations/global/workloadIdentityPools/${WIF_POOL_NAME}"
  WIF_PROVIDER_RESOURCE="${WIF_POOL_RESOURCE}/providers/${WIF_PROVIDER_NAME}"
}

# Banner
echo -e "${CYAN}${BOLD}"
echo "╔════════════════════════════════════════════════════════════════════════╗"
echo "║           🛡️  CodeMender Slim - Google Cloud Interactive Setup         ║"
echo "║    Automated Security Worker & Wiz Security Graph MCP Provisioner      ║"
echo "╚════════════════════════════════════════════════════════════════════════╝"
echo -e "${RESET}"

if [[ "${DRY_RUN}" == "true" ]]; then
  echo -e "${YELLOW}${BOLD}⚠️  DRY-RUN MODE ACTIVE: No cloud resources will be created or altered.${RESET}\n"
fi

# ==============================================================================
# Step 1: Pre-flight Verification & Authentication
# ==============================================================================
next_step "Checking environment prerequisites & authentication..."

if ! command -v gcloud >/dev/null 2>&1; then
  log_error "'gcloud' CLI is required but not found in PATH."
  echo "Please install Google Cloud SDK: https://cloud.google.com/sdk/docs/install"
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  log_error "'python3' is required for secure JSON formatting."
  exit 1
fi

if [[ "${DRY_RUN}" == "true" ]]; then
  ACTIVE_ACCOUNT="dry-run-user@example.com"
  log_success "Prerequisites verified [DRY-RUN]."
else
  ACTIVE_ACCOUNT=$(gcloud auth list --filter="status:ACTIVE" --format="value(account)" 2>/dev/null | head -n 1 || true)
  if [[ -z "${ACTIVE_ACCOUNT}" ]]; then
    log_warn "No active Google Cloud authentication found."
    if [[ "${NON_INTERACTIVE}" == "true" ]]; then
      log_error "Please run 'gcloud auth login' before executing in non-interactive mode."
      exit 1
    fi
    log_info "Initiating gcloud authentication..."
    gcloud auth login --brief
    ACTIVE_ACCOUNT=$(gcloud auth list --filter="status:ACTIVE" --format="value(account)" 2>/dev/null | head -n 1 || true)
    if [[ -z "${ACTIVE_ACCOUNT}" ]]; then
      log_error "Authentication failed. Exiting."
      exit 1
    fi
  fi
  log_success "Authenticated as: ${BOLD}${ACTIVE_ACCOUNT}${RESET}"
fi

# ==============================================================================
# Step 2: Project & Region Validation
# ==============================================================================
next_step "Validating Google Cloud Project & Region..."

# Detect whether we're running inside Google Cloud Shell. Cloud Shell exports
# CLOUD_SHELL=true and the session's project via GOOGLE_CLOUD_PROJECT /
# DEVSHELL_PROJECT_ID (the project selected in the Cloud Console / tutorial).
IN_CLOUD_SHELL=false
if [[ "${CLOUD_SHELL:-}" == "true" ]] || [[ -n "${DEVSHELL_PROJECT_ID:-}" ]]; then
  IN_CLOUD_SHELL=true
fi

# Resolution order (first non-empty wins):
#   1. -p / --project flag or PROJECT_ID env (explicit)
#   2. Active gcloud config project (reflects `gcloud config set project` in this session)
#   3. Cloud Shell session project (GOOGLE_CLOUD_PROJECT, then DEVSHELL_PROJECT_ID)
CURRENT_GCP_PROJECT=""
PROJECT_SOURCE=""
if [[ "${DRY_RUN}" != "true" ]]; then
  CURRENT_GCP_PROJECT=$(gcloud config get-value project 2>/dev/null | tr -d '[:space:]' || true)
  [[ "${CURRENT_GCP_PROJECT}" == "(unset)" ]] && CURRENT_GCP_PROJECT=""
  [[ -n "${CURRENT_GCP_PROJECT}" ]] && PROJECT_SOURCE="gcloud config"
fi
if [[ -z "${CURRENT_GCP_PROJECT}" ]] && [[ -n "${GOOGLE_CLOUD_PROJECT:-}" ]]; then
  CURRENT_GCP_PROJECT="${GOOGLE_CLOUD_PROJECT}"
  PROJECT_SOURCE="GOOGLE_CLOUD_PROJECT"
fi
if [[ -z "${CURRENT_GCP_PROJECT}" ]] && [[ -n "${DEVSHELL_PROJECT_ID:-}" ]]; then
  CURRENT_GCP_PROJECT="${DEVSHELL_PROJECT_ID}"
  PROJECT_SOURCE="DEVSHELL_PROJECT_ID"
fi

if [[ -n "${PROJECT_ID}" ]]; then
  PROJECT_SOURCE="explicit"
elif [[ -n "${CURRENT_GCP_PROJECT}" ]] && { [[ "${IN_CLOUD_SHELL}" == "true" ]] || [[ "${NON_INTERACTIVE}" == "true" ]]; }; then
  # In Cloud Shell the session already has a project selected; use it without prompting.
  PROJECT_ID="${CURRENT_GCP_PROJECT}"
  if [[ "${IN_CLOUD_SHELL}" == "true" ]]; then
    log_info "Detected Cloud Shell project ${BOLD}${PROJECT_ID}${RESET} (via ${PROJECT_SOURCE}). Override with -p <PROJECT_ID>."
  fi
fi

while [[ -z "${PROJECT_ID}" ]]; do
  if [[ "${NON_INTERACTIVE}" == "true" ]]; then
    log_error "PROJECT_ID must be specified via flag (-p) or environment in non-interactive mode."
    exit 1
  fi
  if [[ -n "${CURRENT_GCP_PROJECT}" ]]; then
    read -r -p "Enter Google Cloud Project ID [default: ${CURRENT_GCP_PROJECT}]: " INPUT_PROJECT
    PROJECT_ID="${INPUT_PROJECT:-${CURRENT_GCP_PROJECT}}"
  else
    if [[ "${IN_CLOUD_SHELL}" == "true" ]]; then
      log_warn "No project is selected in this Cloud Shell session (tip: gcloud config set project <PROJECT_ID>)."
    fi
    read -r -p "Enter Google Cloud Project ID: " INPUT_PROJECT
    PROJECT_ID="${INPUT_PROJECT}"
  fi
  PROJECT_ID=$(echo "${PROJECT_ID}" | xargs)
done

# Validate Project Accessibility
if [[ "${DRY_RUN}" != "true" ]]; then
  log_info "Verifying project '${PROJECT_ID}' accessibility..."
  if ! gcloud projects describe "${PROJECT_ID}" --format="value(projectId)" >/dev/null 2>&1; then
    log_error "Cannot access project '${PROJECT_ID}'. Please verify the ID and your permissions."
    exit 1
  fi
  gcloud config set project "${PROJECT_ID}" --quiet >/dev/null 2>&1
fi
log_success "Active Project: ${BOLD}${PROJECT_ID}${RESET}"

# Region Selection & Validation
CURRENT_GCP_REGION=""
if [[ "${DRY_RUN}" != "true" ]]; then
  CURRENT_GCP_REGION=$(gcloud config get-value compute/region 2>/dev/null || true)
fi
DEFAULT_REGION="${CURRENT_GCP_REGION:-us-central1}"

if [[ -z "${REGION}" ]]; then
  if [[ "${NON_INTERACTIVE}" == "true" ]]; then
    REGION="${DEFAULT_REGION}"
  else
    read -r -p "Enter Cloud Run Region [default: ${DEFAULT_REGION}]: " INPUT_REGION
    REGION="${INPUT_REGION:-${DEFAULT_REGION}}"
  fi
fi
REGION=$(echo "${REGION}" | xargs)
log_success "Deployment Region: ${BOLD}${REGION}${RESET}"

# Worker image (no default). Builder/collapsed modes derive it from this project's AR repo.
if [[ "${PROVISION_BUILDER}" != "true" ]]; then
  while [[ -z "${IMAGE_URI}" ]]; do
    read -r -p "Enter worker image URI (e.g. <region>-docker.pkg.dev/<host-project>/<repo>/worker:slim): " INPUT_IMAGE
    IMAGE_URI=$(echo "${INPUT_IMAGE}" | xargs)
  done
  log_success "Worker Image: ${BOLD}${IMAGE_URI}${RESET}"
fi

RUNNER_SA_EMAIL="${RUNNER_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
# NOTE: The reusable workflow hardcodes gs://${PROJECT}-codemender-artifacts when
# collecting scan matrices, so this name is intentionally not configurable.
ARTIFACTS_BUCKET="${PROJECT_ID}-codemender-artifacts"

# ==============================================================================
# Optional Step: Builder / Host Resources (mirrors infra/host Terraform)
# ==============================================================================
BUILDER_SA_EMAIL="${BUILDER_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
BUILDER_IMAGE_URI="${REGION}-docker.pkg.dev/${PROJECT_ID}/${AR_REPO}/worker:slim"
BUILDER_WIF_PROVIDER=""

print_builder_summary() {
  echo -e "${BOLD}Builder Resources:${RESET}"
  echo -e "  • ${BOLD}Artifact Registry:${RESET}  ${REGION}-docker.pkg.dev/${PROJECT_ID}/${AR_REPO}"
  echo -e "  • ${BOLD}Builder SA:${RESET}         ${BUILDER_SA_EMAIL}"
  echo -e "  • ${BOLD}WIF Provider:${RESET}       ${BUILDER_WIF_PROVIDER}"
  echo -e "  • ${BOLD}Trusted GitHub Org:${RESET} ${GITHUB_OWNER}"
  echo -e "\n${BOLD}Host Repo Settings for deploy-worker.yml${RESET} ${DIM}(Settings → Secrets and variables → Actions):${RESET}"
  echo -e "  Secrets:   WIF_PROVIDER=${BUILDER_WIF_PROVIDER}"
  echo -e "             WIF_SERVICE_ACCOUNT=${BUILDER_SA_EMAIL}"
  echo -e "  Variables: GCP_PROJECT=${PROJECT_ID}"
  echo -e "             GCP_REGION=${REGION}"
  echo -e "             AR_REPO=${AR_REPO}"
  echo -e "${DIM}Then run the 'Build & Publish CodeMender Worker (Slim)' workflow to push ${BUILDER_IMAGE_URI}.${RESET}"
  echo -e "${DIM}Consumers pull with their Cloud Run service agent; grant it via --pull-member serviceAccount:service-<CONSUMER_PROJECT_NUMBER>@serverless-robot-prod.iam.gserviceaccount.com${RESET}\n"
}

if [[ "${PROVISION_BUILDER}" == "true" ]]; then
  # Point the consumer job at the image this builder will publish, unless overridden.
  if [[ "${IMAGE_URI_EXPLICIT}" != "true" ]]; then
    IMAGE_URI="${BUILDER_IMAGE_URI}"
  fi

  next_step "Configuring builder resources (Artifact Registry, builder SA, GitHub WIF)..."

  while [[ -z "${GITHUB_OWNER}" ]]; do
    read -r -p "Enter GitHub org/user allowed to build images via WIF (e.g. wiz-demo): " INPUT_OWNER
    GITHUB_OWNER=$(echo "${INPUT_OWNER}" | xargs)
  done
  log_success "Trusted GitHub owner for builder WIF: ${BOLD}${GITHUB_OWNER}${RESET}"

  BUILDER_APIS=(
    "artifactregistry.googleapis.com"
    "iam.googleapis.com"
    "run.googleapis.com"
  )
  BUILDER_ROLES=(
    "roles/artifactregistry.writer"
  )
  PULL_GRANTS=()
  [[ "${PUBLIC_READ}" == "true" ]] && PULL_GRANTS+=("allAuthenticatedUsers")
  if [[ ${#PULL_MEMBERS[@]} -gt 0 ]]; then
    PULL_GRANTS+=("${PULL_MEMBERS[@]}")
  fi

  if [[ "${DRY_RUN}" == "true" ]]; then
    log_info "[DRY-RUN] Checking builder APIs: ${BUILDER_APIS[*]}"
    log_info "[DRY-RUN] Simulating Artifact Registry repo '${AR_REPO}' (${REGION}, DOCKER) — reuse if present, create if missing."
    log_info "[DRY-RUN] Simulating builder SA '${BUILDER_SA_EMAIL}' with ${BUILDER_ROLES[*]}."
    ensure_wif_pool_provider
    log_info "[DRY-RUN] Simulating roles/iam.workloadIdentityUser on '${BUILDER_SA_EMAIL}' for ${WIF_POOL_RESOURCE}/attribute.repository_owner/${GITHUB_OWNER}"
    for member in ${PULL_GRANTS[@]+"${PULL_GRANTS[@]}"}; do
      log_info "[DRY-RUN] Simulating roles/artifactregistry.reader on '${AR_REPO}' for ${member}"
    done
  else
    ENABLED_SERVICES=$(gcloud services list --enabled --project="${PROJECT_ID}" --format="value(config.name)" 2>/dev/null || true)
    MISSING_BUILDER_APIS=()
    for api in "${BUILDER_APIS[@]}"; do
      if ! echo "${ENABLED_SERVICES}" | grep -Fxq "${api}"; then
        MISSING_BUILDER_APIS+=("${api}")
      fi
    done
    if [[ ${#MISSING_BUILDER_APIS[@]} -gt 0 ]]; then
      log_info "Enabling builder APIs: ${MISSING_BUILDER_APIS[*]}"
      gcloud services enable "${MISSING_BUILDER_APIS[@]}" --project="${PROJECT_ID}"
    fi

    if gcloud artifacts repositories describe "${AR_REPO}" --location="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
      log_success "Reusing existing Artifact Registry repo '${AR_REPO}'."
    else
      log_info "Creating Artifact Registry repo '${AR_REPO}'..."
      gcloud artifacts repositories create "${AR_REPO}" \
        --project="${PROJECT_ID}" \
        --location="${REGION}" \
        --repository-format=docker \
        --description="Central container repository for CodeMender Slim worker images" \
        --quiet >/dev/null
      log_success "Created Artifact Registry repo '${AR_REPO}'."
    fi

    if gcloud iam service-accounts describe "${BUILDER_SA_EMAIL}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
      log_success "Builder Service Account '${BUILDER_SA_EMAIL}' exists."
    else
      log_info "Creating builder Service Account '${BUILDER_SA_NAME}'..."
      gcloud iam service-accounts create "${BUILDER_SA_NAME}" \
        --project="${PROJECT_ID}" \
        --display-name="CodeMender Slim Image Builder Service Account" \
        --quiet >/dev/null
      log_success "Created builder Service Account: ${BOLD}${BUILDER_SA_EMAIL}${RESET}"
    fi

    for role in "${BUILDER_ROLES[@]}"; do
      if ! gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
        --member="serviceAccount:${BUILDER_SA_EMAIL}" \
        --role="${role}" \
        --condition=None \
        --quiet >/dev/null 2>&1; then
        log_warn "Failed to bind ${role} to ${BUILDER_SA_EMAIL}."
      fi
    done

    ensure_wif_pool_provider
    if ! gcloud iam service-accounts add-iam-policy-binding "${BUILDER_SA_EMAIL}" \
      --project="${PROJECT_ID}" \
      --role="roles/iam.workloadIdentityUser" \
      --member="principalSet://iam.googleapis.com/${WIF_POOL_RESOURCE}/attribute.repository_owner/${GITHUB_OWNER}" \
      --quiet >/dev/null 2>&1; then
      log_warn "Failed to grant roles/iam.workloadIdentityUser on ${BUILDER_SA_EMAIL} to GitHub org '${GITHUB_OWNER}'."
    fi

    for member in ${PULL_GRANTS[@]+"${PULL_GRANTS[@]}"}; do
      if gcloud artifacts repositories add-iam-policy-binding "${AR_REPO}" \
        --project="${PROJECT_ID}" \
        --location="${REGION}" \
        --member="${member}" \
        --role="roles/artifactregistry.reader" \
        --quiet >/dev/null 2>&1; then
        log_success "Granted image pull on '${AR_REPO}' to ${member}."
      else
        log_warn "Failed to grant image pull on '${AR_REPO}' to ${member}."
      fi
    done
  fi
  BUILDER_WIF_PROVIDER="${WIF_PROVIDER_RESOURCE}"
  log_success "Builder resources configured."

  if [[ "${BUILDER_ONLY}" == "true" ]]; then
    END_TIME=$(date +%s)
    echo -e "\n${GREEN}${BOLD}========================================================================${RESET}"
    echo -e "${GREEN}${BOLD}  🎉 CodeMender Slim Builder Configuration Completed in $((END_TIME - START_TIME))s! ${RESET}"
    echo -e "${GREEN}${BOLD}========================================================================${RESET}\n"
    print_builder_summary
    exit 0
  fi
fi

# ==============================================================================
# Step 3: Google Cloud API Enablement Check
# ==============================================================================
next_step "Checking required Google Cloud APIs..."

REQUIRED_APIS=(
  "run.googleapis.com"
  "secretmanager.googleapis.com"
  "aiplatform.googleapis.com"
  "logging.googleapis.com"
  "iam.googleapis.com"
  "storage.googleapis.com"
)

if [[ "${DRY_RUN}" == "true" ]]; then
  log_info "[DRY-RUN] Checking required APIs: ${REQUIRED_APIS[*]}"
  log_success "All required APIs validated [DRY-RUN]."
else
  log_info "Querying enabled services in '${PROJECT_ID}'..."
  ENABLED_SERVICES=$(gcloud services list --enabled --project="${PROJECT_ID}" --format="value(config.name)" 2>/dev/null || true)

  MISSING_APIS=()
  for api in "${REQUIRED_APIS[@]}"; do
    if ! echo "${ENABLED_SERVICES}" | grep -Fxq "${api}"; then
      MISSING_APIS+=("${api}")
    fi
  done

  if [[ ${#MISSING_APIS[@]} -gt 0 ]]; then
    log_warn "Missing required APIs: ${MISSING_APIS[*]}"
    log_info "Enabling missing APIs in parallel (this usually takes 15-30 seconds)..."
    gcloud services enable "${MISSING_APIS[@]}" --project="${PROJECT_ID}"
    log_success "Successfully enabled APIs: ${MISSING_APIS[*]}"
  else
    log_success "All required Google Cloud APIs are already enabled."
  fi
fi

# ==============================================================================
# Step 4: Secure Wiz MCP Credential Prompting & Secret Manager
# ==============================================================================
next_step "Configuring Wiz Security Graph MCP credentials..."

SECRET_EXISTS=false
if [[ "${DRY_RUN}" != "true" ]]; then
  if gcloud secrets describe "${WIZ_SECRET_NAME}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    SECRET_EXISTS=true
  fi
fi

PROMPT_FOR_CREDS=true
if [[ "${SECRET_EXISTS}" == "true" ]]; then
  log_info "Secret '${WIZ_SECRET_NAME}' already exists in Secret Manager."
  if [[ "${NON_INTERACTIVE}" == "true" ]] && [[ -z "${WIZ_CLIENT_SECRET}" ]]; then
    log_success "Using existing Secret Manager credentials for '${WIZ_SECRET_NAME}'."
    PROMPT_FOR_CREDS=false
  elif [[ "${NON_INTERACTIVE}" != "true" ]]; then
    echo -e "${YELLOW}Existing secret found.${RESET} Would you like to use the existing secret or overwrite it?"
    echo "  1) Use existing secret (Recommended)"
    echo "  2) Overwrite with new Wiz credentials"
    read -r -p "Select option [1/2, default: 1]: " SECRET_CHOICE
    SECRET_CHOICE="${SECRET_CHOICE:-1}"
    if [[ "${SECRET_CHOICE}" == "1" ]]; then
      log_success "Using existing Secret '${WIZ_SECRET_NAME}'."
      PROMPT_FOR_CREDS=false
    fi
  fi
fi

if [[ "${PROMPT_FOR_CREDS}" != "true" ]]; then
  if [[ -n "${TENANT_ENV}" ]]; then
    log_warn "--tenant-env is ignored because the existing secret is reused. Choose 'Overwrite' to change the Wiz MCP endpoint."
  fi
  # Verify the reused secret has the fields the worker needs (values are never printed).
  if [[ "${DRY_RUN}" != "true" ]]; then
    MISSING_SECRET_KEYS=$(gcloud secrets versions access latest --secret="${WIZ_SECRET_NAME}" --project="${PROJECT_ID}" 2>/dev/null | python3 -c '
import json, sys
raw = sys.stdin.read().strip()
if not raw:
    sys.exit(0)
try:
    d = json.loads(raw)
except Exception:
    print("valid JSON"); sys.exit(0)
missing = []
if not any(d.get(k) for k in ("Wiz-DataCenter", "datacenter", "data_center")):
    missing.append("datacenter")
if not d.get("mcp_url"):
    missing.append("mcp_url")
print(", ".join(missing))
' || true)
    if [[ "${MISSING_SECRET_KEYS}" == *datacenter* || "${MISSING_SECRET_KEYS}" == "valid JSON" ]]; then
      log_warn "Secret '${WIZ_SECRET_NAME}' is missing: ${MISSING_SECRET_KEYS}. The worker will skip Wiz MCP until you re-run ./setup.sh and choose 'Overwrite'."
    elif [[ "${MISSING_SECRET_KEYS}" == *mcp_url* ]]; then
      log_warn "Secret '${WIZ_SECRET_NAME}' has no mcp_url, so the worker will use https://mcp.app.wiz.io?mode=explicit."
      log_warn "If your Wiz tenant is not production (e.g. demo), re-run ./setup.sh and choose 'Overwrite'."
    fi
  fi
fi

if [[ "${PROMPT_FOR_CREDS}" == "true" ]]; then
  # Client ID
  while [[ -z "${WIZ_CLIENT_ID}" ]]; do
    if [[ "${NON_INTERACTIVE}" == "true" ]]; then
      log_error "WIZ_CLIENT_ID must be provided when configuring credentials in non-interactive mode."
      exit 1
    fi
    read -r -p "Enter Wiz Service Account Client ID: " INPUT_CLIENT_ID
    WIZ_CLIENT_ID=$(echo "${INPUT_CLIENT_ID}" | xargs)
    if [[ -z "${WIZ_CLIENT_ID}" ]]; then
      log_error "Wiz Client ID cannot be empty."
    fi
  done

  # Client Secret (Masked input via read -s)
  while [[ -z "${WIZ_CLIENT_SECRET}" ]]; do
    if [[ "${NON_INTERACTIVE}" == "true" ]]; then
      log_error "WIZ_CLIENT_SECRET must be provided when configuring credentials in non-interactive mode."
      exit 1
    fi
    read -r -s -p "Enter Wiz Service Account Client Secret (hidden): " WIZ_CLIENT_SECRET
    echo
    if [[ -z "${WIZ_CLIENT_SECRET}" ]]; then
      log_error "Wiz Client Secret cannot be empty."
      continue
    fi
    read -r -s -p "Confirm Wiz Service Account Client Secret (hidden): " WIZ_CLIENT_SECRET_CONFIRM
    echo
    if [[ "${WIZ_CLIENT_SECRET}" != "${WIZ_CLIENT_SECRET_CONFIRM}" ]]; then
      log_error "Secrets did not match. Please re-enter."
      WIZ_CLIENT_SECRET=""
      WIZ_CLIENT_SECRET_CONFIRM=""
    fi
  done

  # DataCenter (required, no default)
  WIZ_DATACENTER=$(trim_lower "${WIZ_DATACENTER}")
  while [[ ! "${WIZ_DATACENTER}" =~ ^[a-z0-9-]+$ ]]; do
    if [[ -n "${WIZ_DATACENTER}" ]]; then
      log_error "Invalid Wiz DataCenter '${WIZ_DATACENTER}' (use letters, digits and '-' only)."
    fi
    if [[ "${NON_INTERACTIVE}" == "true" ]]; then
      log_error "A valid Wiz DataCenter (--datacenter or WIZ_DATACENTER, e.g. us20, eu1) is required in non-interactive mode."
      exit 1
    fi
    if ! read -r -p "Enter Wiz DataCenter (required, e.g. us20, eu1): " INPUT_DC; then
      echo
      log_error "No input received; the Wiz DataCenter is required."
      exit 1
    fi
    WIZ_DATACENTER=$(trim_lower "${INPUT_DC}")
    if [[ -z "${WIZ_DATACENTER}" ]]; then
      log_error "Wiz DataCenter is required and cannot be blank."
    fi
  done

  # Wiz Tenant Env (default: app). Only used to derive the MCP URL; it is not stored itself.
  if [[ -z "${TENANT_ENV}" ]] && [[ "${NON_INTERACTIVE}" != "true" ]]; then
    read -r -p "Enter Wiz Tenant Env [default: app]: " TENANT_ENV || TENANT_ENV=""
  fi
  while true; do
    TENANT_ENV=$(trim_lower "${TENANT_ENV}")
    TENANT_ENV="${TENANT_ENV:-app}"
    if [[ "${TENANT_ENV}" == "prod" ]] || [[ "${TENANT_ENV}" == "production" ]]; then
      TENANT_ENV="app"
    fi
    if [[ "${TENANT_ENV}" =~ ^[a-z0-9-]+$ ]]; then
      break
    fi
    log_error "Invalid Wiz Tenant Env '${TENANT_ENV}' (use letters, digits and '-' only)."
    if [[ "${NON_INTERACTIVE}" == "true" ]]; then
      exit 1
    fi
    read -r -p "Enter Wiz Tenant Env [default: app]: " TENANT_ENV || TENANT_ENV=""
  done
  WIZ_MCP_URL="https://mcp.${TENANT_ENV}.wiz.io?mode=explicit"
  log_success "Wiz DataCenter: ${BOLD}${WIZ_DATACENTER}${RESET} | Wiz MCP endpoint: ${BOLD}${WIZ_MCP_URL}${RESET}"

  # Construct Secret JSON Safely with client_id, client_secret, datacenter, and mcp_url
  WIZ_SECRET_PAYLOAD=$(python3 -c "import json, sys; print(json.dumps({'client_id': sys.argv[1], 'client_secret': sys.argv[2], 'datacenter': sys.argv[3], 'mcp_url': sys.argv[4]}))" "${WIZ_CLIENT_ID}" "${WIZ_CLIENT_SECRET}" "${WIZ_DATACENTER}" "${WIZ_MCP_URL}")

  if [[ "${DRY_RUN}" == "true" ]]; then
    log_info "[DRY-RUN] Simulating secret creation for '${WIZ_SECRET_NAME}'..."
  else
    if [[ "${SECRET_EXISTS}" == "true" ]]; then
      log_info "Adding updated version to Secret Manager '${WIZ_SECRET_NAME}'..."
      printf "%s" "${WIZ_SECRET_PAYLOAD}" | gcloud secrets versions add "${WIZ_SECRET_NAME}" \
        --project="${PROJECT_ID}" \
        --data-file=- \
        --quiet >/dev/null
    else
      log_info "Creating Secret '${WIZ_SECRET_NAME}' in Secret Manager..."
      printf "%s" "${WIZ_SECRET_PAYLOAD}" | gcloud secrets create "${WIZ_SECRET_NAME}" \
        --project="${PROJECT_ID}" \
        --replication-policy="automatic" \
        --data-file=- \
        --quiet >/dev/null
    fi
  fi

  unset WIZ_CLIENT_SECRET WIZ_CLIENT_SECRET_CONFIRM WIZ_SECRET_PAYLOAD
  log_success "Wiz MCP credentials stored securely in Secret Manager ('${WIZ_SECRET_NAME}')."
fi

# ==============================================================================
# Step 5: Service Account & Least-Privilege IAM Roles
# ==============================================================================
next_step "Configuring Service Account and IAM permissions..."

REQUIRED_ROLES=(
  "roles/secretmanager.secretAccessor"
  "roles/aiplatform.user"
  "roles/logging.logWriter"
  "roles/logging.viewer"
  "roles/run.developer"
)

if [[ "${DRY_RUN}" == "true" ]]; then
  log_info "[DRY-RUN] Simulating Service Account '${RUNNER_SA_EMAIL}' and IAM bindings: ${REQUIRED_ROLES[*]}"
  log_success "Service Account permissions validated [DRY-RUN]."
else
  if ! gcloud iam service-accounts describe "${RUNNER_SA_EMAIL}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    log_info "Creating Service Account '${RUNNER_SA_NAME}'..."
    gcloud iam service-accounts create "${RUNNER_SA_NAME}" \
      --project="${PROJECT_ID}" \
      --display-name="CodeMender Slim Worker Service Account" \
      --quiet >/dev/null
    log_success "Created Service Account: ${BOLD}${RUNNER_SA_EMAIL}${RESET}"
  else
    log_success "Service Account '${RUNNER_SA_EMAIL}' exists."
  fi

  log_info "Applying minimal IAM roles for CodeMender execution..."
  for role in "${REQUIRED_ROLES[@]}"; do
    if ! gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
      --member="serviceAccount:${RUNNER_SA_EMAIL}" \
      --role="${role}" \
      --condition=None \
      --quiet >/dev/null 2>&1; then
      log_warn "Failed to bind ${role} to ${RUNNER_SA_EMAIL} (check your IAM permissions)."
    fi
  done
  log_success "IAM roles configured successfully."
fi

# ==============================================================================
# Step 6: Cloud Storage - Ephemeral Scan Artifacts Bucket
# ==============================================================================
next_step "Configuring scan artifacts bucket 'gs://${ARTIFACTS_BUCKET}'..."

if [[ "${DRY_RUN}" == "true" ]]; then
  log_info "[DRY-RUN] Simulating bucket 'gs://${ARTIFACTS_BUCKET}' (Location: ${REGION}, uniform access, 1-day delete lifecycle) with roles/storage.objectUser for '${RUNNER_SA_EMAIL}'."
  log_success "Scan artifacts bucket configured [DRY-RUN]."
else
  # Bucket names are global, so "exists" isn't enough: it must exist in THIS project.
  #   - describe OK + projectNumber matches  -> reuse
  #   - describe OK + different projectNumber -> owned elsewhere, abort
  #   - describe 403                          -> exists but owned elsewhere / no access, abort
  #   - describe 404                          -> create (matches google_storage_bucket.artifacts)
  PROJECT_NUMBER=$(gcloud projects describe "${PROJECT_ID}" --format="value(projectNumber)")
  BUCKET_DESCRIBE_OUT=""
  BUCKET_DESCRIBE_RC=0
  BUCKET_DESCRIBE_OUT=$(gcloud storage buckets describe "gs://${ARTIFACTS_BUCKET}" --raw --format="value(projectNumber,location)" 2>&1) || BUCKET_DESCRIBE_RC=$?

  if [[ ${BUCKET_DESCRIBE_RC} -eq 0 ]]; then
    read -r BUCKET_PROJECT BUCKET_LOCATION <<<"${BUCKET_DESCRIBE_OUT}"
    if [[ "${BUCKET_PROJECT}" != "${PROJECT_NUMBER}" ]]; then
      log_error "Bucket 'gs://${ARTIFACTS_BUCKET}' already exists but belongs to project number ${BUCKET_PROJECT}, not '${PROJECT_ID}' (${PROJECT_NUMBER})."
      log_error "The reusable workflow requires gs://<PROJECT_ID>-codemender-artifacts in the job's project; delete or reclaim that bucket and re-run."
      exit 1
    fi
    log_success "Reusing existing bucket 'gs://${ARTIFACTS_BUCKET}' (location: ${BUCKET_LOCATION})."
    if [[ -n "${BUCKET_LOCATION}" ]] && [[ "${BUCKET_LOCATION,,}" != "${REGION,,}" ]]; then
      log_warn "Bucket location '${BUCKET_LOCATION}' differs from region '${REGION}' (Terraform expects ${REGION}); bucket location cannot be changed in place."
    fi
  elif echo "${BUCKET_DESCRIBE_OUT}" | grep -qiE '403|forbidden|permission|does not have storage\.buckets\.get'; then
    log_error "Bucket 'gs://${ARTIFACTS_BUCKET}' already exists but is not accessible from '${ACTIVE_ACCOUNT}' (likely owned by another project)."
    log_error "Details: ${BUCKET_DESCRIBE_OUT}"
    exit 1
  elif echo "${BUCKET_DESCRIBE_OUT}" | grep -qiE '404|not found|notfound'; then
    log_info "Creating bucket 'gs://${ARTIFACTS_BUCKET}'..."
    if ! gcloud storage buckets create "gs://${ARTIFACTS_BUCKET}" \
      --project="${PROJECT_ID}" \
      --location="${REGION}" \
      --uniform-bucket-level-access \
      --quiet >/dev/null; then
      log_error "Unable to create 'gs://${ARTIFACTS_BUCKET}'. Bucket names are global; it may already be owned by another project."
      exit 1
    fi
    log_success "Created bucket: ${BOLD}gs://${ARTIFACTS_BUCKET}${RESET}"
  else
    log_error "Unable to determine whether 'gs://${ARTIFACTS_BUCKET}' exists: ${BUCKET_DESCRIBE_OUT}"
    exit 1
  fi

  # Converge settings to match Terraform on both new and reused buckets:
  # uniform bucket-level access + 1-day delete lifecycle (scan matrices are short-lived handoffs).
  LIFECYCLE_FILE=$(mktemp)
  cat >"${LIFECYCLE_FILE}" <<'JSON'
{"rule": [{"action": {"type": "Delete"}, "condition": {"age": 1}}]}
JSON
  gcloud storage buckets update "gs://${ARTIFACTS_BUCKET}" \
    --uniform-bucket-level-access \
    --lifecycle-file="${LIFECYCLE_FILE}" \
    --quiet >/dev/null
  rm -f "${LIFECYCLE_FILE}"
  LIFECYCLE_FILE=""

  if ! gcloud storage buckets add-iam-policy-binding "gs://${ARTIFACTS_BUCKET}" \
    --member="serviceAccount:${RUNNER_SA_EMAIL}" \
    --role="roles/storage.objectUser" \
    --quiet >/dev/null 2>&1; then
    log_warn "Failed to bind roles/storage.objectUser on gs://${ARTIFACTS_BUCKET} to ${RUNNER_SA_EMAIL}."
  fi
  log_success "Bucket lifecycle (1-day TTL) and runner access configured."
fi

# ==============================================================================
# Step 7: Cloud Run Job Provisioning
# ==============================================================================
next_step "Configuring Cloud Run Job '${JOB_NAME}'..."

ENV_VARS="CM_DISABLE_SANDBOX=true,WIZ_SECRET_NAME=${WIZ_SECRET_NAME},PROJECT_ID=${PROJECT_ID},SCAN_ARTIFACTS_BUCKET=${ARTIFACTS_BUCKET}"
JOB_FLAGS=(
  --project="${PROJECT_ID}"
  --region="${REGION}"
  --image="${IMAGE_URI}"
  --service-account="${RUNNER_SA_EMAIL}"
  --cpu="2"
  --memory="4Gi"
  --tasks=1
  --max-retries="${JOB_MAX_RETRIES}"
  --task-timeout="1800s"
  --set-env-vars="${ENV_VARS}"
  --quiet
)

JOB_SKIPPED=false
if [[ "${DRY_RUN}" == "true" ]]; then
  log_info "[DRY-RUN] Simulating deployment of Cloud Run Job '${JOB_NAME}' (Region: ${REGION}, Image: ${IMAGE_URI})."
  log_info "[DRY-RUN] Job environment: ${ENV_VARS}"
  log_success "Cloud Run Job '${JOB_NAME}' configured [DRY-RUN]."
elif [[ "${PROVISION_BUILDER}" == "true" ]] && ! gcloud artifacts docker images describe "${IMAGE_URI}" >/dev/null 2>&1; then
  # Freshly provisioned builder: the image won't exist until deploy-worker.yml runs.
  JOB_SKIPPED=true
  log_warn "Image '${IMAGE_URI}' not found yet; skipping Cloud Run Job creation."
  log_warn "Run the deploy-worker workflow to publish it, then re-run this script to create the job."
else
  if gcloud run jobs describe "${JOB_NAME}" --region="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    log_info "Updating Cloud Run Job '${JOB_NAME}'..."
    gcloud run jobs update "${JOB_NAME}" "${JOB_FLAGS[@]}" >/dev/null
    log_success "Cloud Run Job '${JOB_NAME}' updated successfully."
  else
    log_info "Creating Cloud Run Job '${JOB_NAME}'..."
    gcloud run jobs create "${JOB_NAME}" "${JOB_FLAGS[@]}" >/dev/null
    log_success "Cloud Run Job '${JOB_NAME}' created successfully."
  fi
fi

# ==============================================================================
# Optional: Workload Identity Federation (GitHub Actions)
# ==============================================================================
CONSUMER_WIF_PROVIDER=""
if [[ -z "${CONFIGURE_WIF}" ]] && [[ "${NON_INTERACTIVE}" != "true" ]]; then
  echo
  read -r -p "Configure GitHub Actions Workload Identity Federation (WIF)? [y/N]: " WIF_CHOICE
  WIF_CHOICE="${WIF_CHOICE:-N}"
  if [[ "${WIF_CHOICE}" =~ ^[Yy]$ ]]; then
    CONFIGURE_WIF="true"
  fi
fi

if [[ "${CONFIGURE_WIF}" == "true" ]]; then
  while [[ -z "${GITHUB_REPO}" ]]; do
    if [[ "${NON_INTERACTIVE}" == "true" ]]; then
      log_warn "GITHUB_REPO not provided; skipping WIF GitHub binding."
      break
    fi
    read -r -p "Enter GitHub repository (owner/repo): " INPUT_REPO
    GITHUB_REPO=$(echo "${INPUT_REPO}" | xargs)
  done

  if [[ -n "${GITHUB_REPO}" ]]; then
    # Shared with the builder in --collapsed mode (cached after first call).
    ensure_wif_pool_provider
    if [[ "${COLLAPSED}" == "true" ]]; then
      log_info "Collapsed mode: runner shares WIF pool '${WIF_POOL_NAME}' / provider '${WIF_PROVIDER_NAME}' with builder '${BUILDER_SA_EMAIL}'."
    fi
    WIF_MEMBER="principalSet://iam.googleapis.com/${WIF_POOL_RESOURCE}/attribute.repository/${GITHUB_REPO}"
    if [[ "${DRY_RUN}" == "true" ]]; then
      log_info "[DRY-RUN] Simulating WIF setup for repository: ${GITHUB_REPO} (pool: ${WIF_POOL_NAME}, provider: ${WIF_PROVIDER_NAME})"
    elif ! gcloud iam service-accounts add-iam-policy-binding "${RUNNER_SA_EMAIL}" \
      --project="${PROJECT_ID}" \
      --role="roles/iam.workloadIdentityUser" \
      --member="${WIF_MEMBER}" \
      --quiet >/dev/null 2>&1; then
      log_warn "Failed to grant roles/iam.workloadIdentityUser on ${RUNNER_SA_EMAIL} to ${GITHUB_REPO}."
    fi
    CONSUMER_WIF_PROVIDER="${WIF_PROVIDER_RESOURCE}"
    log_success "Configured WIF binding for '${GITHUB_REPO}'."
  fi
fi

# ==============================================================================
# Completion Summary & Quickstart Snippet
# ==============================================================================
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo -e "\n${GREEN}${BOLD}========================================================================${RESET}"
echo -e "${GREEN}${BOLD}  🎉 CodeMender Slim Google Cloud Configuration Completed in ${DURATION}s! ${RESET}"
echo -e "${GREEN}${BOLD}========================================================================${RESET}\n"

echo -e "${BOLD}Resource Summary:${RESET}"
echo -e "  • ${BOLD}Project ID:${RESET}         ${PROJECT_ID}"
echo -e "  • ${BOLD}Region:${RESET}             ${REGION}"
echo -e "  • ${BOLD}Cloud Run Job:${RESET}      ${JOB_NAME}"
echo -e "  • ${BOLD}Runner SA:${RESET}          ${RUNNER_SA_EMAIL}"
echo -e "  • ${BOLD}Secret Name:${RESET}        ${WIZ_SECRET_NAME}"
echo -e "  • ${BOLD}Artifacts Bucket:${RESET}   gs://${ARTIFACTS_BUCKET}"
echo -e "  • ${BOLD}Worker Image:${RESET}       ${IMAGE_URI}"
if [[ -n "${CONSUMER_WIF_PROVIDER}" ]]; then
  echo -e "  • ${BOLD}WIF Provider:${RESET}       ${CONSUMER_WIF_PROVIDER}"
fi

echo -e "\n${BOLD}Quick Test (gcloud CLI):${RESET}"
echo -e "${DIM}Trigger a fast mock scan (skips 'cm find') against a public repository:${RESET}"
echo -e "${CYAN}gcloud run jobs execute ${JOB_NAME} \\"
echo -e "  --project=\"${PROJECT_ID}\" \\"
echo -e "  --region=\"${REGION}\" \\"
echo -e "  --args=\"REPO=owner/public-repo,CM_ACTION=scan,CM_MOCK_FINDINGS=true\"${RESET}"

echo -e "\n${BOLD}GitHub Repository Variables${RESET} ${DIM}(Settings → Secrets and variables → Actions → Variables):${RESET}"
echo -e "  GCP_PROJECT=${PROJECT_ID}"
echo -e "  GCP_REGION=${REGION}"
if [[ -n "${CONSUMER_WIF_PROVIDER}" ]]; then
  echo -e "  WIF_PROVIDER=${CONSUMER_WIF_PROVIDER}"
  echo -e "  WIF_SERVICE_ACCOUNT=${RUNNER_SA_EMAIL}"
fi

echo -e "\n${BOLD}Caller GitHub Actions Workflow Configuration:${RESET}"
echo -e "${DIM}Add this job to any caller repo (e.g. .github/workflows/codemender.yml):${RESET}"
if [[ -z "${CALLER_WORKFLOW_REF}" ]]; then
  echo -e "${DIM}(Replace the placeholder, or pass --caller-workflow-ref to print the real ref.)${RESET}"
fi
echo -e "${YELLOW}uses: ${CALLER_WORKFLOW_REF:-<OWNER>/<REPO>/.github/workflows/codemender.yml@main}"
echo "secrets: inherit"
echo "with:"
echo "  action: scan"
echo "  project-id: \${{ vars.GCP_PROJECT }}"
echo "  region: \${{ vars.GCP_REGION }}"
echo "  job-name: \"${JOB_NAME}\""
if [[ -n "${CONSUMER_WIF_PROVIDER}" ]]; then
  echo "  wiz-secret-name: \"${WIZ_SECRET_NAME}\""
  echo "  wif-provider: \${{ vars.WIF_PROVIDER }}"
  echo -e "  wif-service-account: \${{ vars.WIF_SERVICE_ACCOUNT }}${RESET}\n"
else
  echo -e "  wiz-secret-name: \"${WIZ_SECRET_NAME}\"${RESET}\n"
fi

if [[ "${PROVISION_BUILDER}" == "true" ]]; then
  print_builder_summary
  if [[ "${COLLAPSED}" == "true" ]]; then
    echo -e "${DIM}Collapsed mode: builder and runner share WIF provider ${BUILDER_WIF_PROVIDER} but use separate identities.${RESET}"
    echo -e "${DIM}If one repo hosts both workflows, keep the runner in Actions *variables* (WIF_SERVICE_ACCOUNT=${RUNNER_SA_EMAIL})${RESET}"
    echo -e "${DIM}and the builder in Actions *secrets* (WIF_SERVICE_ACCOUNT=${BUILDER_SA_EMAIL}); codemender.yml prefers vars, deploy-worker.yml reads secrets.${RESET}\n"
  fi
fi

if [[ "${JOB_SKIPPED}" == "true" ]]; then
  log_warn "Cloud Run Job '${JOB_NAME}' was NOT created because '${IMAGE_URI}' isn't published yet. Publish it, then re-run with the same flags."
fi
