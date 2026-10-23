#!/usr/bin/env bash
# ==============================================================================
# CodeMender & Wiz Autonomous Security Worker (Slim / Stateless)
# ==============================================================================
set -euo pipefail
export PYTHONUNBUFFERED=1

# Parse container arguments (KEY=VALUE) as environment variables
for arg in "$@"; do
  if [[ "${arg}" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
    export "${BASH_REMATCH[1]}=${BASH_REMATCH[2]}"
  fi
done

REPO="${REPO:-}"
if [ -z "${REPO}" ]; then
  echo "❌ Error: REPO environment variable is required (e.g. owner/repo)." >&2
  exit 1
fi

TARGET_REF="${TARGET_REF:-${REF:-main}}"
BASE_REF="${BASE_REF:-main}"
PROJECT_ID="${PROJECT_ID:-${GCP_PROJECT:-}}"
if [ -z "${PROJECT_ID}" ]; then
  echo "❌ Error: PROJECT_ID or GCP_PROJECT environment variable is required." >&2
  exit 1
fi
CM_MODEL="${CM_MODEL:-gemini-4-argon}"
WIZ_SECRET_NAME="${WIZ_SECRET_NAME:-wiz-mcp-config}"
ISSUE_NUM="${ISSUE_NUMBER:-${ISSUE_NUM:-}}"
VULN_ID="${VULN_ID:-}"
MODE="${MODE:-fix}"
VERIFY_FIRST="${VERIFY_FIRST:-false}"
ADDITIONAL_LOGGING="${ADDITIONAL_LOGGING:-false}"
LOG_LEVEL="${LOG_LEVEL:-INFO}"
if [ "${ADDITIONAL_LOGGING}" = "true" ]; then
  LOG_LEVEL="DEBUG"
fi
export ADDITIONAL_LOGGING LOG_LEVEL

CM_MOCK_FINDINGS="${CM_MOCK_FINDINGS:-false}"
SCRIPT_DIR="${SCRIPT_DIR:-$(cd "$(dirname "$0")" && pwd)}"
[ -d "/worker" ] && SCRIPT_DIR="/worker"
FETCH_WIZ_SCRIPT="${SCRIPT_DIR}/fetch_wiz_context.py"
INGEST_WIZ_SCRIPT="${SCRIPT_DIR}/ingest_wiz_pentest.py"
PARSE_ISSUE_SCRIPT="${SCRIPT_DIR}/parse_issue.py"
MOCK_FINDINGS_SCRIPT="${SCRIPT_DIR}/mock_findings.py"

WORKSPACE_DIR="${WORKSPACE_DIR:-/workspace}"
REPO_DIR="${REPO_DIR:-${WORKSPACE_DIR}/repo}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-${WORKSPACE_DIR}/artifacts}"
mkdir -p "${REPO_DIR}" "${ARTIFACTS_DIR}"

# Symmetrical shell logging functions matching worker/logger.py
log_header() {
  local title="$1"
  echo "================================================================================"
  echo "${title}"
  echo "================================================================================"
}

log_step() {
  local step_title="$1"
  echo "--------------------------------------------------------------------------------"
  echo "🔍 ${step_title}"
  echo "--------------------------------------------------------------------------------"
}

log_info() { echo "ℹ️  $*"; }
log_success() { echo "✅ $*"; }
log_warn() { echo "⚠️  $*"; }
log_error() { echo "❌ $*" >&2; }
log_debug() {
  if [ "${ADDITIONAL_LOGGING}" = "true" ]; then
    echo "🔬 $*"
  fi
}

# Normalize action via table-like case dispatch
RAW_CMD="${CM_ACTION:-${COMMAND:-fix}}"
[[ "${RAW_CMD}" == *"entrypoint.sh"* ]] && RAW_CMD="${CM_ACTION:-fix}"
ACTION="$(echo "${RAW_CMD}" | tr '[:upper:]' '[:lower:]' | xargs)"

case "${ACTION}" in
  find|scan)            ACTION="scan"; MODE="scan" ;;
  analyze)              ACTION="remediate"; MODE="analyze" ;;
  fix|import|remediate) ACTION="remediate"; MODE="${MODE:-fix}" ;;
  verify)               ACTION="verify"; MODE="verify" ;;
  *)
    log_error "Unrecognized action '${ACTION}'. Allowed: scan, verify, remediate."
    exit 1
    ;;
esac

MODEL_ARGS=()
[ -n "${CM_MODEL:-}" ] && MODEL_ARGS=(--model "${CM_MODEL}")

cm_ver=$(cm --version 2>&1 | head -n 1 || echo "unknown")

CM_BOOTSTRAP_TOOLS_FILE="${CM_BOOTSTRAP_TOOLS_FILE:-/tmp/cm_bootstrap_tools.txt}"

refresh_toolchain_inventory() {
  local policy_file="${HOME:-/root}/.codemender/command_policy.yaml"
  local candidates=()
  local installed=()
  local missing=()

  while IFS= read -r cmd; do
    [ -n "${cmd}" ] && candidates+=("${cmd}")
  done < <(
    {
      if [ -f "${policy_file}" ]; then
        python3 -c "import sys, yaml; d = yaml.safe_load(open(sys.argv[1])) or {}; print('\n'.join(str(x) for x in (d.get('allowed_commands') or [])))" "${policy_file}" 2>/dev/null || true
      fi
      if [ -f "${CM_BOOTSTRAP_TOOLS_FILE}" ]; then
        cat "${CM_BOOTSTRAP_TOOLS_FILE}" 2>/dev/null || true
      fi
    } | awk 'NF && !seen[$0]++'
  )

  for cmd in "${candidates[@]}"; do
    if command -v "${cmd}" >/dev/null 2>&1; then
      installed+=("${cmd}")
    else
      missing+=("${cmd}")
    fi
  done

  local installed_str="None."
  local missing_str="None (all policy-allowed commands are installed)."
  if [ ${#installed[@]} -gt 0 ]; then
    installed_str="$(printf "%s, " "${installed[@]}")"
    installed_str="${installed_str%, }."
  fi
  if [ ${#missing[@]} -gt 0 ]; then
    missing_str="$(printf "%s, " "${missing[@]}")"
    missing_str="${missing_str%, }."
  fi

  BASE_TOOLCHAIN_INVENTORY="[EXECUTION ENVIRONMENT & TOOLCHAIN INVENTORY]
You are executing inside an ephemeral, stateless Cloud Run container (Debian Bookworm, root user).
- Pre-installed Tools: ${installed_str}
- NOT Pre-installed: ${missing_str}
- RULE: Do NOT execute filesystem searches (e.g. 'find / -name', 'which', 'whereis') searching for tools not listed above.
- If a toolchain is required and not present, you have root privileges to install it directly (e.g. 'apt-get update && apt-get install -y <pkg>' or curl)."
}

refresh_toolchain_inventory

log_header "🛡️  CodeMender Slim Worker Initializing (Stateless / Zero-DB Mode)"
echo "📦 Target Repository:  ${REPO}"
echo "🌿 Target Ref:         ${TARGET_REF} (Base: ${BASE_REF})"
if [ "${ACTION}" = "remediate" ]; then
  echo "⚙️  Action:             ${ACTION} (Mode: ${MODE})"
else
  echo "⚙️  Action:             ${ACTION}"
fi
echo "🤖 Gemini Model:       ${CM_MODEL}"
echo "📦 CodeMender Version: ${cm_ver}"
echo "🔧 Additional Logging: ${ADDITIONAL_LOGGING}"
[ -n "${ISSUE_NUM}" ] && echo "🎫 Issue Number:       #${ISSUE_NUM}"
[ -n "${VULN_ID}" ] && echo "🎯 Vulnerability ID:   ${VULN_ID}"

# ==============================================================================
# CodeMender Configuration & Policy Resolution
# ==============================================================================
setup_codemender_config() {
  local active_dir="${HOME:-/root}/.codemender"
  local repo_cm_dir="${REPO_DIR:-/workspace/repo}/.codemender"

  if [ -d "${repo_cm_dir}" ]; then
    log_info "Found .codemender in repository; applying overrides to ${active_dir}..."
    mkdir -p "${active_dir}"
    shopt -s nullglob
    local files=("${repo_cm_dir}"/*)
    shopt -u nullglob
    if [ ${#files[@]} -gt 0 ]; then
      cp -rf "${repo_cm_dir}"/* "${active_dir}/"
      if [ -f "${repo_cm_dir}/config.yaml" ]; then
        log_success "Using repository CodeMender configuration from ${repo_cm_dir}/config.yaml"
      fi
      if [ -f "${repo_cm_dir}/command_policy.yaml" ]; then
        log_success "Using repository CodeMender command policy from ${repo_cm_dir}/command_policy.yaml"
      fi
    fi
  else
    log_info "No .codemender in repository; continuing with baked-in ${active_dir}"
  fi
  refresh_toolchain_inventory
}

run_repo_bootstrap() {
  if [ "${ACTION}" = "scan" ]; then
    return 0
  fi
  local bootstrap_script="${REPO_DIR:-/workspace/repo}/.codemender/bootstrap.sh"
  if [ -f "${bootstrap_script}" ]; then
    log_info "Found .codemender/bootstrap.sh; bootstrapping toolchains for ${ACTION} (${#@} target file(s))..."
    if (cd "${REPO_DIR:-/workspace/repo}" && CM_ACTION="${ACTION}" CM_BOOTSTRAP_TOOLS_FILE="${CM_BOOTSTRAP_TOOLS_FILE}" bash "${bootstrap_script}" "$@"); then
      log_success "Completed .codemender/bootstrap.sh toolchain setup."
    else
      log_warn ".codemender/bootstrap.sh failed; continuing with available worker toolchains."
    fi
  fi
  refresh_toolchain_inventory
}

# ==============================================================================
# Authentication & Repository Setup
# ==============================================================================
setup_auth_and_workspace() {
  local caller_token="${GITHUB_TOKEN:-}"
  local app_token=""

  if [ -n "${GITHUB_APP_ID:-}" ] && [ -n "${GITHUB_APP_INSTALLATION_ID:-}" ]; then
    log_info "Acquiring dynamic installation access token via GitHub App (ID: ${GITHUB_APP_ID})..."
    export GITHUB_APP_SECRET_NAME="${GITHUB_APP_SECRET_NAME:-codemender-github-app}"
    rm -f /tmp/github_app_token
    python3 "${SCRIPT_DIR}/github_app_auth.py" --configure || true
    if [ -f "/tmp/github_app_token" ]; then
      local dyn
      dyn="$(tr -d '\r\n[:space:]' < /tmp/github_app_token)"
      if [[ "${dyn}" =~ ^ghs_ ]]; then
        app_token="${dyn}"
        log_success "Successfully acquired dynamic GitHub App installation token."
      fi
    fi
  fi

  export GITHUB_TOKEN="${app_token:-${caller_token}}"
  export GH_TOKEN="${GITHUB_TOKEN}"

  if [ -n "${GITHUB_TOKEN:-}" ]; then
    git config --global --add safe.directory "*"
    git config --global url."https://x-access-token:${GITHUB_TOKEN}@github.com/".insteadOf "https://github.com/"
    git config --global user.name "${GIT_USER_NAME:-codemender-runner[bot]}"
    git config --global user.email "${GIT_USER_EMAIL:-codemender-runner[bot]@users.noreply.github.com}"
    echo "${GITHUB_TOKEN}" | gh auth login --with-token 2>/dev/null || true
    gh auth setup-git 2>/dev/null || true

    log_info "Cloning https://github.com/${REPO} (ref: ${TARGET_REF})..."
    if ! git clone --depth 50 --branch "${TARGET_REF}" "https://x-access-token:${GITHUB_TOKEN}@github.com/${REPO}.git" "${REPO_DIR}" 2>/dev/null; then
      log_warn "Ref '${TARGET_REF}' not found directly, cloning default branch..."
      git clone --depth 50 "https://x-access-token:${GITHUB_TOKEN}@github.com/${REPO}.git" "${REPO_DIR}"
    fi
    log_success "Workspace initialized for ${REPO} at ${REPO_DIR}."
  else
    log_warn "GITHUB_TOKEN not provided. Relying on local workspace mount if present."
    git config --global user.name "codemender-bot"
    git config --global user.email "codemender-bot@google.com"
  fi

  setup_codemender_config

  cd "${REPO_DIR}"
}

# ==============================================================================
# Action 1: Scheduled Security Scan & Discovery (cm find)
# ==============================================================================
run_scan() {
  log_header "🔍 Route A: Scheduled Security Scan & Discovery (cm find)"
  log_step "Step 1: Gathering Wiz MCP Security Context for ${REPO}..."
  local wiz_ctx="/tmp/wiz_context.md"
  local wiz_json="/tmp/wiz_context.json"
  python3 "${FETCH_WIZ_SCRIPT}" --repo "${REPO}" --output "${wiz_ctx}" --json-output "${wiz_json}" --project "${PROJECT_ID}" --secret "${WIZ_SECRET_NAME}" || true
  if [ -s "${wiz_ctx}" ]; then
    log_info "Loaded external Wiz security context from ${wiz_ctx}."
  else
    log_info "No external Wiz context returned. Proceeding with direct repository scan."
  fi

  log_step "Step 2: Executing CodeMender Scan (cm find)..."
  local status=0
  local find_ctx="${BASE_TOOLCHAIN_INVENTORY}"
  if [ -s "${wiz_ctx}" ]; then
    find_ctx="${find_ctx}

$(cat "${wiz_ctx}")"
    log_info "Executing: cm find . -c \"<toolchain_inventory + wiz_security_context>\" -y --unrestricted --bypass-warning ${MODEL_ARGS[*]:-}"
  else
    log_info "Executing: cm find . -c \"<toolchain_inventory>\" -y --unrestricted --bypass-warning ${MODEL_ARGS[*]:-}"
  fi
  if [ "${CM_MOCK_FINDINGS}" = "true" ]; then
    log_warn "🧪 MOCK MODE ACTIVE: Skipping 'cm find', injecting synthetic mock findings..."
    python3 "${MOCK_FINDINGS_SCRIPT}" --output "${ARTIFACTS_DIR}/findings.json" --repo "${REPO}"
  else
    cm find . -c "${find_ctx}" -y --unrestricted --bypass-warning "${MODEL_ARGS[@]}" 2>&1 | tee "${ARTIFACTS_DIR}/cm-find.log" || status="${PIPESTATUS[0]}"

    if [ "${status}" -ne 0 ] || grep -qE "Session FAILED|code\s*=\s*13|code=13" "${ARTIFACTS_DIR}/cm-find.log" 2>/dev/null; then
      log_error "CodeMender find scan failed (exit code: ${status})."
      exit "${status:-1}"
    fi

    cm report --format json > "${ARTIFACTS_DIR}/findings.json" 2>/dev/null || echo '[]' > "${ARTIFACTS_DIR}/findings.json"
  fi
  local total
  total=$(jq -r 'if type=="array" then length else (.findings // [] | length) end' "${ARTIFACTS_DIR}/findings.json" 2>/dev/null || echo 0)
  log_success "Discovery scan complete. Discovered ${total} candidate finding(s)."
  log_info "Findings saved to ${ARTIFACTS_DIR}/findings.json"

  log_step "Step 3: Preparing & Uploading Verification Matrix (Pre-Verification Deduplication)..."
  if [ "${total}" -gt 0 ]; then
    log_info "Evaluating ${total} scan candidate(s) against existing Wiz penetration tests with Gemini semantic reasoning..."
    python3 "${PARSE_ISSUE_SCRIPT}" \
      --scan-matrix "${ARTIFACTS_DIR}/findings.json" \
      --wiz-context "${wiz_json}" \
      --project "${PROJECT_ID}" > "${ARTIFACTS_DIR}/matrix.json" || echo '[]' > "${ARTIFACTS_DIR}/matrix.json"
    local matrix_count
    matrix_count=$(jq 'length' "${ARTIFACTS_DIR}/matrix.json" 2>/dev/null || echo 0)
    log_success "Verification matrix ready: ${matrix_count} new candidate(s) to verify (${total} total candidates scanned)."
  else
    log_info "No candidate findings discovered. Skipping verification matrix generation."
    echo "[]" > "${ARTIFACTS_DIR}/matrix.json"
  fi

  if [ -n "${SCAN_ARTIFACTS_BUCKET:-}" ]; then
    python3 "${SCRIPT_DIR}/gcs_helper.py" upload "${ARTIFACTS_DIR}/matrix.json" "gs://${SCAN_ARTIFACTS_BUCKET}/scans/${CLOUD_RUN_EXECUTION:-default}/matrix.json" 2>&1 || true
    [ -s "${wiz_ctx}" ] && python3 "${SCRIPT_DIR}/gcs_helper.py" upload "${wiz_ctx}" "gs://${SCAN_ARTIFACTS_BUCKET}/scans/${CLOUD_RUN_EXECUTION:-default}/wiz_context.md" 2>&1 || true
    log_success "Uploaded scan artifacts to gs://${SCAN_ARTIFACTS_BUCKET}/scans/${CLOUD_RUN_EXECUTION:-default}/"
  fi
}

# ==============================================================================
# Action 2: Isolated Parallel Verification & Wiz Export (cm verify)
# ==============================================================================
run_verify() {
  log_header "🧪 Route B: Isolated Verification Worker for Finding: ${VULN_ID}"
  log_step "Step 1: Normalizing & Importing Candidate Finding..."
  if [ -n "${CANDIDATE_JSON_B64:-}" ]; then
    echo "${CANDIDATE_JSON_B64}" | base64 -d > "${ARTIFACTS_DIR}/candidate_finding.json"
  elif [ -n "${ISSUE_BODY_B64:-}" ]; then
    echo "${ISSUE_BODY_B64}" | base64 -d > "${ARTIFACTS_DIR}/candidate_finding.json"
  fi

  python3 "${PARSE_ISSUE_SCRIPT}" \
    --normalize-candidate "${ARTIFACTS_DIR}/candidate_finding.json" \
    --vuln-id "${VULN_ID}" \
    --output "${ARTIFACTS_DIR}/imported_findings.json"

  if [ ! -s "${ARTIFACTS_DIR}/imported_findings.json" ]; then
    log_error "imported_findings.json is empty or failed to generate."
    exit 1
  fi

  local verify_files=()
  while IFS= read -r fp; do
    [ -n "${fp}" ] && verify_files+=("${fp}")
  done < <(jq -r 'if type=="array" then .[] else (.findings // [])[] end | .location.file_path // .file_path // empty' "${ARTIFACTS_DIR}/imported_findings.json" 2>/dev/null | sort -u || true)
  run_repo_bootstrap "${verify_files[@]+"${verify_files[@]}"}"

  log_info "Registering candidate finding into CodeMender (cm report import)..."
  cm report import --file "${ARTIFACTS_DIR}/imported_findings.json" -p "${REPO_DIR}" 2>&1 | tee "${ARTIFACTS_DIR}/cm-import.log" || true
  cm report --format json > "${ARTIFACTS_DIR}/findings.json" 2>> "${ARTIFACTS_DIR}/cm-import.log" || true

  local target_id
  target_id=$(python3 "${PARSE_ISSUE_SCRIPT}" --resolve-imported-id --artifacts-dir "${ARTIFACTS_DIR}")
  if [ -z "${target_id}" ]; then
    log_error "Could not resolve CodeMender Finding ID after cm report import."
    exit 1
  fi

  local short_id="${target_id:0:8}"
  local verify_ctx="${BASE_TOOLCHAIN_INVENTORY}

[STRICT HIGH-SPEED VERIFICATION DIRECTIVES]
1. HARD TURN BUDGET: You MUST conclude verification (call report_finding or finish) within 6 agent turns.
2. ZERO BUILD OR DEPENDENCY OVERHEAD: The build command is 'true'. DO NOT run 'npm install', 'mvn clean install', 'gradle', 'cargo', or any package manager. Do not spend turns downloading or compiling external libraries.
3. FORBIDDEN BLOCKING PROCESSES: NEVER start long-running servers, web apps, or background daemons (e.g. 'npm start', 'node server.js', 'flask run', 'python -m http.server'). All bash commands MUST terminate within 5 seconds.
4. STATIC & UNIT SINK CONFIRMATION:
   - Determine whether the vulnerability is reachable by analyzing the AST/code flow statically.
   - If writing a PoC in '.exploit/exploit.sh', write a minimal 5-line unit script directly invoking the function/class with mock inputs (e.g. 'python3 -c ...' or a focused test run). Do NOT attempt live multi-tier web server or database exploits.
5. FAST EARLY TERMINATION: As soon as you confirm the code path lacks input sanitization or authorization checks, immediately call report_finding with confidence >= 80% and call finish. If dead code or properly mitigated, call finish immediately."
  if [ "${CM_MOCK_FINDINGS}" = "true" ]; then
    log_warn "🧪 MOCK MODE ACTIVE: Skipping 'cm verify', simulating VERIFIED exploit status..."
    python3 "${MOCK_FINDINGS_SCRIPT}" --mock-verify --artifacts-dir "${ARTIFACTS_DIR}" --finding-id "${target_id}"
  else
    log_step "Step 2: Executing cm verify for ${target_id} (${short_id})..."
    log_info "Command: cm verify \"${target_id}\" -c \"<strict_high_speed_directives>\" ${MODEL_ARGS[*]:-} --skip-exploit-verification --no-reset -y --unrestricted --bypass-warning"
    local verify_status=0
    cm verify "${target_id}" -c "${verify_ctx}" "${MODEL_ARGS[@]}" --skip-exploit-verification --no-reset -y --unrestricted --bypass-warning 2>&1 | tee "${ARTIFACTS_DIR}/cm-verify-${short_id}.log" || verify_status="${PIPESTATUS[0]}"
    cm report --format json > "${ARTIFACTS_DIR}/findings.json" 2>/dev/null || true

    if [ "${verify_status}" -ne 0 ] || grep -qE "Session FAILED|code\s*=\s*13|code=13" "${ARTIFACTS_DIR}/cm-verify-${short_id}.log" 2>/dev/null; then
      log_error "CodeMender verification failed for ${short_id} (exit code: ${verify_status})."
      exit "${verify_status:-1}"
    fi
  fi

  log_step "Step 3: Evaluating Verification Status & Ingesting to Wiz..."
  local is_verified
  is_verified=$(python3 "${PARSE_ISSUE_SCRIPT}" --is-verified --artifacts-dir "${ARTIFACTS_DIR}" --finding-id "${target_id}" --vuln-id "${VULN_ID}")
  if [ "${is_verified}" = "true" ]; then
    log_success "Finding ${short_id} confirmed VERIFIED active sink! Ingesting to Wiz Penetration Tests..."
    local cm_ver
    cm_ver=$(cm --version 2>&1 | head -n 1 | awk '{print $NF}' || echo "unknown")
    local ctx_arg=()
    if [ -s "/tmp/wiz_context.json" ]; then
      ctx_arg=(--wiz-context "/tmp/wiz_context.json")
    elif [ -s "${ARTIFACTS_DIR}/wiz_context.json" ]; then
      ctx_arg=(--wiz-context "${ARTIFACTS_DIR}/wiz_context.json")
    fi

    python3 "${INGEST_WIZ_SCRIPT}" \
      --finding-file "${ARTIFACTS_DIR}/imported_findings.json" \
      --repo "${REPO}" \
      --model "${CM_MODEL}" \
      --cm-version "${cm_ver}" \
      --project "${PROJECT_ID}" \
      --secret "${WIZ_SECRET_NAME}" \
      ${ctx_arg[@]+"${ctx_arg[@]}"} \
      --output "${ARTIFACTS_DIR}/wiz_pentest.json" 2>&1 | tee "${ARTIFACTS_DIR}/wiz-ingest.log" || true
    local wiz_id
    wiz_id=$(jq -r '.id // empty' "${ARTIFACTS_DIR}/wiz_pentest.json" 2>/dev/null || true)
    local ingest_status
    ingest_status=$(jq -r '.status // empty' "${ARTIFACTS_DIR}/wiz_pentest.json" 2>/dev/null || true)
    if [ "${ingest_status}" = "CORRELATED_EXISTING" ] || [ "${ingest_status}" = "EXISTING" ]; then
      log_success "Deduplicated against existing Wiz finding: ${wiz_id} (status: ${ingest_status})"
    elif [ -n "${wiz_id}" ]; then
      log_success "Linked Wiz Penetration Test: ${wiz_id}"
    else
      log_warn "Finding was verified by CodeMender but could not be registered in Wiz Penetration Tests."
    fi
  else
    log_warn "Finding ${short_id} was NOT verified by CodeMender (status is DISMISSED or UNVERIFIED). Skipping Wiz export and Gemini deduplication."
  fi
  log_info "🏁 Verification completed for ${short_id}."
}

# ==============================================================================
# Action 3: Downstream Context Intake & Remediation (cm fix)
# ==============================================================================
run_remediate() {
  log_header "🛠️ Route C: Downstream Context Intake & Remediation (cm fix)"
  log_step "Step 1: Ingesting Downstream Context & Structured Findings..."
  [ -n "${ISSUE_BODY_B64:-}" ] && echo "${ISSUE_BODY_B64}" | base64 -d > /tmp/issue_body.txt || touch /tmp/issue_body.txt
  [ -n "${ISSUE_COMMENT_B64:-}" ] && echo "${ISSUE_COMMENT_B64}" | base64 -d > /tmp/issue_comment.txt || touch /tmp/issue_comment.txt

  local comment_txt
  comment_txt="$(cat /tmp/issue_comment.txt 2>/dev/null || true)"
  if [[ "${comment_txt}" =~ ^/(cm|codemender)[[:space:]]+fix([[:space:]]+([a-zA-Z0-9_-]+))? ]]; then
    log_info "Detected '/cm fix' command in issue comment. Setting MODE=fix."
    MODE="fix"
    [ -n "${BASH_REMATCH[3]:-}" ] && VULN_ID="${BASH_REMATCH[3]}"
  fi

  if [ -n "${ISSUE_NUM}" ] && [ -n "${GITHUB_TOKEN:-}" ] && [ ! -s /tmp/issue_body.txt ]; then
    log_info "Fetching issue #${ISSUE_NUM} from GitHub..."
    gh issue view "${ISSUE_NUM}" --repo "${REPO}" --json body -q .body > /tmp/issue_body.txt 2>/dev/null || true
    gh issue view "${ISSUE_NUM}" --repo "${REPO}" --json comments -q '.comments[].body' >> /tmp/issue_comment.txt 2>/dev/null || true
  fi

  if [ -n "${VULN_ID}" ] && [ "${VULN_ID}" != "all" ] && [ ! -s /tmp/issue_body.txt ] && [ -n "${GITHUB_TOKEN:-}" ]; then
    log_info "Searching for open issue matching finding '${VULN_ID}' in ${REPO}..."
    local matched
    matched=$(gh issue list --repo "${REPO}" --state open --search "${VULN_ID}" --limit 1 --json number -q '.[0].number' 2>/dev/null || true)
    if [ -n "${matched}" ]; then
      log_info "Found matching Issue #${matched} for finding '${VULN_ID}'."
      ISSUE_NUM="${matched}"
      gh issue view "${ISSUE_NUM}" --repo "${REPO}" --json body -q .body > /tmp/issue_body.txt 2>/dev/null || true
    fi
  fi

  python3 "${PARSE_ISSUE_SCRIPT}" \
    --body-file /tmp/issue_body.txt \
    --comment-file /tmp/issue_comment.txt \
    --repo "${REPO}" \
    --workspace "${REPO_DIR}" \
    --output "${ARTIFACTS_DIR}/imported_findings.json" \
    --fixes-output "${ARTIFACTS_DIR}/recommended_fixes.json" \
    --context-output "${ARTIFACTS_DIR}/recommended_fixes.txt"

  if [ ! -s "${ARTIFACTS_DIR}/imported_findings.json" ] || [ "$(jq -r 'length // 0' "${ARTIFACTS_DIR}/imported_findings.json" 2>/dev/null || echo 0)" -eq 0 ]; then
    log_warn "No actionable structured security finding was found in issue context."
    exit 0
  fi

  log_step "Step 2: Registering Findings into CodeMender (cm report import)..."
  cm report import --file "${ARTIFACTS_DIR}/imported_findings.json" -p "${REPO_DIR}" 2>&1 | tee "${ARTIFACTS_DIR}/cm-import.log" || true
  cm report --format json > "${ARTIFACTS_DIR}/findings.json" 2>> "${ARTIFACTS_DIR}/cm-import.log" || true

  local filter_args=()
  if [ -n "${VULN_ID:-}" ] && [ "${VULN_ID}" != "all" ] && [ -z "${RUNNER_BRANCH:-}" ] && [ -z "${ISSUE_BODY_B64:-}" ]; then
    filter_args=(--vuln-id "${VULN_ID}")
  fi

  python3 "${PARSE_ISSUE_SCRIPT}" --generate-tasks --artifacts-dir "${ARTIFACTS_DIR}" --tasks-output "${ARTIFACTS_DIR}/remediation_tasks.json" "${filter_args[@]}"

  local num_tasks
  num_tasks=$(jq -r 'length // 0' "${ARTIFACTS_DIR}/remediation_tasks.json" 2>/dev/null || echo 0)
  if [ "${num_tasks}" -eq 0 ]; then
    log_warn "No matching remediation tasks found to process."
    exit 0
  fi

  local owner_name="${OWNER:-$(jq -r '.[0].owner // ""' "${ARTIFACTS_DIR}/remediation_tasks.json" | sed 's/^@//')}"
  local branch
  if [ -n "${RUNNER_BRANCH:-}" ]; then
    branch="${RUNNER_BRANCH}"
  elif [ -n "${owner_name}" ] && [ "${owner_name}" != "unassigned" ]; then
    branch="codemender/fix-owner-${owner_name}"
  elif [ "${num_tasks}" -eq 1 ]; then
    branch="codemender/fix-$(jq -r '.[0].short_id // "remediate"' "${ARTIFACTS_DIR}/remediation_tasks.json" | cut -c1-8)"
  else
    branch="codemender/fix-unassigned"
  fi

  log_step "Step 3: Preparing Branch ${branch} & Processing ${num_tasks} Finding(s)..."
  log_info "Base: ${BASE_REF} | Branch: ${branch} | Owner: ${owner_name:-unassigned}"
  git checkout -f "${BASE_REF}" 2>/dev/null || git checkout -f main 2>/dev/null || true
  git clean -fd
  git checkout -B "${branch}"
  setup_codemender_config

  local task_files=()
  while IFS= read -r fp; do
    [ -n "${fp}" ] && task_files+=("${fp}")
  done < <(jq -r '.[].file_path // empty' "${ARTIFACTS_DIR}/remediation_tasks.json" 2>/dev/null | sort -u || true)
  run_repo_bootstrap "${task_files[@]+"${task_files[@]}"}"

  local committed=0
  local first_label=""
  local first_color=""
  local last_wiz_id=""

  for (( idx=0; idx<num_tasks; idx++ )); do
    local fid short_id fpath line title sev lname lcolor rec_fixes
    fid=$(jq -r ".[$idx].finding_id" "${ARTIFACTS_DIR}/remediation_tasks.json")
    short_id=$(jq -r ".[$idx].short_id" "${ARTIFACTS_DIR}/remediation_tasks.json")
    fpath=$(jq -r ".[$idx].file_path" "${ARTIFACTS_DIR}/remediation_tasks.json")
    line=$(jq -r ".[$idx].line" "${ARTIFACTS_DIR}/remediation_tasks.json")
    title=$(jq -r ".[$idx].title" "${ARTIFACTS_DIR}/remediation_tasks.json")
    sev=$(jq -r ".[$idx].severity" "${ARTIFACTS_DIR}/remediation_tasks.json")
    lname=$(jq -r ".[$idx].label_name" "${ARTIFACTS_DIR}/remediation_tasks.json")
    lcolor=$(jq -r ".[$idx].label_color" "${ARTIFACTS_DIR}/remediation_tasks.json")
    rec_fixes=$(jq -r ".[$idx].recommended_fixes // \"\"" "${ARTIFACTS_DIR}/remediation_tasks.json")

    [ -z "${first_label}" ] && first_label="${lname}"
    [ -z "${first_color}" ] && first_color="${lcolor}"
    [ -z "${rec_fixes}" ] && [ -n "${RECOMMENDED_FIXES_B64:-}" ] && rec_fixes="$(echo "${RECOMMENDED_FIXES_B64}" | base64 -d 2>/dev/null || echo "${RECOMMENDED_FIXES_B64}")"

    log_info "🛠️ Processing $((idx+1))/${num_tasks}: [${sev}] ${title} (${fpath}:${line})"

    if [ "${VERIFY_FIRST:-false}" = "true" ]; then
      log_step "Step 3a: Verifying Candidate Finding (cm verify)..."
      cm verify "${fid}" "${MODEL_ARGS[@]}" --skip-exploit-verification --no-reset -y --unrestricted --bypass-warning 2>&1 | tee "${ARTIFACTS_DIR}/cm-verify-${short_id}.log" || true
      cm report --format json > "${ARTIFACTS_DIR}/findings.json" 2>/dev/null || true
      local verified
      verified=$(python3 "${PARSE_ISSUE_SCRIPT}" --is-verified --artifacts-dir "${ARTIFACTS_DIR}" --finding-id "${fid}")
      if [ "${verified}" != "true" ]; then
        log_warn "Finding ${short_id} not verified as active sink. Skipping remediation."
        continue
      fi
      log_success "Finding ${short_id} verified as active sink."
    fi

    local existing_wiz_id
    existing_wiz_id=$(jq -r ".[$idx].wiz_id // empty" "${ARTIFACTS_DIR}/remediation_tasks.json" 2>/dev/null || true)
    if [ -n "${existing_wiz_id}" ]; then
      last_wiz_id="${existing_wiz_id}"
      log_info "Retained linked Wiz Penetration Test ID: ${last_wiz_id}"
    fi

    local fix_context="${BASE_TOOLCHAIN_INVENTORY}

[REMEDIATION & TESTING GUIDELINES]
1. Patch Implementation: Apply the recommended fix cleanly and defensively to the target file(s).
2. Targeted Unit Testing Only:
   - If the required toolchain is pre-installed or quickly installed, and a dedicated unit test file exists for the modified code (e.g. 'test/.../<module>_test.*'), you may run ONLY that specific test file to confirm your fix.
   - Do NOT run whole-repository build commands, multi-package test suites, or end-to-end integration tests.
3. Fallback: If a targeted unit test does not exist or requires external infrastructure (e.g. external databases, cloud services, Docker-in-Docker), do not attempt to set up mock infrastructure. Ensure syntactic correctness via code analysis and finalize the patch."

    if [ -n "${rec_fixes}" ]; then
      fix_context="${fix_context}

[APPLIED REMEDIATION GUIDANCE]
${rec_fixes}"
      if [ "${ADDITIONAL_LOGGING}" = "true" ]; then
        log_info "💡 Recommended Fix Guidance for ${short_id} (${#rec_fixes} characters):"
        echo "--------------------------------------------------------------------------------"
        echo "${rec_fixes}"
        echo "--------------------------------------------------------------------------------"
      else
        log_info "💡 Attached recommended fix guidance for ${short_id} (${#rec_fixes} characters)."
      fi
      log_info "Executing: cm fix \"${fid}\" -c \"<toolchain_inventory + testing_guidelines + guidance>\" ${MODEL_ARGS[*]:-} -y --unrestricted --bypass-warning"
    else
      log_warn "⚠️ No recommended fix guidance found for ${short_id}. CodeMender will infer fix autonomously."
      log_info "Executing: cm fix \"${fid}\" -c \"<toolchain_inventory + testing_guidelines>\" ${MODEL_ARGS[*]:-} -y --unrestricted --bypass-warning"
    fi
    cm fix "${fid}" -c "${fix_context}" "${MODEL_ARGS[@]}" -y --unrestricted --bypass-warning 2>&1 | tee "${ARTIFACTS_DIR}/cm-fix-${short_id}.log" || true

    if [ -n "$(git status --porcelain)" ]; then
      if [ "${ADDITIONAL_LOGGING}" = "true" ]; then
        log_info "Generated patch diff for ${short_id}:"
        echo "--------------------------------------------------------------------------------"
        git diff || true
        echo "--------------------------------------------------------------------------------"
      fi
      git commit -am "fix(security): apply CodeMender remediation for ${short_id}"
      committed=$((committed + 1))
      log_success "Staged remediation commit for ${short_id}."
    else
      log_info "No code modifications produced by CodeMender for ${short_id}."
    fi
  done

  log_step "Step 4: Authoring Consolidated Pull Request..."
  if [ "${committed}" -gt 0 ]; then
    log_info "${committed} remediation commit(s) generated on branch ${branch}."
    git remote set-url origin "https://x-access-token:${GITHUB_TOKEN}@github.com/${REPO}.git"
    git push origin "${branch}" --force
    log_success "Pushed branch ${branch} to origin."

    if [ -n "${RUNNER_BRANCH:-}" ]; then
      log_info "Runner branch '${branch}' pushed. PR aggregation deferred to workflow orchestrator."
      exit 0
    fi

    local pr_title pr_body_file="${ARTIFACTS_DIR}/pr_body.md"
    pr_title="$(python3 "${PARSE_ISSUE_SCRIPT}" --build-pr-title --artifacts-dir "${ARTIFACTS_DIR}" --owner "${owner_name}")"
    python3 "${PARSE_ISSUE_SCRIPT}" \
      --build-pr-body \
      --artifacts-dir "${ARTIFACTS_DIR}" \
      --repo "${REPO}" \
      --ref "${TARGET_REF}" \
      --base-ref "${BASE_REF}" \
      --issue-num "${ISSUE_NUM}" \
      --wiz-id "${last_wiz_id}" \
      --owner "${owner_name}" \
      --output "${pr_body_file}"

    [ -n "${GITHUB_TOKEN:-}" ] && [ -n "${first_label}" ] && gh label create "${first_label}" --color "${first_color}" --description "CodeMender automated remediation" --repo "${REPO}" --force 2>/dev/null || true

    local existing_pr=""
    [ -n "${GITHUB_TOKEN:-}" ] && existing_pr=$(gh pr list --repo "${REPO}" --head "${branch}" --state open --json number -q '.[0].number' 2>/dev/null || true)

    if [ -n "${existing_pr}" ]; then
      log_info "Updating existing Draft PR #${existing_pr} on branch ${branch}..."
      gh pr edit "${existing_pr}" --repo "${REPO}" --title "${pr_title}" --body-file "${pr_body_file}" --add-label "${first_label}" 2>/dev/null || true
      log_success "Draft PR #${existing_pr} updated."
    else
      log_info "Creating new Draft Pull Request on branch ${branch}..."
      local assignee_args=()
      [ -n "${owner_name}" ] && [ "${owner_name}" != "unassigned" ] && assignee_args=(--assignee "${owner_name}")
      gh pr create --draft --repo "${REPO}" --head "${branch}" --base "${BASE_REF}" --title "${pr_title}" --body-file "${pr_body_file}" --label "${first_label}" "${assignee_args[@]}" \
        || gh pr create --draft --repo "${REPO}" --head "${branch}" --base "${BASE_REF}" --title "${pr_title}" --body-file "${pr_body_file}"
      log_success "Draft Pull Request opened."
    fi
  else
    log_info "No code modifications produced across any remediation task."
  fi
  log_success "Completed remediation processing for all ${num_tasks} finding(s)."
}

setup_auth_and_workspace
"run_${ACTION}"
