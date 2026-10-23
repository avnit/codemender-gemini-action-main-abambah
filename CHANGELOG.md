# Changelog

All notable changes to the **CodeMender Slim** (`codemender-gemini-action`) project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- **Experimental worker channel**:
  - `deploy-worker.yml` derives the image channel strictly from the branch ref: `refs/heads/main` publishes `worker:slim` (+ SHA tag), while pushes or manual dispatches on any feature branch automatically publish `worker:slim-experimental` (+ SHA tag) and can never overwrite `worker:slim`. The build summary prints the `gcloud run jobs update` command (jobs pin digests and are never updated automatically).
  - `codemender.yml` gains `channel` (default `stable`) and `experimental-job-name` inputs; `experimental` runs `<job-name>-experimental` for scan, verify and remediate, with a pre-check that fails clearly if the job does not exist.
  - README documents the one-time job clone (`gcloud run jobs describe --format=export` → `replace`) and the development loop.
- **Open in Google Cloud Shell & Interactive Provisioner (`setup.sh`)**:
  - Added "Open in Google Cloud Shell" badge and quickstart documentation to `README.md` linked to an interactive Cloud Shell walkthrough (`tutorial.md`).
  - Added idempotent, interactive `setup.sh` mirroring `infra/consumer` Terraform: enables required APIs (`run`, `secretmanager`, `aiplatform`, `logging`, `iam`, `storage`), prompts securely for Wiz credentials (`read -s`) into Secret Manager, provisions the `codemender-slim-runner` service account with least-privilege IAM, creates the `${PROJECT_ID}-codemender-artifacts` scan artifacts bucket (1-day lifecycle, `roles/storage.objectUser`), deploys the Cloud Run Job with `SCAN_ARTIFACTS_BUCKET`, and optionally configures GitHub Workload Identity Federation.
  - Prints a ready-to-paste caller workflow snippet (including `wif-provider` / `wif-service-account` inputs) and the GitHub repository variables to set.
  - Auto-detects the target project from the Cloud Shell session (active `gcloud config`, then `GOOGLE_CLOUD_PROJECT` / `DEVSHELL_PROJECT_ID`) without prompting; `-p` still overrides. The tutorial uses `<walkthrough-project-setup>` so users pick the project up front.
  - `--builder` provisions `infra/host` resources only (Artifact Registry repo, builder SA with `artifactregistry.writer`, org-scoped WIF binding, optional `--pull-member` / `--public-read`). `--collapsed` provisions host + consumer in one project with a single shared WIF pool/provider and separate builder/runner service accounts. Includes `infra/host` Terraform parity tests.
  - Added `tutorial.md` walkthrough with one-click execution blocks for Google Cloud Shell.
  - Added unit test suite `tests/test_setup_script.py` covering script syntax, help flags, dry-run simulation, Terraform parity, and documentation link validations.

### Changed
- **Wiz tenant selection & datacenter handling**:
  - `setup.sh` now requires the Wiz DataCenter (no `app` default; blank or invalid input re-prompts, and non-interactive runs fail fast without `--datacenter` / `WIZ_DATACENTER`).
  - `setup.sh` prompts for the Wiz Tenant Env (default `app`, or `--tenant-env`) and stores only the derived `mcp_url` (`https://mcp.<env>.wiz.io?mode=explicit`) in the secret. `WIZ_ENV` / `--wiz-env` are removed and the env itself is no longer stored or parsed.
  - When reusing an existing secret, `setup.sh` warns if it lacks `datacenter` or `mcp_url` and suggests overwriting it.
  - The worker reads `mcp_url` from the secret (falling back to `https://mcp.app.wiz.io?mode=explicit`); an explicit `--mcp-url` always wins. The environment-variable credential path for local runs now requires `WIZ_DATACENTER` alongside `WIZ_CLIENT_ID` / `WIZ_CLIENT_SECRET`.
  - When Wiz MCP is skipped (missing/unreadable secret, missing datacenter, rejected credentials, unreachable endpoint), `fetch_wiz_context.py` and `ingest_wiz_pentest.py` log a warning with the specific reason and how to fix it.

---

## [0.0.1] - 2026-09-24

### Added
- **Initial Release of CodeMender Slim**:
  - Lean, cloud-native automated security scanning, verification, and vulnerability remediation engine powered by CodeMender (`cm`), Google Gemini, and Wiz Security Graph MCP.
  - Pure stateless architecture requiring zero persistent databases, Cloud Functions, Pub/Sub queues, or long-term storage buckets.

- **Stateless Cloud Run Worker Engine (`worker/`)**:
  - Ephemeral container image (`worker/Dockerfile`) based on Debian Bookworm Slim with pre-installed Go 1.24, Node.js 20.x, Python 3.11, build-essential, GitHub CLI (`gh`), Gemini CLI, and pre-baked CodeMender (`cm`) CLI binary.
  - Container entrypoint (`worker/entrypoint.sh`) providing unified dispatch for three core execution actions: `scan`, `verify`, and `remediate`.
  - Configurable Gemini model selection (defaulting to `gemini-3.8-flash`), customizable log verbosity, and headless execution flags (`--bypass-warning`, `--unrestricted`, `-y`).

- **Security Discovery Scan & Wiz MCP Graph Context (`action: scan`)**:
  - `worker/fetch_wiz_context.py`: Queries Wiz Security Graph via Wiz MCP JSON-RPC (`WizMcpClient`) over HTTP to discover cloud resources, active CVEs, SAST findings, exposed secrets, and penetration test findings, rendering a structured Markdown context file.
  - Executes full repository vulnerability discovery via `cm find .` enriched with toolchain inventory and external Wiz security context.
  - Pre-verification deduplication in `worker/planner.py`: leverages Gemini semantic reasoning (`find_semantic_match_with_gemini`) to cross-reference discovered candidates against existing Wiz penetration test findings, skipping redundant verification jobs.
  - Lightweight Cloud Storage handoff via `worker/gcs_helper.py`: utilizes minimal `google-cloud-storage` Python SDK (~25MB) instead of full Cloud SDK (~800MB) to stage candidate matrices and scan context (`gs://${PROJECT}-codemender-artifacts/scans/${EXECUTION}/`).

- **Parallel Verification & Wiz Penetration Test Ingestion (`action: verify`)**:
  - Decoupled parallel verification matrix in GitHub Actions executing `cm verify` concurrently in isolated Cloud Run jobs (`max-parallel: 10`).
  - Candidate finding normalization via `worker/parser.py` (`normalize_candidate_findings` / `--normalize-candidate`) for reliable registration via `cm report import`.
  - Strict high-speed verification directives (turn budget, zero build overhead, static & unit sink confirmation).
  - Verification outcome resolution (`is_finding_verified` / `--is-verified`) checking SQLite state DB and report outputs.
  - `worker/ingest_wiz_pentest.py`: Automatically registers confirmed active sinks (`status == VERIFIED`) into Wiz Penetration Testing findings via Wiz MCP with repository/branch resource graph links, CWE classification, vulnerable code snippets, and remediation guidance.

- **Autonomous Vulnerability Remediation (`action: remediate`)**:
  - `worker/parser.py`: Deterministic parser for downstream agent JSON outputs, markdown code fences, embedded JSON objects, escaped strings, and fallback regex patterns for plain-text issue bodies and comments (`extract_json_candidates`, `parse_downstream_agent_output`).
  - `(Owner, File)` Parallel Runner Isolation: `worker/planner.py` partitions remediation tasks by `(owner, file_path)` pairs. Multiple findings in the same file for the same owner are processed sequentially on a dedicated runner branch (`codemender/patch-${owner}-${runner_id}`), while findings across distinct files/owners run concurrently in isolated Cloud Run jobs to ensure conflict-free merges.
  - Autonomous patch generation using `cm fix` with targeted unit testing guidelines and applied remediation guidance.
  - Automatic commit staging for security patches (`fix(security): apply CodeMender remediation for <id>`).

- **Pull Request Authoring & Owner Branch Aggregation (`worker/pr_builder.py`)**:
  - Conventional commit PR title authoring (`build_pr_title`) tailored to single findings, owner batches, or unassigned batches.
  - Rich Markdown Draft PR body authoring (`build_pr_body`, `render_batch_pr_body`) featuring structured tables, severity badges/labels, file permalinks, issue close references (`Closes #<num>`), and embedded machine-readable metadata comments (`codemender-batch-metadata`, `wiz-pentest-metadata`).
  - Workflow orchestrator aggregation (`aggregate_owner_prs`): merges isolated runner branches per owner into consolidated branches (`codemender/fix-owner-${owner}` / `codemender/fix-unassigned`), opens or updates consolidated Draft PRs, assigns owners via `--assignee`, and cleans up temporary runner branches on the remote repository.

- **Centralized Logging & GitHub Actions Diagnostics (`worker/logger.py`)**:
  - Standardized logging module with configurable log levels (`LOG_LEVEL`, `ADDITIONAL_LOGGING`), timestamps, and component names.
  - Visual formatting helpers (`log_header`, `log_step`, `log_info`, `log_success`, `log_warn`, `log_error`, `log_debug`, `log_version`).
  - Native GitHub Actions workflow command integration (`::group::`, `::endgroup::`, `::error::`, `::warning::`, `::notice::`) and `log_group` context manager.

- **Dynamic Authentication & Secret Resolution**:
  - GitHub App authentication helper (`worker/github_app_auth.py`) for generating RS256 JWTs and acquiring dynamic installation access tokens.
  - Ambient Workload Identity Federation (WIF) or service account key authentication for Google Cloud.
  - GCP Secret Manager integration (`worker/common.py`) for retrieving Wiz API credentials (`wiz-mcp-config`).

- **Centralized Reusable GitHub Actions Workflows (`.github/workflows/`)**:
  - `codemender.yml`: Canonical reusable workflow supporting scheduled scans, manual triggers (`workflow_dispatch`), and `@cm-remediate` issue comments, coordinating `run-slim-scan`, `run-slim-verify`, `plan-remediation`, `run-slim-remediate`, and `aggregate-owner-prs` jobs.
  - `deploy-worker.yml`: Automated CI pipeline building and publishing worker container images (`:slim` and immutable commit SHA tags) to Google Artifact Registry.

- **Decoupled Terraform Infrastructure Modules (`infra/`)**:
  - `infra/host/`: Provisions central container distribution infrastructure (Artifact Registry `codemender-workers`, Builder Service Account `codemender-slim-builder`, Host Workload Identity Federation, and cross-project pull permissions).
  - `infra/consumer/`: Turnkey module for target consumer GCP projects provisioning the ephemeral Cloud Run Job (`wiz-codemender-slim`), runner execution Service Account (`codemender-slim-runner`), minimal IAM permissions, and Consumer WIF pool.

- **Automated Test Suite & Mocking Framework**:
  - 40 unit tests covering issue parsing, Wiz MCP integration, GCS helper, and logging (`PYTHONPATH=worker python3 -m unittest discover -s tests -v`).
  - `worker/mock_findings.py`: Synthetic mock findings and verification simulation mode (`--mock-findings`, `CM_MOCK_FINDINGS`) enabling end-to-end testing of discovery, matrix generation, and PR consolidation in seconds without invoking LLMs.
