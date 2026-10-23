# CodeMender Slim: Cloud Shell Setup
<walkthrough-tutorial-duration duration="3"></walkthrough-tutorial-duration>

Welcome to the **CodeMender Slim** interactive setup guide! In about 3 minutes, this walkthrough deploys the consumer-side infrastructure for the automated security scanning and vulnerability remediation engine into your Google Cloud project.

---

## 1. Overview & Architecture

CodeMender Slim is a lean, stateless, cloud-native automated vulnerability remediation engine powered by:
- **CodeMender (`cm`)** security reasoning engine
- **Google Gemini** models via Vertex AI
- **Wiz Security Graph MCP** for context-rich CVE, SAST, secret, and pentest correlation
- **Google Cloud Run Jobs** for serverless, parallel scan / verify / remediation runners

`setup.sh` is the imperative equivalent of the `infra/consumer` Terraform module. It is idempotent, so it is safe to re-run.

### What the Setup Script Configures:
1. **Google Cloud APIs**: Validates and enables `run.googleapis.com`, `secretmanager.googleapis.com`, `aiplatform.googleapis.com`, `logging.googleapis.com`, `iam.googleapis.com`, and `storage.googleapis.com`.
2. **Wiz MCP Credentials**: Prompts securely (masked terminal input) for your Wiz Service Account Client ID, Secret, DataCenter (required), and Tenant Env (default `app`, used to derive the MCP URL), storing them in Secret Manager (`wiz-mcp-config`).
3. **Runner Service Account & IAM**: Provisions `codemender-slim-runner` with least-privilege roles (`roles/secretmanager.secretAccessor`, `roles/aiplatform.user`, `roles/logging.logWriter`, `roles/logging.viewer`, and `roles/run.developer`).
4. **Scan Artifacts Bucket**: Creates `<PROJECT_ID>-codemender-artifacts` (uniform access, 1-day auto-delete) used to hand scan matrices from Cloud Run back to GitHub Actions, and grants the runner `roles/storage.objectUser`.
5. **Cloud Run Job**: Creates or updates `wiz-codemender-slim` with 2 vCPUs, 4 GiB memory, a 30-minute timeout, 2 retries, and `SCAN_ARTIFACTS_BUCKET` wired in.
6. **Workload Identity Federation (Optional)**: Reuses or creates the `codemender-pool` / `github-provider` and lets your GitHub repository impersonate the runner without keys.

---

## 2. Select Your Project

<walkthrough-project-setup></walkthrough-project-setup>

Point Cloud Shell at the project you picked above:

```bash
gcloud config set project <walkthrough-project-id/>
```

`setup.sh` automatically uses the project from your Cloud Shell session (active `gcloud config`, falling back to `GOOGLE_CLOUD_PROJECT`), so you won't be prompted for it. Pass `-p <PROJECT_ID>` to override.

---

## 3. Launch Interactive Setup

Run the setup script directly in your Cloud Shell terminal:

```bash
./setup.sh
```

Preview everything without touching your project:

```bash
./setup.sh --dry-run
```

### Guided Prompts:
* **Google Cloud Project ID**: Auto-detected from your Cloud Shell session (no prompt).
* **Cloud Run Region**: Defaults to `us-central1` (or your configured region).
* **Wiz Service Account Credentials**:
  * **Client ID**: Your Wiz Service Account ID.
  * **Client Secret**: Input is masked (`read -s`) and confirmed.
  * **DataCenter** (required): Your Wiz tenant datacenter (e.g. `us20`, `eu1`). There is no default; blank input re-prompts.
  * **Tenant Env** (default `app`): Selects the Wiz MCP endpoint `https://mcp.<env>.wiz.io?mode=explicit` (e.g. `demo` → `mcp.demo.wiz.io`). Only the resulting URL is stored in the secret.
* **Workload Identity Federation**: Optionally specify a target GitHub repository (`owner/repo`) to allow keyless CI/CD dispatches.

---

## 4. Verify Cloud Run Job

Once the setup completes, verify that your Cloud Run Job is healthy:

```bash
gcloud run jobs describe wiz-codemender-slim --region=us-central1
```

Trigger a fast mock scan (skips `cm find`) against a public repository. The worker reads `KEY=VALUE` container args:

```bash
gcloud run jobs execute wiz-codemender-slim \
  --region=us-central1 \
  --args="REPO=owner/public-repo,CM_ACTION=scan,CM_MOCK_FINDINGS=true"
```

---

## 5. Connect Caller Repositories

In the caller repository, set these **Actions variables** (**Settings → Secrets and variables → Actions → Variables**), using the values printed at the end of `setup.sh`:

- `GCP_PROJECT`
- `GCP_REGION`
- `WIF_PROVIDER` *(if WIF was configured)*
- `WIF_SERVICE_ACCOUNT` *(if WIF was configured)*

Then add the CodeMender workflow (e.g. `.github/workflows/codemender.yml`):

```yaml
name: "CodeMender Security Suite"

on:
  schedule:
    - cron: "0 0 * * 0" # Weekly scheduled security scan
  issue_comment:
    types: [created]   # Comment '@cm-remediate' to trigger on an issue
  workflow_dispatch:
    inputs:
      action:
        description: "Operation: 'scan' or 'remediate'"
        required: true
        default: "remediate"
        type: choice
        options:
          - remediate
          - scan

permissions:
  contents: write
  issues: write
  pull-requests: write
  id-token: write

jobs:
  codemender:
    uses: <OWNER>/<REPO>/.github/workflows/codemender.yml@main
    secrets: inherit
    with:
      action: ${{ github.event_name == 'schedule' && 'scan' || github.event.inputs.action || 'remediate' }}
      project-id: ${{ vars.GCP_PROJECT }}
      region: ${{ vars.GCP_REGION }}
      job-name: "wiz-codemender-slim"
      wiz-secret-name: "wiz-mcp-config"
      wif-provider: ${{ vars.WIF_PROVIDER }}
      wif-service-account: ${{ vars.WIF_SERVICE_ACCOUNT }}
```

<walkthrough-conclusion-trophy></walkthrough-conclusion-trophy>

You're all set! CodeMender Slim is deployed and ready to automatically scan and remediate vulnerabilities.
