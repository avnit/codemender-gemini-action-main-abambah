# CodeMender Slim Infrastructure

This directory separates infrastructure into two decoupled layers:

1. **`host/`**: Central infrastructure provisioned and maintained by you (the action host).
2. **`consumer/`**: Turnkey infrastructure provisioned in the consumer's Google Cloud project.

---

## 🏛️ Architecture & Responsibility Model

```
┌────────────────────────────────────────────────────────────────────────┐
│ HOST INFRASTRUCTURE (infra/host)                                      │
│ Project: host-gcp-project                                             │
├────────────────────────────────────────────────────────────────────────┤
│ • Artifact Registry Repository: codemender-workers                    │
│ • Builder Service Account: codemender-slim-builder                    │
│ • Host WIF: Authenticates GitHub Actions deploy-worker pipeline       │
│ • Cross-project image pull IAM permissions                             │
└────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ docker push (deploy-worker.yml)
                                    ▼
                     us-central1-docker.pkg.dev/.../worker:slim
                                    │
                                    │ docker pull (cross-project)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ CONSUMER INFRASTRUCTURE (infra/consumer)                               │
│ Project: customer-gcp-project                                         │
├────────────────────────────────────────────────────────────────────────┤
│ • Cloud Run Job: codemender-worker-slim (Pulls image from Host GAR)    │
│ • Dedicated Service Account: codemender-slim-runner                    │
│ • Minimal IAM: Secret Accessor (Wiz), Vertex AI User, Cloud Logging    │
│ • Consumer WIF: Authenticates customer GitHub Actions to run jobs      │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Execution & Deployment Order

Because Cloud Run requires a container image to already exist before the job can be created, follow this sequence:

### Step 1: Apply Host Infrastructure (GAR + Builder SA + Host WIF)
```bash
cd infra/host
terraform init
terraform apply -var="project_id=YOUR_HOST_PROJECT_ID"
```
*Outputs `wif_provider` and `builder_service_account_email`.*

### Step 2: Set Host GitHub Repo Variables & Build the Image
In your `codemender-gemini-action` GitHub repository (**Settings $\rightarrow$ Secrets and variables $\rightarrow$ Actions**):
- `WIF_PROVIDER`: *(From Step 1 output)*
- `WIF_SERVICE_ACCOUNT`: *(From Step 1 output)*
- `GCP_PROJECT`: `YOUR_HOST_PROJECT_ID`
- `GCP_REGION`: `us-central1`
- `AR_REPO`: `codemender-workers`

Now run or push to trigger **`.github/workflows/deploy-worker.yml`**. It authenticates via WIF, builds `worker/Dockerfile`, and pushes `worker:slim` into Artifact Registry.

### Step 3: Apply Consumer Infrastructure (Cloud Run Job + Consumer WIF)
Now that the image exists in GAR, deploy the consumer infrastructure:

```bash
cd ../consumer
terraform init
terraform apply \
  -var="project_id=YOUR_CONSUMER_PROJECT_ID" \
  -var="image_uri=us-central1-docker.pkg.dev/YOUR_HOST_PROJECT_ID/codemender-workers/worker:slim"
```

---

## 📦 Sharing with Customers (Future Multi-Tenant)

When onboarding a new customer or organization:

1. **You (Host)**:
   Add their project or service account to `authorized_pull_members` in `infra/host/` (or enable `public_read = true`).

2. **Customer (Consumer)**:
   Provide the customer with the `infra/consumer/` folder. They run:
   ```bash
   cd infra/consumer
   terraform init
   terraform apply \
     -var="project_id=acme-corp-security" \
     -var="github_repo=acme-corp/target-repo" \
     -var="create_wif=true"
   ```
   The consumer Terraform outputs the exact workflow snippet for them to paste into `.github/workflows/codemender.yml`.
