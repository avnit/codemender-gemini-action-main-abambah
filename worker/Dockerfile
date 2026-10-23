# Stage 1: Pull Go toolchain from official image
FROM golang:1.24-bookworm AS go-builder

# Stage 2: Minimal slim runtime
FROM debian:bookworm-slim

# 1. Copy Go toolchain from go-builder (minimal footprint, keeps Go available)
COPY --from=go-builder /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}"

# 2. Base tools, compilers, Python, Node.js 20, and GitHub CLI (NO bulky google-cloud-sdk)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    unzip \
    git \
    build-essential \
    python3 \
    python3-pip \
    python3-venv \
    ca-certificates \
    gnupg \
    jq \
 && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
 && apt-get install -y --no-install-recommends nodejs \
 && mkdir -p -m 755 /etc/apt/keyrings \
 && curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | tee /etc/apt/keyrings/githubcli-archive-keyring.gpg > /dev/null \
 && chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg \
 && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
 && apt-get update && apt-get install -y --no-install-recommends gh \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# 3. Minimal Python SDKs (google-cloud-storage replaces ~800MB google-cloud-cli package)
RUN pip install --no-cache-dir --break-system-packages \
    google-cloud-secret-manager \
    google-cloud-storage \
    cryptography \
    requests \
    pyyaml \
 && npm install -g @google/gemini-cli \
 && npm cache clean --force \
 && rm -rf /root/.cache

# 4. Download and pre-bake CodeMender (cm) CLI binary from Google Artifact Registry
RUN curl -L -o /tmp/cm-linux-amd64.zip \
    "https://artifactregistry.googleapis.com/download/v1/projects/cmoc-prod/locations/us/repositories/codemender-cli-production/files/cm%3Astable%3Acm-linux-amd64.zip:download?alt=media" \
 && unzip -q /tmp/cm-linux-amd64.zip -d /tmp/cm-dist \
 && mv /tmp/cm-dist/cm /usr/local/bin/cm \
 && chmod 755 /usr/local/bin/cm \
 && rm -rf /tmp/cm-linux-amd64.zip /tmp/cm-dist

# 5. Copy baseline CodeMender configuration and worker execution scripts
COPY worker/.codemender/ /root/.codemender/
COPY worker/entrypoint.sh /entrypoint.sh
COPY worker/*.py /worker/

RUN chmod +x /entrypoint.sh /worker/*.py

# 6. Runtime environment
ENV CM_DISABLE_SANDBOX=true
ENV PYTHONPATH=/worker

WORKDIR /workspace
ENTRYPOINT ["/entrypoint.sh"]
