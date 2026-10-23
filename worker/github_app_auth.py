#!/usr/bin/env python3
"""Mints short-lived GitHub App Installation Access Tokens using an RSA PEM private key in GCP Secret Manager."""

import base64
import json
import logging
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

from common import fetch_gcp_secret

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("github-app-auth")


def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def generate_jwt_rs256(app_id: str, private_key_pem: str) -> str:
    """Generates an RS256 JWT valid for 9 minutes using cryptography."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    now = int(time.time())
    header = _base64url_encode(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode("utf-8"))
    payload = _base64url_encode(json.dumps({"iat": now - 60, "exp": now + 540, "iss": str(app_id)}, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header}.{payload}".encode("ascii")

    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8") if isinstance(private_key_pem, str) else private_key_pem,
        password=None,
    )
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input.decode('ascii')}.{_base64url_encode(signature)}"


def get_installation_access_token(app_id: str, installation_id: str, secret_name: str, project_id: str) -> str:
    """Exchanges an RS256 JWT for a GitHub App installation access token."""
    jwt_token = generate_jwt_rs256(app_id, fetch_gcp_secret(secret_name, project_id))
    req = urllib.request.Request(
        f"https://api.github.com/app/installations/{installation_id}/access_tokens",
        method="POST",
        headers={
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "codemender-worker-auth",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if token := data.get("token"):
                return token
            raise ValueError(f"No token returned in GitHub response: {data}")
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"GitHub API returned HTTP {e.code}: {e.read().decode('utf-8')}") from e


def configure_git_and_gh(token: str, git_user: str = "codemender-bot", git_email: str = "codemender-bot@google.com") -> None:
    """Configures git and gh CLI with the generated installation token."""
    subprocess.run(["git", "config", "--global", f"url.https://x-access-token:{token}@github.com/.insteadOf", "https://github.com/"], check=True)
    subprocess.run(["git", "config", "--global", "user.name", git_user], check=True)
    subprocess.run(["git", "config", "--global", "user.email", git_email], check=True)
    os.environ["GITHUB_TOKEN"] = os.environ["GH_TOKEN"] = token
    with open("/tmp/github_app_token", "w", encoding="utf-8") as f:
        f.write(token.strip())


if __name__ == "__main__":
    app_id = os.environ.get("GITHUB_APP_ID")
    inst_id = os.environ.get("GITHUB_APP_INSTALLATION_ID")
    if not app_id or not inst_id:
        print("ERROR: GITHUB_APP_ID and GITHUB_APP_INSTALLATION_ID must be set.", file=sys.stderr)
        sys.exit(1)

    secret_name = os.environ.get("GITHUB_APP_SECRET_NAME", "github-app-key")
    project = os.environ.get("GCP_PROJECT") or os.environ.get("PROJECT_ID") or os.environ.get("GCP_PROJECT_ID", "")
    tok = get_installation_access_token(app_id, inst_id, secret_name, project)
    if "--configure" in sys.argv:
        configure_git_and_gh(tok)
    else:
        with open("/tmp/github_app_token", "w", encoding="utf-8") as f:
            f.write(tok.strip())
    print(tok.strip())
