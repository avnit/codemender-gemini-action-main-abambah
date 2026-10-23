#!/usr/bin/env python3
"""
Shared core utilities for CodeMender Slim Worker:
- File path & severity normalization
- Resilient JSON / file I/O helpers
- GCP Secret Manager & Wiz MCP JSON-RPC client
"""

import json
import logging
import os
import re
import subprocess
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

import requests
from logger import get_logger

logger = get_logger("codemender-common")

DEFAULT_SECRET_NAME = "wiz-mcp-config"

# Production Wiz MCP endpoint. Non-production tenants store their full endpoint
# (e.g. https://mcp.demo.wiz.io?mode=explicit) as `mcp_url` in the Wiz secret; setup.sh
# derives it from the --tenant-env prompt.
DEFAULT_MCP_URL = "https://mcp.app.wiz.io?mode=explicit"

SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
    "INFO": "ℹ️",
}

SEVERITY_COLORS = {
    "critical": "b60205",
    "high": "d93f0b",
    "medium": "fbca04",
    "low": "0e8a16",
    "info": "1d76db",
}


def first_of(data: Dict[str, Any], *keys: str, default: Any = "") -> Any:
    """Returns the first non-empty value for the given keys in `data`, or `default`."""
    if not isinstance(data, dict):
        return default
    for k in keys:
        val = data.get(k)
        if val is not None and val != "":
            return val
    return default


def clean_file_path(path: str) -> str:
    """Standardizes and cleans relative/absolute repository file paths."""
    if not path:
        return ""
    p = str(path).strip().strip("`'\"")
    p = re.sub(r"^.*?(?:_work|actions-runner)/[^/]+/[^/]+/", "", p)
    for prefix in ("/workspace/repo/", "/workspace/"):
        if p.startswith(prefix):
            p = p[len(prefix):]
            break
    else:
        if os.path.isabs(p):
            for marker in ("/repo/", "/juice-shop/", "/quackathon/", "/OpenLLM/"):
                if marker in p:
                    p = p.split(marker, 1)[1]
                    break
    p = re.sub(r"\s*\(L\d+.*?\)", "", p)
    p = re.sub(r"^\.?/+", "", p)
    p = re.sub(r"^(\.\./)+", "", p)
    return p.strip("`")


clean_path = clean_file_path


def format_severity(severity_str: str, use_icon: bool = True, icons: Optional[dict] = None) -> str:
    """Normalizes severity strings and optionally prefixes with status emoji."""
    s_clean = re.sub(r"<[^>]+>", "", str(severity_str).strip())
    s_clean = re.sub(r"^[🔴🟠🟡🟢⚪ℹ️🛡️\s]+", "", s_clean).strip().upper()
    if s_clean == "INFORMATIONAL":
        s_clean = "INFO"
    if not use_icon:
        return s_clean
    icon_map = icons or SEVERITY_ICONS
    emoji = icon_map.get(s_clean, "🛡️")
    return f"{emoji} {s_clean}" if s_clean else str(severity_str).strip()


def get_severity_label_info(severity: str) -> Tuple[str, str]:
    """Returns (label_name, hex_color) for a given severity string."""
    sev = str(severity).strip().lower()
    return f"codemender-fix:{sev}", SEVERITY_COLORS.get(sev, "1d76db")


def load_json_loose(text: str) -> Any:
    """Parses JSON resiliently, supporting unescaped newlines and shell-escaped quotes."""
    if not text or not text.strip():
        return None
    trimmed = text.strip()
    for candidate in (trimmed, trimmed.replace('\\"', '"')):
        try:
            return json.loads(candidate, strict=False)
        except Exception:
            pass
    fence = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", trimmed, re.IGNORECASE)
    if fence:
        inner = fence.group(1).strip()
        for candidate in (inner, inner.replace('\\"', '"')):
            try:
                return json.loads(candidate, strict=False)
            except Exception:
                pass
    return None


def read_json_file(path: str, default: Any = None) -> Any:
    """Reads and parses a JSON file safely, returning `default` on failure."""
    if not path or not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            parsed = load_json_loose(f.read())
            return parsed if parsed is not None else default
    except Exception:
        return default


def write_json_file(path: str, data: Any, indent: Optional[int] = 2) -> None:
    """Writes `data` as JSON to `path`, creating parent directories as needed."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=indent)


def extract_nodes(items: List[Dict[str, Any]], *container_keys: str) -> List[Dict[str, Any]]:
    """Extracts graph entity node dictionaries from Wiz MCP response envelopes."""
    nodes: List[Dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        found = None
        for key in container_keys:
            container = item.get(key)
            if isinstance(container, dict) and isinstance(container.get("nodes"), list):
                found = container["nodes"]
                break
        if found is None:
            found = item.get("nodes") if isinstance(item.get("nodes"), list) else ([item] if "id" in item else [])
        nodes.extend(n for n in found if isinstance(n, dict))
    return nodes


def fetch_gcp_secret(secret_name: str, project_id: Optional[str] = None) -> str:
    """Fetches a secret payload from GCP Secret Manager via Python SDK or gcloud CLI."""
    proj = (
        project_id
        or os.environ.get("GCP_PROJECT")
        or os.environ.get("PROJECT_ID")
        or os.environ.get("GCP_PROJECT_ID")
    )
    if not proj:
        raise RuntimeError("GCP_PROJECT environment variable or project_id parameter is required")
    try:
        from google.cloud import secretmanager
        client = secretmanager.SecretManagerServiceClient()
        res_name = (
            secret_name if "/versions/" in secret_name
            else f"{secret_name}/versions/latest" if "/" in secret_name
            else f"projects/{proj}/secrets/{secret_name}/versions/latest"
        )
        return client.access_secret_version(request={"name": res_name}).payload.data.decode("utf-8").strip()
    except Exception as e:
        sdk_error = e
        logger.debug(f"Secret Manager client notice: {e}")

    cmd = ["gcloud", "secrets", "versions", "access", "latest", f"--secret={secret_name}"]
    if proj and "/" not in secret_name:
        cmd.append(f"--project={proj}")
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except FileNotFoundError:
        # The slim worker image intentionally ships without gcloud; surface the SDK error instead.
        raise RuntimeError(f"Unable to access secret '{secret_name}' in project '{proj}': {sdk_error}") from None
    if res.returncode == 0 and res.stdout.strip():
        return res.stdout.strip()
    raise RuntimeError(f"Unable to access secret '{secret_name}' in project '{proj}': {sdk_error}")


def _wiz_creds(
    client_id: str = "",
    client_secret: str = "",
    datacenter: str = "",
    mcp_url: str = DEFAULT_MCP_URL,
    skip_reason: str = "",
) -> Dict[str, str]:
    """Builds the credential dict; a non-empty `skip_reason` means Wiz MCP must not be used."""
    return {
        "client_id": client_id,
        "client_secret": client_secret,
        "datacenter": datacenter,
        "mcp_url": mcp_url,
        "skip_reason": skip_reason,
    }


def load_wiz_credentials(
    project_id: Optional[str] = None,
    secret_name: str = DEFAULT_SECRET_NAME,
) -> Dict[str, str]:
    """Resolves Wiz credentials from environment variables (local runs) or GCP Secret Manager.

    Environment path: WIZ_CLIENT_ID + WIZ_CLIENT_SECRET + WIZ_DATACENTER (always the production MCP
    URL; pass --mcp-url to target another tenant). Secret path: JSON with client_id, client_secret,
    datacenter and optional mcp_url (written by setup.sh). The datacenter is required and never
    defaulted. When credentials are unusable, `skip_reason` explains why.
    """
    env_id = (os.environ.get("WIZ_CLIENT_ID") or "").strip()
    env_secret = (os.environ.get("WIZ_CLIENT_SECRET") or "").strip()
    env_mcp_url = (os.environ.get("WIZ_MCP_URL") or "").strip()
    if env_id and env_secret:
        env_dc = (os.environ.get("WIZ_DATACENTER") or "").strip()
        if not env_dc:
            return _wiz_creds(skip_reason=(
                "WIZ_CLIENT_ID/WIZ_CLIENT_SECRET are set but WIZ_DATACENTER is missing. "
                "Set WIZ_DATACENTER to your Wiz tenant datacenter (e.g. us20, eu1)."
            ))
        logger.info("Loaded Wiz credentials from environment variables.")
        return _wiz_creds(env_id, env_secret, env_dc, env_mcp_url or DEFAULT_MCP_URL)

    rerun_hint = f"Re-run ./setup.sh and choose to overwrite the '{secret_name}' secret."
    try:
        raw = fetch_gcp_secret(secret_name, project_id)
    except Exception as e:
        return _wiz_creds(skip_reason=(
            f"could not read Secret Manager secret '{secret_name}' ({e}). Check that the secret exists in the "
            "project and the runner service account has roles/secretmanager.secretAccessor, or set "
            "WIZ_CLIENT_ID, WIZ_CLIENT_SECRET and WIZ_DATACENTER for local runs."
        ))

    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("expected a JSON object")
    except Exception:
        return _wiz_creds(skip_reason=f"secret '{secret_name}' is not a valid JSON object. {rerun_hint}")

    cid = str(first_of(data, "Wiz-Client-Id", "client_id", "Wiz_Client_Id", "clientId")).strip()
    csec = str(first_of(data, "Wiz-Client-Secret", "client_secret", "Wiz_Client_Secret", "clientSecret")).strip()
    dc = str(first_of(data, "Wiz-DataCenter", "datacenter", "data_center")).strip()
    mcp_url = str(first_of(data, "mcp_url", "mcpUrl", "WIZ_MCP_URL", "url")).strip()

    if not cid or not csec:
        return _wiz_creds(skip_reason=f"secret '{secret_name}' is missing client_id or client_secret. {rerun_hint}")
    if not dc:
        return _wiz_creds(skip_reason=f"secret '{secret_name}' has no datacenter. {rerun_hint}")
    if not mcp_url:
        logger.info(
            f"Secret '{secret_name}' has no mcp_url; using {DEFAULT_MCP_URL}. "
            f"Non-production tenants: {rerun_hint}"
        )
    return _wiz_creds(cid, csec, dc, mcp_url or DEFAULT_MCP_URL)


load_credentials = load_wiz_credentials


class WizMcpClient:
    """Lightweight JSON-RPC client for Wiz MCP over HTTP."""

    def __init__(self, mcp_url: Optional[str] = None, creds: Optional[Dict[str, str]] = None):
        self.creds = creds or {}
        # Priority: explicit URL (e.g. --mcp-url) > URL stored in the Wiz secret > production default.
        self.mcp_url = mcp_url or self.creds.get("mcp_url") or DEFAULT_MCP_URL
        self.session = requests.Session()
        self.session_id: Optional[str] = None
        self._req_id = 0
        self.last_error: str = ""

    def _next_id(self) -> int:
        self._req_id += 1
        return self._req_id

    def _headers(self) -> Dict[str, str]:
        h = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Wiz-Client-Id": self.creds.get("client_id", ""),
            "Wiz-Client-Secret": self.creds.get("client_secret", ""),
            "Wiz-DataCenter": self.creds.get("datacenter", ""),
        }
        if self.session_id:
            for key in ("Mcp-Session-Id", "mcp-session-id", "X-Session-Id"):
                h[key] = self.session_id
        return h

    def initialize(self) -> bool:
        """Opens an MCP session. On failure returns False and records the cause in `last_error`."""
        self.last_error = ""
        if self.creds.get("skip_reason"):
            self.last_error = self.creds["skip_reason"]
            return False
        if not self.creds.get("client_id") or not self.creds.get("client_secret"):
            self.last_error = "no Wiz client ID/secret were provided."
            return False
        if not self.creds.get("datacenter"):
            self.last_error = "no Wiz datacenter was provided."
            return False
        payload = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"roots": {"listChanged": True}},
                "clientInfo": {"name": "codemender-slim-worker", "version": "1.0.0"},
            },
        }
        target = f"{self.mcp_url} (datacenter '{self.creds.get('datacenter')}')"
        try:
            resp = self.session.post(self.mcp_url, json=payload, headers=self._headers(), timeout=20)
            s_id = resp.headers.get("Mcp-Session-Id") or resp.headers.get("mcp-session-id")
            if not s_id and resp.status_code == 200:
                try:
                    s_id = resp.json().get("result", {}).get("sessionId")
                except Exception:
                    pass
            if s_id:
                self.session_id = str(s_id)
                self.session.post(
                    self.mcp_url,
                    json={"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
                    headers=self._headers(),
                    timeout=10,
                )
                logger.info(f"Connected to Wiz MCP at {target}.")
                return True
            if resp.status_code == 200:
                logger.info(f"Connected to Wiz MCP at {target}.")
                return True
            if resp.status_code in (401, 403):
                self.last_error = (
                    f"Wiz MCP rejected the credentials (HTTP {resp.status_code}) at {target}. Check the client "
                    "ID/secret, and that the datacenter and tenant env chosen in setup.sh match your Wiz tenant."
                )
            else:
                self.last_error = f"Wiz MCP returned HTTP {resp.status_code} during initialize at {target}."
            return False
        except Exception as e:
            self.last_error = f"could not reach Wiz MCP at {target}: {e}"
            return False

    def call_tool(self, tool_name: str, parameters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Invokes a Wiz MCP tool via the standard execute envelope."""
        payload = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "tools/call",
            "params": {
                "name": "execute",
                "arguments": {"tool_name": tool_name, "parameters": parameters or {}},
            },
        }
        call_url = self.mcp_url
        if self.session_id and "sessionId=" not in call_url:
            sep = "&" if "?" in call_url else "?"
            call_url = f"{call_url}{sep}sessionId={urllib.parse.quote(self.session_id)}"

        try:
            resp = self.session.post(call_url, json=payload, headers=self._headers(), timeout=30)
            if resp.status_code != 200:
                logger.warning(f"Wiz MCP tool '{tool_name}' returned HTTP {resp.status_code}")
                return []
            parsed_items: List[Dict[str, Any]] = []
            for item in resp.json().get("result", {}).get("content", []):
                text_content = item.get("text", "")
                if text_content:
                    try:
                        parsed = json.loads(text_content)
                        if isinstance(parsed, list):
                            parsed_items.extend(parsed)
                        elif isinstance(parsed, dict):
                            parsed_items.append(parsed)
                    except Exception:
                        parsed_items.append({"raw_text": text_content})
            return parsed_items
        except Exception as e:
            logger.warning(f"Error calling Wiz MCP tool '{tool_name}': {e}")
            return []


WizMcpSession = WizMcpClient
