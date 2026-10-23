#!/usr/bin/env python3
"""
Unit tests for CodeMender Slim Wiz Integration:
- fetch_wiz_context.py
- ingest_wiz_pentest.py
- resolve_wiz_pentest.py
- parse_issue.py (Wiz metadata in Draft PR body)
"""

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

# Ensure worker is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "worker")))

from fetch_wiz_context import (
    format_context_markdown,
    load_wiz_credentials,
    WizMcpClient,
    harvest_wiz_context,
)
from ingest_wiz_pentest import (
    clean_path,
    fetch_all_open_wiz_findings,
    find_semantic_match_with_gemini,
    ingest_finding_to_wiz,
    normalize_wiz_finding_for_llm,
)
from parse_issue import build_pr_body
from parser import normalize_candidate_findings
from planner import generate_scan_matrix, is_finding_verified


class TestSlimWizIntegration(unittest.TestCase):

    def test_format_context_markdown(self):
        ctx = {
            "repo": "wiz-demo/talisman",
            "resources": [{"id": "res-1", "type": "VCS_REPOSITORY", "name": "talisman"}],
            "vulnerabilities": [
                {
                    "name": "CVE-2024-1234",
                    "severity": "CRITICAL",
                    "packageName": "express",
                    "description": "Prototype pollution flaw"
                }
            ],
            "sast_findings": [
                {
                    "title": "SQL Injection in User Controller",
                    "severity": "HIGH",
                    "location": {"path": "src/controllers/user.ts"},
                    "ruleName": "CWE-89"
                }
            ],
            "secrets": [
                {
                    "type": "AWS Access Key",
                    "filePath": "config/aws.env"
                }
            ],
            "penetration_tests": [
                {
                    "id": "PENTEST-101",
                    "name": "[CodeMender] SSRF in web hook",
                    "severity": "HIGH",
                    "statusV2": "OPEN"
                }
            ]
        }
        md = format_context_markdown(ctx)
        self.assertIn("CVE-2024-1234", md)
        self.assertIn("SQL Injection in User Controller", md)
        self.assertIn("AWS Access Key", md)
        self.assertIn("PENTEST-101", md)
        self.assertIn("ALREADY KNOWN", md)

    def test_harvest_wiz_context_status_filtering(self):
        client = MagicMock(spec=WizMcpClient)

        def mock_call(tool_name, params=None):
            if tool_name == "list_cloud_resources":
                return [{"id": "branch-1", "type": "REPOSITORY_BRANCH", "name": "main"}]
            elif tool_name == "list_vulnerability_findings":
                self.assertIn("status", params)
                self.assertEqual(params["status"], ["OPEN", "IN_PROGRESS"])
                return [
                    {"id": "vuln-open", "name": "CVE-2024-1111", "status": "OPEN"},
                    {"id": "vuln-resolved", "name": "CVE-2023-2222", "status": "RESOLVED"}
                ]
            elif tool_name == "list_sast_findings":
                self.assertIn("status", params)
                self.assertEqual(params["status"], ["OPEN", "IN_PROGRESS"])
                return [
                    {"id": "sast-open", "title": "XSS flaw", "status": "OPEN"},
                    {"id": "sast-resolved", "title": "Old flaw", "status": "RESOLVED"}
                ]
            elif tool_name == "list_secret_findings":
                self.assertIn("status", params)
                self.assertEqual(params["status"], ["OPEN", "IN_PROGRESS"])
                return [
                    {"id": "sec-open", "name": "Live API Key", "status": "OPEN"},
                    {"id": "sec-rejected", "name": "False positive", "status": "REJECTED"}
                ]
            elif tool_name == "list_penetration_test_findings":
                self.assertIn("status", params)
                self.assertEqual(params["status"], ["OPEN", "IN_PROGRESS"])
                return [
                    {
                        "id": "PENTEST-1",
                        "name": "[CodeMender] Open Pentest",
                        "status": "OPEN",
                        "resource": {"id": "branch-1"},
                        "tags": [{"key": "Repository", "value": "owner/repo"}]
                    },
                    {
                        "id": "PENTEST-2",
                        "name": "[CodeMender] Resolved Pentest",
                        "status": "RESOLVED",
                        "resource": {"id": "branch-1"},
                        "tags": [{"key": "Repository", "value": "owner/repo"}]
                    }
                ]
            return []

        client.call_tool.side_effect = mock_call
        ctx = harvest_wiz_context(client, repo="owner/repo")

        # Verify only unresolved / open findings were ingested
        vuln_ids = [v.get("id") for v in ctx["vulnerabilities"]]
        self.assertIn("vuln-open", vuln_ids)
        self.assertNotIn("vuln-resolved", vuln_ids)

        sast_ids = [s.get("id") for s in ctx["sast_findings"]]
        self.assertIn("sast-open", sast_ids)
        self.assertNotIn("sast-resolved", sast_ids)

        sec_ids = [s.get("id") for s in ctx["secrets"]]
        self.assertIn("sec-open", sec_ids)
        self.assertNotIn("sec-rejected", sec_ids)

        pt_ids = [p.get("id") for p in ctx["penetration_tests"]]
        self.assertIn("PENTEST-1", pt_ids)
        self.assertNotIn("PENTEST-2", pt_ids)

    @patch("fetch_wiz_context.load_wiz_credentials")
    @patch("fetch_wiz_context.WizMcpClient")
    def test_fetch_wiz_context_main_json_output(self, mock_client_cls, mock_load_creds):
        mock_load_creds.return_value = {"client_id": "cid", "client_secret": "sec", "datacenter": "us20", "mcp_url": "https://mcp.demo.wiz.io?mode=explicit"}
        mock_client = mock_client_cls.return_value
        mock_client.initialize.return_value = True
        mock_client.call_tool.return_value = []
        with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as f_md:
            md_path = f_md.name
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f_json:
            json_path = f_json.name

        try:
            with patch("sys.argv", ["fetch_wiz_context.py", "--repo", "owner/repo", "--output", md_path, "--json-output", json_path]):
                from fetch_wiz_context import main as fetch_main
                fetch_main()
            self.assertTrue(os.path.exists(md_path))
            self.assertTrue(os.path.exists(json_path))
            with open(json_path) as jf:
                data = json.load(jf)
                self.assertEqual(data.get("repo"), "owner/repo")
            # No --mcp-url flag: the client must fall back to the URL stored in the credentials.
            mock_client_cls.assert_called_once_with(None, mock_load_creds.return_value)
        finally:
            os.remove(md_path)
            os.remove(json_path)

    @patch("fetch_wiz_context.load_wiz_credentials")
    def test_fetch_wiz_context_warns_with_skip_reason(self, mock_load_creds):
        mock_load_creds.return_value = {"client_id": "", "client_secret": "", "datacenter": "", "mcp_url": "", "skip_reason": "secret 'wiz-mcp-config' has no datacenter."}
        with tempfile.TemporaryDirectory() as td:
            md_path = os.path.join(td, "ctx.md")
            with patch("sys.argv", ["fetch_wiz_context.py", "--repo", "owner/repo", "--output", md_path]):
                from fetch_wiz_context import main as fetch_main
                with self.assertLogs("fetch-wiz-context", level="WARNING") as logs:
                    fetch_main()
            self.assertTrue(any("has no datacenter" in line for line in logs.output))
            with open(md_path) as f:
                self.assertIn("Perform full discovery scan", f.read())

    def test_load_wiz_credentials_env(self):
        with patch.dict(os.environ, {
            "WIZ_CLIENT_ID": "mock-client",
            "WIZ_CLIENT_SECRET": "mock-secret",
            "WIZ_DATACENTER": "us20"
        }, clear=True):
            creds = load_wiz_credentials()
            self.assertEqual(creds["client_id"], "mock-client")
            self.assertEqual(creds["client_secret"], "mock-secret")
            self.assertEqual(creds["datacenter"], "us20")
            self.assertEqual(creds["skip_reason"], "")
            self.assertNotIn("env", creds)
            self.assertEqual(creds["mcp_url"], "https://mcp.app.wiz.io?mode=explicit")

    def test_load_wiz_credentials_env_requires_datacenter(self):
        with patch.dict(os.environ, {"WIZ_CLIENT_ID": "mock-client", "WIZ_CLIENT_SECRET": "mock-secret"}, clear=True):
            creds = load_wiz_credentials()
            self.assertIn("WIZ_DATACENTER is missing", creds["skip_reason"])
            client = WizMcpClient(creds=creds)
            self.assertFalse(client.initialize())
            self.assertIn("WIZ_DATACENTER is missing", client.last_error)

    def test_load_wiz_credentials_ignores_wiz_env(self):
        with patch.dict(os.environ, {
            "WIZ_CLIENT_ID": "mock-client",
            "WIZ_CLIENT_SECRET": "mock-secret",
            "WIZ_DATACENTER": "us20",
            "WIZ_ENV": "demo",
        }, clear=True):
            creds = load_wiz_credentials()
            self.assertEqual(creds["mcp_url"], "https://mcp.app.wiz.io?mode=explicit")

    @patch("common.fetch_gcp_secret")
    def test_load_wiz_credentials_secret_mcp_url(self, mock_fetch):
        mock_fetch.return_value = json.dumps({
            "client_id": "sec-cid",
            "client_secret": "sec-secret",
            "datacenter": "us36",
            "mcp_url": "https://mcp.demo.wiz.io?mode=explicit",
        })
        with patch.dict(os.environ, {}, clear=True):
            creds = load_wiz_credentials(project_id="test-proj")
            self.assertEqual(creds["client_id"], "sec-cid")
            self.assertEqual(creds["datacenter"], "us36")
            self.assertEqual(creds["mcp_url"], "https://mcp.demo.wiz.io?mode=explicit")
            client = WizMcpClient(creds=creds)
            self.assertEqual(client.mcp_url, "https://mcp.demo.wiz.io?mode=explicit")
            self.assertEqual(client._headers()["Wiz-DataCenter"], "us36")
            # An explicit URL (e.g. --mcp-url) always wins, even the production default.
            explicit = WizMcpClient("https://mcp.app.wiz.io?mode=explicit", creds)
            self.assertEqual(explicit.mcp_url, "https://mcp.app.wiz.io?mode=explicit")

    @patch("common.fetch_gcp_secret")
    def test_load_wiz_credentials_secret_without_mcp_url_uses_default(self, mock_fetch):
        mock_fetch.return_value = json.dumps({
            "Wiz-Client-Id": "sec-cid",
            "Wiz-Client-Secret": "sec-secret",
            "Wiz-DataCenter": "us36",
            "WIZ_ENV": "demo",
        })
        with patch.dict(os.environ, {}, clear=True):
            creds = load_wiz_credentials(project_id="test-proj")
            self.assertEqual(creds["skip_reason"], "")
            self.assertEqual(creds["mcp_url"], "https://mcp.app.wiz.io?mode=explicit")

    @patch("common.fetch_gcp_secret")
    def test_load_wiz_credentials_secret_requires_datacenter(self, mock_fetch):
        mock_fetch.return_value = json.dumps({"client_id": "sec-cid", "client_secret": "sec-secret"})
        with patch.dict(os.environ, {}, clear=True):
            creds = load_wiz_credentials(project_id="test-proj")
            self.assertEqual(creds["client_id"], "")
            self.assertIn("has no datacenter", creds["skip_reason"])
            self.assertIn("setup.sh", creds["skip_reason"])

    @patch("common.fetch_gcp_secret", side_effect=RuntimeError("permission denied"))
    def test_load_wiz_credentials_secret_unreadable(self, _mock_fetch):
        with patch.dict(os.environ, {}, clear=True):
            creds = load_wiz_credentials(project_id="test-proj")
            self.assertIn("could not read Secret Manager secret", creds["skip_reason"])
            self.assertIn("permission denied", creds["skip_reason"])

    def test_initialize_reports_auth_failure_reason(self):
        creds = {"client_id": "cid", "client_secret": "sec", "datacenter": "us20", "mcp_url": "https://mcp.demo.wiz.io?mode=explicit", "skip_reason": ""}
        client = WizMcpClient(creds=creds)
        resp = MagicMock(status_code=401, headers={})
        with patch.object(client.session, "post", return_value=resp):
            self.assertFalse(client.initialize())
        self.assertIn("HTTP 401", client.last_error)
        self.assertIn("mcp.demo.wiz.io", client.last_error)
        self.assertIn("us20", client.last_error)

    def test_clean_path(self):
        self.assertEqual(clean_path("/app/routes/api.ts"), "app/routes/api.ts")
        self.assertEqual(clean_path("./src/main.py"), "src/main.py")
        self.assertEqual(clean_path("`controllers/auth.go`"), "controllers/auth.go")

    @patch("ingest_wiz_pentest.find_semantic_match_with_gemini")
    def test_ingest_finding_duplicate_detection(self, mock_gemini_match):
        client = MagicMock(spec=WizMcpClient)
        client.call_tool.return_value = [
            {
                "id": "PENTEST-9999",
                "name": "[CodeMender] XSS in comment.js",
                "tags": [
                    {"key": "Repository", "value": "owner/repo"}
                ]
            }
        ]
        mock_gemini_match.return_value = "PENTEST-9999"
        finding = {
            "id": "abc12345-6789",
            "title": "XSS in comment.js",
            "file_path": "static/comment.js",
            "severity": "HIGH",
            "message": "Unescaped DOM write"
        }
        result = ingest_finding_to_wiz(
            client=client,
            finding=finding,
            repo="owner/repo",
            model="gemini-3.7-flash",
            cm_version="0.2.1"
        )
        self.assertEqual(result["id"], "PENTEST-9999")
        self.assertEqual(result["status"], "EXISTING")
        mock_gemini_match.assert_called_once()

    @patch("ingest_wiz_pentest.find_semantic_match_with_gemini")
    def test_ingest_finding_semantic_duplicate_detection(self, mock_gemini_match):
        client = MagicMock(spec=WizMcpClient)
        # Mock list_penetration_test_findings returning open finding for repo with different ID and title variation
        client.call_tool.return_value = [
            {
                "id": "PENTEST-SEMANTIC-1",
                "name": "[CodeMender] Unauthenticated Deletion Vulnerability in src/talisman/api/rituals.clj",
                "description": "Missing auth on delete",
                "severity": "MEDIUM",
                "status": "OPEN",
                "tags": [
                    {"key": "Repository", "value": "wiz-demo/talisman"},
                    {"key": "CodeMenderFindingID", "value": "completely-different-uuid"}
                ]
            }
        ]
        # Simulate Gemini recognizing semantic equivalence
        mock_gemini_match.return_value = "PENTEST-SEMANTIC-1"

        finding = {
            "id": "new-uuid-9999",
            "title": "Missing Authentication on Ritual Ledger Deletion",
            "file_path": "src/talisman/api/rituals.clj",
            "line": 45,
            "severity": "MEDIUM",
            "message": "DELETE endpoint does not verify session or role"
        }
        result = ingest_finding_to_wiz(
            client=client,
            finding=finding,
            repo="wiz-demo/talisman",
            model="gemini-2.5-flash",
            cm_version="0.8.0"
        )
        self.assertEqual(result["id"], "PENTEST-SEMANTIC-1")
        self.assertEqual(result["status"], "EXISTING")
        mock_gemini_match.assert_called_once()

    def test_ingest_finding_creation(self):
        client = MagicMock(spec=WizMcpClient)
        # First call: list_penetration_test_findings (empty)
        # Second call: list_cloud_resources
        # Third call: create_penetration_test_finding
        def mock_call(tool_name, params=None):
            if tool_name == "list_penetration_test_findings":
                return []
            elif tool_name == "list_cloud_resources":
                return [{"id": "repo-resource-123", "type": "VCS_REPOSITORY"}]
            elif tool_name == "create_penetration_test_finding":
                return [{"createPenetrationTestFinding": {"penetrationTestFinding": {"id": "PENTEST-8888"}}}]
            return []

        client.call_tool.side_effect = mock_call
        finding = {
            "id": "def56789-1111",
            "title": "Insecure Direct Object Reference",
            "file_path": "api/users.py",
            "line": 42,
            "severity": "CRITICAL",
            "message": "Missing tenant isolation check",
            "cwe": "CWE-639",
            "snippet": "user = db.query(User).get(request.args['id'])"
        }

        result = ingest_finding_to_wiz(
            client=client,
            finding=finding,
            repo="owner/repo",
            model="gemini-3.7-flash",
            cm_version="0.2.1",
            rec_fixes="Add tenant scope filter"
        )
        self.assertEqual(result["id"], "PENTEST-8888")
        self.assertEqual(result["status"], "CREATED")

    def test_normalize_wiz_finding_for_llm_all_domains(self):
        # 1. Penetration test with embedded path/line in description
        pt = {
            "id": "PT-123",
            "name": "[CodeMender] Command Injection in server.py",
            "description": "## Vulnerability Details\nUntrusted input.\n\n## Target Location\n- **Repository:** `owner/repo`\n- **File:** `server.py` (Line 50)\n",
            "severity": "CRITICAL",
            "weaknesses": ["CWE-78"],
        }
        norm_pt = normalize_wiz_finding_for_llm(pt)
        self.assertEqual(norm_pt["wiz_id"], "PT-123")
        self.assertEqual(norm_pt["domain"], "PENETRATION_TEST")
        self.assertEqual(norm_pt["file_path"], "server.py")
        self.assertEqual(norm_pt["line"], 50)
        self.assertEqual(norm_pt["vuln_type_or_cwe"], "CWE-78")
        self.assertIn("Untrusted input", norm_pt["description"])

        # 2. SAST finding
        sast = {
            "id": "SAST-456",
            "name": "SQL Injection in db.py",
            "location": {"path": "src/db.py", "line": 42},
            "severity": "HIGH",
            "ruleName": "CWE-89",
            "description": "Concatenation of raw user input into query string",
        }
        norm_sast = normalize_wiz_finding_for_llm(sast)
        self.assertEqual(norm_sast["wiz_id"], "SAST-456")
        self.assertEqual(norm_sast["domain"], "SAST")
        self.assertEqual(norm_sast["file_path"], "src/db.py")
        self.assertEqual(norm_sast["line"], 42)
        self.assertEqual(norm_sast["vuln_type_or_cwe"], "CWE-89")

        # 3. Vulnerability (CVE) finding
        vuln = {
            "id": "VULN-789",
            "name": "CVE-2023-30533",
            "packageName": "sheetjs",
            "locationPath": "package.json",
            "severity": "HIGH",
            "description": "Prototype pollution vulnerability",
        }
        norm_vuln = normalize_wiz_finding_for_llm(vuln)
        self.assertEqual(norm_vuln["wiz_id"], "VULN-789")
        self.assertEqual(norm_vuln["domain"], "VULNERABILITY")
        self.assertEqual(norm_vuln["file_path"], "package.json")
        self.assertEqual(norm_vuln["vuln_type_or_cwe"], "CVE-2023-30533")

        # 4. Secret finding
        sec = {
            "id": "SEC-001",
            "type": "AWS Secret Access Key",
            "filePath": "config/aws.json",
            "lineNumber": 12,
            "severity": "HIGH",
            "description": "Hardcoded AWS secret key detected",
        }
        norm_sec = normalize_wiz_finding_for_llm(sec)
        self.assertEqual(norm_sec["wiz_id"], "SEC-001")
        self.assertEqual(norm_sec["domain"], "SECRET")
        self.assertEqual(norm_sec["file_path"], "config/aws.json")
        self.assertEqual(norm_sec["line"], 12)

    @patch("ingest_wiz_pentest.find_semantic_match_with_gemini")
    def test_ingest_finding_cross_domain_sast_deduplication(self, mock_gemini_match):
        client = MagicMock(spec=WizMcpClient)
        # Mock finding context with existing SAST flaw
        mock_gemini_match.return_value = "SAST-123"
        finding = {
            "id": "cand-sast-99",
            "title": "SQL Injection in User Lookup",
            "file_path": "src/db.py",
            "line": 42,
            "severity": "HIGH",
            "cwe": "CWE-89",
            "message": "Raw SQL concatenation",
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f_ctx:
            json.dump({
                "sast_findings": [
                    {
                        "id": "SAST-123",
                        "name": "SQL Injection in db.py",
                        "location": {"path": "src/db.py", "line": 42},
                        "ruleName": "CWE-89",
                        "severity": "HIGH",
                    }
                ]
            }, f_ctx)
            ctx_path = f_ctx.name

        try:
            result = ingest_finding_to_wiz(
                client=client,
                finding=finding,
                repo="wiz-demo/talisman",
                wiz_context_path=ctx_path,
            )
            self.assertEqual(result["id"], "SAST-123")
            self.assertEqual(result["status"], "CORRELATED_EXISTING")
            self.assertEqual(result["domain"], "SAST")
            # Ensure create_penetration_test_finding was NOT called!
            for call_args in client.call_tool.call_args_list:
                self.assertNotEqual(call_args[0][0], "create_penetration_test_finding")
        finally:
            os.remove(ctx_path)

    @patch("ingest_wiz_pentest.find_semantic_match_with_gemini")
    def test_ingest_finding_cross_domain_secret_deduplication(self, mock_gemini_match):
        client = MagicMock(spec=WizMcpClient)
        mock_gemini_match.return_value = "SEC-456"
        finding = {
            "id": "cand-sec-1",
            "title": "Exposed GitHub Token",
            "file_path": "scripts/deploy.sh",
            "line": 10,
            "severity": "HIGH",
            "message": "Hardcoded token in script",
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f_ctx:
            json.dump({
                "secrets": [
                    {
                        "id": "SEC-456",
                        "type": "GitHub Personal Access Token",
                        "filePath": "scripts/deploy.sh",
                        "lineNumber": 10,
                        "severity": "HIGH",
                    }
                ]
            }, f_ctx)
            ctx_path = f_ctx.name

        try:
            result = ingest_finding_to_wiz(
                client=client,
                finding=finding,
                repo="wiz-demo/talisman",
                wiz_context_path=ctx_path,
            )
            self.assertEqual(result["id"], "SEC-456")
            self.assertEqual(result["status"], "CORRELATED_EXISTING")
            self.assertEqual(result["domain"], "SECRET")
            # Ensure create_penetration_test_finding was NOT called!
            for call_args in client.call_tool.call_args_list:
                self.assertNotEqual(call_args[0][0], "create_penetration_test_finding")
        finally:
            os.remove(ctx_path)

    def test_build_pr_body_with_wiz_metadata(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            findings_file = os.path.join(tmpdir, "imported_findings.json")
            with open(findings_file, "w") as f:
                json.dump([{
                    "id": "f1a2b3c4",
                    "file_path": "routes/auth.py",
                    "line": 15,
                    "title": "SQL Injection",
                    "severity": "CRITICAL",
                    "vuln_type": "CWE-89",
                    "message": "Raw SQL query concatenation"
                }], f)

            body = build_pr_body(
                artifacts_dir=tmpdir,
                finding_id="f1a2b3c4",
                repo="owner/repo",
                ref="main",
                base_ref="main",
                issue_num="123",
                wiz_id="PENTEST-4567"
            )

            self.assertIn('<!-- wiz-pentest-metadata: {"id": "PENTEST-4567", "repo": "owner/repo", "cm_id": "f1a2b3c4"} -->', body)
            self.assertIn("### 🛡️ Wiz Penetration Testing Ledger", body)
            self.assertIn("`PENTEST-4567`", body)
            self.assertIn("Closes #123", body)

    def test_is_finding_verified(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            findings_file = os.path.join(tmpdir, "findings.json")
            with open(findings_file, "w") as f:
                json.dump([{
                    "id": "abc12345",
                    "file_path": "app.py",
                    "status": "VERIFIED"
                }], f)

            self.assertTrue(is_finding_verified(tmpdir, "abc12345"))
            self.assertTrue(is_finding_verified(tmpdir, "abc12345-6789"))

            # False when status is not VERIFIED
            with open(findings_file, "w") as f:
                json.dump([{
                    "id": "abc12345",
                    "file_path": "app.py",
                    "status": "SUSPECTED"
                }], f)
            self.assertFalse(is_finding_verified(tmpdir, "abc12345"))

    def test_normalize_candidate_preserves_recommended_fixes(self):
        candidate_json = json.dumps([{
            "id": "c1a2b3c4",
            "file_path": "server.py",
            "line": 42,
            "title": "Command Injection",
            "severity": "CRITICAL",
            "recommended_fixes": "Use shlex.quote() or subprocess with list arguments."
        }])
        res = normalize_candidate_findings(candidate_json)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["recommended_fixes"], "Use shlex.quote() or subprocess with list arguments.")

    def test_ingest_finding_uses_embedded_rec_fixes(self):
        client = MagicMock(spec=WizMcpClient)
        created_payloads = []
        def mock_call(tool_name, params=None):
            if tool_name == "list_penetration_test_findings":
                return []
            elif tool_name == "list_cloud_resources":
                return [{"id": "repo-1", "type": "VCS_REPOSITORY"}]
            elif tool_name == "create_penetration_test_finding":
                created_payloads.append(params)
                return [{"createPenetrationTestFinding": {"penetrationTestFinding": {"id": "PENTEST-7777"}}}]
            return []

        client.call_tool.side_effect = mock_call
        finding = {
            "id": "test1234",
            "title": "SQL Injection",
            "file_path": "db.py",
            "line": 10,
            "severity": "HIGH",
            "recommended_fixes": "Use parameterized queries."
        }
        res = ingest_finding_to_wiz(client, finding, repo="test/repo")
        self.assertEqual(res["id"], "PENTEST-7777")
        self.assertEqual(len(created_payloads), 1)
        self.assertIn("Use parameterized queries.", created_payloads[0]["remediation_instructions"])

    def test_generate_scan_matrix_without_wiz_context(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump([
                {"id": "cand-1", "title": "SQL Injection", "file_path": "db.py", "severity": "HIGH"},
                {"id": "cand-2", "title": "XSS", "file_path": "web.py", "severity": "MEDIUM"}
            ], f)
            findings_path = f.name
        try:
            matrix = generate_scan_matrix(findings_path)
            self.assertEqual(len(matrix), 2)
            self.assertEqual(matrix[0]["short_id"], "cand-1")
            self.assertEqual(matrix[1]["short_id"], "cand-2")
        finally:
            os.remove(findings_path)

    @patch("ingest_wiz_pentest.find_semantic_match_with_gemini")
    def test_generate_scan_matrix_pre_verification_deduplication(self, mock_gemini):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f_find:
            json.dump([
                {"id": "cand-exact-1234", "title": "Exact Matched Flaw", "file_path": "auth.py", "severity": "CRITICAL"},
                {"id": "cand-semantic-5678", "title": "Missing Auth on Rituals", "file_path": "src/rituals.clj", "severity": "HIGH"},
                {"id": "cand-unique-9999", "title": "Unique BOLA in Potions", "file_path": "src/potions.clj", "severity": "HIGH"}
            ], f_find)
            findings_path = f_find.name

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f_wiz:
            json.dump({
                "penetration_tests": [
                    {
                        "id": "PENTEST-EXACT",
                        "name": "[CodeMender] Exact Matched Flaw in auth.py",
                        "tags": [{"key": "CodeMenderFindingID", "value": "cand-exa"}]
                    },
                    {
                        "id": "PENTEST-SEMANTIC",
                        "name": "[CodeMender] Unauthenticated Ritual Deletion",
                        "tags": []
                    }
                ]
            }, f_wiz)
            wiz_path = f_wiz.name

        def mock_sem(candidate, existing_findings, project_id=None):
            if "auth.py" in candidate.get("file_path", ""):
                return "PENTEST-EXACT"
            if "rituals" in candidate.get("file_path", ""):
                return "PENTEST-SEMANTIC"
            return None

        mock_gemini.side_effect = mock_sem

        try:
            matrix = generate_scan_matrix(findings_path, wiz_context_path=wiz_path)
            # Only cand-unique-9999 should remain in the matrix!
            self.assertEqual(len(matrix), 1)
            self.assertEqual(matrix[0]["short_id"], "cand-uni")
            self.assertEqual(matrix[0]["file_path"], "src/potions.clj")
        finally:
            os.remove(findings_path)
            os.remove(wiz_path)

    @patch("ingest_wiz_pentest.find_semantic_match_with_gemini")
    def test_generate_scan_matrix_cross_domain_deduplication(self, mock_gemini):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f_find:
            json.dump([
                {"id": "cand-sast-1", "title": "SQL Injection", "file_path": "db.py", "severity": "HIGH"},
                {"id": "cand-cve-2", "title": "Lodash Prototype Pollution", "file_path": "package.json", "severity": "CRITICAL"},
                {"id": "cand-sec-3", "title": "Slack Webhook Exposed", "file_path": "config.json", "severity": "HIGH"},
                {"id": "cand-new-4", "title": "Unique Logic Flaw", "file_path": "payment.py", "severity": "HIGH"},
            ], f_find)
            findings_path = f_find.name

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f_wiz:
            json.dump({
                "sast_findings": [
                    {"id": "SAST-99", "name": "SQL Injection in db.py", "filePath": "db.py"}
                ],
                "vulnerabilities": [
                    {"id": "CVE-2021-23337", "name": "CVE-2021-23337", "packageName": "lodash"}
                ],
                "secrets": [
                    {"id": "SEC-88", "type": "Slack Webhook URL", "filePath": "config.json"}
                ],
                "penetration_tests": []
            }, f_wiz)
            wiz_path = f_wiz.name

        def mock_sem(candidate, existing_findings, project_id=None):
            fpath = candidate.get("file_path", "")
            if "db.py" in fpath:
                return "SAST-99"
            if "package.json" in fpath:
                return "CVE-2021-23337"
            if "config.json" in fpath:
                return "SEC-88"
            return None

        mock_gemini.side_effect = mock_sem

        try:
            matrix = generate_scan_matrix(findings_path, wiz_context_path=wiz_path)
            # Only cand-new-4 should remain!
            self.assertEqual(len(matrix), 1)
            self.assertEqual(matrix[0]["short_id"], "cand-new")
            self.assertEqual(matrix[0]["file_path"], "payment.py")
        finally:
            os.remove(findings_path)
            os.remove(wiz_path)


if __name__ == "__main__":
    unittest.main()
