#!/usr/bin/env python3
"""
Comprehensive unit tests for CodeMender Slim Worker modules:
- common.py (path/severity helpers, loose JSON loader, node extraction)
- parser.py (JSON extraction, downstream agent output, regex fallback, candidate normalization)
- planner.py (ID correlation across JSON & SQLite, verification check, task & matrix planning)
- pr_builder.py (single & batch PR title/body generation)
"""

import base64
import json
import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "worker")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from parse_issue import (
    build_pr_body,
    build_pr_title,
    clean_file_path,
    extract_json_candidates,
    render_batch_pr_body,
    generate_remediation_matrix,
    generate_remediation_tasks,
    generate_scan_matrix,
    get_severity_label_info,
    is_finding_verified,
    normalize_candidate_findings,
    parse_downstream_agent_output,
    parse_fallback_patterns,
    resolve_imported_finding_id,
)
from common import load_json_loose, write_json_file


class TestSlimParser(unittest.TestCase):

    def _seed_dir(self, td: str, imported=None, cm=None, fixes=None) -> None:
        if imported is not None:
            write_json_file(os.path.join(td, "imported_findings.json"), imported)
        if cm is not None:
            write_json_file(os.path.join(td, "findings.json"), cm)
        if fixes is not None:
            write_json_file(os.path.join(td, "recommended_fixes.json"), fixes)

    def test_user_action_result_structured_output(self):
        text = json.dumps({
            "actionResult": {
                "text": None,
                "structuredOutput": {
                    "file_path": "/sorcery-solutions-frontend/src/package.json",
                    "line": 1,
                    "message": "Pinned to next@15.2.2 exposing CVE-2025-55182.",
                    "recommended_fixes": "Step 1: WAF rules\nStep 2: Upgrade next to 15.5.21\nStep 3: Exclude .next/",
                    "severity": "CRITICAL",
                    "title": "Upgrade Next.js and Pin Transitive Dependencies",
                    "vuln_type": "CVE-2025-55182, CVE-2025-29927",
                },
                "conversationId": "2de3e7c2-34d8-42a2-8cbd-8ed358bffb8b",
            }
        })
        candidates = extract_json_candidates(text)
        findings, fixes = parse_downstream_agent_output(candidates, repo="wiz-demo/ceres-mining-operations-ga")
        self.assertEqual(len(findings), 1)
        self.assertEqual(len(fixes), 1)

        f = findings[0]
        self.assertIn("Step 2:", f["recommended_fixes"])
        self.assertNotIn("conversationId", f)
        self.assertEqual(f["file_path"], "sorcery-solutions-frontend/src/package.json")
        self.assertEqual(f["severity"], "CRITICAL")
        self.assertEqual(len(f["id"]), 8)
        self.assertEqual(fixes[0]["finding_id"], f["id"])
        self.assertIn("Step 2:", fixes[0]["recommended_fixes"])

    def test_fenced_markdown_with_snake_case(self):
        text = """
```json
{
  "actionResult": {
    "structured_output": {
      "file_path": "backend/auth/jwt.py",
      "line": 45,
      "title": "JWT None Algorithm Bypass",
      "severity": "HIGH",
      "vuln_type": "CWE-347",
      "message": "Token verification accepts alg=none.",
      "recommended_fixes": "Reject alg=none in jwt.decode()"
    }
  }
}
```
"""
        findings, fixes = parse_downstream_agent_output(extract_json_candidates(text), repo="owner/repo")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["file_path"], "backend/auth/jwt.py")
        self.assertEqual(fixes[0]["recommended_fixes"], "Reject alg=none in jwt.decode()")

    def test_multiple_findings_array(self):
        text = json.dumps({
            "actionResult": {
                "structuredOutput": [
                    {"file_path": "/src/a.ts", "line": 10, "title": "Finding A", "severity": "CRITICAL", "recommended_fixes": "Fix A"},
                    {"file_path": "/src/b.ts", "line": 20, "title": "Finding B", "severity": "MEDIUM", "recommended_fixes": "Fix B"},
                ]
            }
        })
        findings, fixes = parse_downstream_agent_output(extract_json_candidates(text), repo="test/repo")
        self.assertEqual(len(findings), 2)
        self.assertEqual([f["file_path"] for f in findings], ["src/a.ts", "src/b.ts"])
        self.assertEqual([fx["recommended_fixes"] for fx in fixes], ["Fix A", "Fix B"])

    def test_direct_root_object(self):
        text = json.dumps({
            "file_path": "/api/users.py",
            "line": 15,
            "title": "SQL Injection",
            "severity": "HIGH",
            "vuln_type": "CWE-89",
            "recommended_fixes": "Use parameterized queries",
        })
        findings, fixes = parse_downstream_agent_output(extract_json_candidates(text), repo="test/repo")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["file_path"], "api/users.py")
        self.assertEqual(fixes[0]["recommended_fixes"], "Use parameterized queries")

    def test_resolve_imported_finding_id_strategies(self):
        with tempfile.TemporaryDirectory() as td:
            self._seed_dir(
                td,
                imported=[{"file_path": "src/auth.clj", "line": 42, "title": "Hardcoded JWT Secret"}],
                cm=[
                    {"FindingID": "old-id", "FilePath": "/workspace/repo/other.py", "Title": "Other", "SessionID": "s1"},
                    {"FindingID": "cm-uuid-9999", "FilePath": "/workspace/repo/src/auth.clj", "Title": "Hardcoded JWT Secret", "SessionID": "import_1"},
                ],
            )
            self.assertEqual(resolve_imported_finding_id(td), "cm-uuid-9999")

    def test_resolve_and_verify_via_sqlite(self):
        with tempfile.TemporaryDirectory() as td:
            db_file = os.path.join(td, "state.db")
            conn = sqlite3.connect(db_file)
            conn.execute("CREATE TABLE findings (finding_id TEXT, session_id TEXT, status TEXT)")
            conn.execute("INSERT INTO findings VALUES ('sqlite-uuid-1234', 'import_99', 'VERIFIED')")
            conn.commit()
            conn.close()

            self.assertEqual(resolve_imported_finding_id(td), "sqlite-uuid-1234")
            self.assertTrue(is_finding_verified(td, "sqlite-uuid-1234"))
            self.assertFalse(is_finding_verified(td, "non-existent-id"))

    def test_normalize_candidate_and_scan_matrix(self):
        raw = '{"FindingID": "cand-12345678", "FilePath": "/workspace/repo/app.py", "StartLine": 12, "Title": "RCE"}'
        norm = normalize_candidate_findings(raw)
        self.assertEqual(len(norm), 1)
        self.assertEqual(norm[0]["file_path"], "app.py")
        self.assertEqual(norm[0]["line"], 12)

        with tempfile.TemporaryDirectory() as td:
            fp = os.path.join(td, "findings.json")
            write_json_file(fp, norm)
            s_matrix = generate_scan_matrix(fp)
            self.assertEqual(len(s_matrix), 1)
            self.assertEqual(s_matrix[0]["short_id"], "cand-123")
            self.assertEqual(s_matrix[0]["candidate_id"], "cand-12345678")
            self.assertEqual(s_matrix[0]["file_path"], "app.py")

    def test_build_pr_title_and_body(self):
        with tempfile.TemporaryDirectory() as td:
            self._seed_dir(
                td,
                imported=[{"id": "292105d6", "file_path": "src/package.json", "line": 1, "title": "Upgrade Next.js", "severity": "CRITICAL", "vuln_type": "CVE-2025-55182", "message": "Critical RCE."}],
                fixes=[{"finding_id": "292105d6", "file_path": "src/package.json", "recommended_fixes": "Step 1: Upgrade next to 15.5.21"}],
            )
            self.assertEqual(build_pr_title(td, finding_id="292105d6-xxxx"), "fix(security): Upgrade Next.js (292105d6)")
            body = build_pr_body(td, finding_id="292105d6-xxxx", repo="wiz-demo/ceres", ref="main", base_ref="main", issue_num="77")
            self.assertIn("> **Closes #77**", body)
            self.assertIn("🔴 CRITICAL", body)
            self.assertIn("Step 1: Upgrade next to 15.5.21", body)

    def test_fallback_unformatted_plain_text(self):
        text = 'File: src/package.json, line 14.\nFixed code:\n  "next": "15.5.21"\nExplanation: CVE-2025-29927 in Next.js.'
        findings, fixes = parse_fallback_patterns(text, repo="test/repo")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["file_path"], "src/package.json")
        self.assertEqual(findings[0]["line"], 14)
        self.assertIn('"next": "15.5.21"', fixes[0]["recommended_fixes"])

    def test_get_severity_label_info(self):
        self.assertEqual(get_severity_label_info("CRITICAL"), ("codemender-fix:critical", "b60205"))
        self.assertEqual(get_severity_label_info("HIGH"), ("codemender-fix:high", "d93f0b"))
        self.assertEqual(get_severity_label_info("MEDIUM"), ("codemender-fix:medium", "fbca04"))
        self.assertEqual(get_severity_label_info("LOW"), ("codemender-fix:low", "0e8a16"))

    def test_generate_remediation_tasks_and_single_runner(self):
        with tempfile.TemporaryDirectory() as td:
            self._seed_dir(
                td,
                imported=[{"id": "hash1234", "file_path": "src/spell.clj", "line": 23, "title": "SQL Injection", "severity": "CRITICAL", "wiz_id": "PENTEST-42"}],
                cm=[{"finding_id": "cm-new-uuid-9999", "file_path": "/workspace/repo/src/spell.clj", "start_line": 23, "title": "SQL Injection"}],
                fixes=[{"file_path": "src/spell.clj", "line": 23, "recommended_fixes": "Use honey sql"}],
            )
            tasks = generate_remediation_tasks(td, vuln_id_filter="hash1234")
            self.assertEqual(len(tasks), 1)
            self.assertEqual(tasks[0]["finding_id"], "cm-new-uuid-9999")
            self.assertEqual(tasks[0]["recommended_fixes"], "Use honey sql")
            self.assertEqual(tasks[0]["wiz_id"], "PENTEST-42")

    def test_generate_remediation_matrix_owner_aggregation_and_filter(self):
        raw_issue = json.dumps([
            {"file_path": "a.py", "line": 10, "title": "Finding 1", "severity": "CRITICAL", "owner": "alice", "recommended_fixes": "Fix 1"},
            {"file_path": "a.py", "line": 20, "title": "Finding 2", "severity": "HIGH", "owner": "alice", "recommended_fixes": "Fix 2"},
            {"file_path": "b.py", "line": 30, "title": "Finding 3", "severity": "HIGH", "owner": "alice", "recommended_fixes": "Fix 3"},
            {"file_path": "c.py", "line": 40, "title": "Finding 4", "severity": "MEDIUM"},
        ])
        matrix = generate_remediation_matrix(body_text=raw_issue, repo="wiz-demo/talisman", verify_first="false")
        self.assertEqual(len(matrix), 3)
        self.assertEqual(matrix[0]["verify_first"], "false")

        alice_a = next(m for m in matrix if m["owner"] == "alice" and m["file_path"] == "a.py")
        self.assertEqual(alice_a["findings_count"], 2)
        self.assertEqual(len(json.loads(base64.b64decode(alice_a["finding_json_b64"]).decode("utf-8"))), 2)

        filtered = generate_remediation_matrix(body_text=raw_issue, repo="wiz-demo/talisman", vuln_id_filter=matrix[2]["finding_id"][:8])
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["file_path"], "c.py")

    def test_extract_json_with_literal_newlines_and_escaped_quotes(self):
        raw_newline = '{"file_path":"src/core.clj","line":10,"title":"Hardcoded   \n  Secret","severity":"CRITICAL"}'
        self.assertEqual(extract_json_candidates(raw_newline)[0]["file_path"], "src/core.clj")
        raw_escaped = '{\\"file_path\\":\\"src/core.clj\\",\\"line\\":10,\\"title\\":\\"Secret\\"}'
        self.assertEqual(extract_json_candidates(raw_escaped)[0]["file_path"], "src/core.clj")
        self.assertEqual(clean_file_path("`src/foo.py`"), "src/foo.py")
        self.assertIsNotNone(load_json_loose(raw_newline))

    def test_render_batch_pr_body_table_and_unassigned(self):
        items = [
            {
                "finding_id": "85dbae56",
                "severity": "CRITICAL",
                "file_path": "src/talisman/auth.clj",
                "line": 61,
                "title": "Authentication Security Hardening in auth.clj",
                "message": "Unsalted SHA-256 password hashing enables rainbow table attacks.",
                "recommended_fixes": "Replace unsalted SHA-256 with bcrypt.",
                "owner": "sdoyle88",
            },
            {
                "finding_id": "8fd9b309",
                "severity": "HIGH",
                "file_path": "src/talisman/api/artifacts.clj",
                "line": 47,
                "title": "Path Traversal in artifacts.clj",
                "message": "Path traversal via name parameter.",
                "recommended_fixes": "Canonicalize the resolved file path.",
                "owner": "sdoyle88",
            },
        ]
        body = render_batch_pr_body(items, repo="owner/repo", ref="main", issue_num="26", owner="sdoyle88")
        self.assertIn("<!-- codemender-batch-metadata: {\"count\": 2, \"owner\": \"sdoyle88\"} -->", body)
        self.assertIn("## 🛡️ CodeMender Automated Security Remediation (Aggregated Draft)", body)
        self.assertIn("> **Closes #26**", body)
        self.assertIn("**Assigned Reviewer:** @sdoyle88", body)
        self.assertIn("| # | Severity | Finding ID | Target Location | Vulnerability Title |", body)
        self.assertIn("| 1 | **CRITICAL** | `85dbae56` | [`src/talisman/auth.clj:61`](https://github.com/owner/repo/blob/main/src/talisman/auth.clj#L61) | Authentication Security Hardening in auth.clj |", body)
        self.assertIn("| 2 | **HIGH** | `8fd9b309` | [`src/talisman/api/artifacts.clj:47`](https://github.com/owner/repo/blob/main/src/talisman/api/artifacts.clj#L47) | Path Traversal in artifacts.clj |", body)
        self.assertIn("### 🔍 Remediation Details", body)
        self.assertIn("#### 1. `85dbae56`: Authentication Security Hardening in auth.clj", body)
        self.assertIn("- **Summary:** Unsalted SHA-256 password hashing enables rainbow table attacks.", body)
        self.assertIn("Replace unsalted SHA-256 with bcrypt.", body)

        # Unassigned case: should NOT include @unassigned reviewer
        unassigned_body = render_batch_pr_body(items, repo="owner/repo", ref="main", issue_num="26", owner="unassigned")
        self.assertNotIn("@unassigned", unassigned_body)
        self.assertNotIn("Assigned Reviewer", unassigned_body)
        self.assertIn("<!-- codemender-batch-metadata: {\"count\": 2, \"owner\": \"unassigned\"} -->", unassigned_body)

    def test_build_pr_title_batch(self):
        with tempfile.TemporaryDirectory() as td:
            tasks_file = os.path.join(td, "remediation_tasks.json")
            with open(tasks_file, "w") as f:
                json.dump([
                    {"title": "Vuln 1", "owner": "alice"},
                    {"title": "Vuln 2", "owner": "alice"},
                ], f)

            self.assertEqual(build_pr_title(td, owner="alice"), "fix(security): resolve 2 CodeMender findings for @alice")
            self.assertEqual(build_pr_title(td, owner="unassigned"), "fix(security): resolve 2 CodeMender findings")


if __name__ == "__main__":
    unittest.main()
