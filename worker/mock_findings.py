#!/usr/bin/env python3
"""
Temporary Modular Mock for CodeMender findings & verification.
Allows fast end-to-end testing of:
- Discovery scan & matrix publishing
- Gemini semantic deduplication against existing Wiz penetration test findings
- New Wiz penetration test finding creation via Wiz MCP
WITHOUT running slow full-codebase LLM scans or exploit compilation.

NOTE: This is a temporary testing utility that will be removed later.
"""

import argparse
import json
import os
import sys
from typing import Any, Dict, List


def generate_mock_findings(repo: str) -> List[Dict[str, Any]]:
    """
    Generates two mock findings for testing:
    1. Candidate A: Duplicate test (similar to known open finding in talisman rituals.clj).
    2. Candidate B: New finding test (hardcoded encryption secret).
    """
    return [
        {
            "id": "mock-dup-0001-aaaa-bbbb-ccccdddd1111",
            "title": "Missing Authentication on Ritual Ledger Deletion",
            "file_path": "src/talisman/api/rituals.clj",
            "line": 42,
            "start_line": 40,
            "end_line": 45,
            "severity": "MEDIUM",
            "vuln_type": "CWE-306",
            "message": "The DELETE /api/rituals/:id route does not enforce authorization or authentication checks.",
            "snippet": '(DELETE "/api/rituals/:id" [id] (delete-ritual-handler id))',
            "recommended_fixes": "Wrap the endpoint with (require-auth (delete-ritual-handler id)) to ensure authentication.",
            "status": "UNVERIFIED",
        },
        {
            "id": "mock-new-0002-eeee-ffff-111122223333",
            "title": "Hardcoded Cryptographic Salt in Key Derivation",
            "file_path": "src/talisman/crypto.clj",
            "line": 18,
            "start_line": 15,
            "end_line": 20,
            "severity": "HIGH",
            "vuln_type": "CWE-798",
            "message": "A static, hardcoded salt string is used in PBKDF2 password hashing.",
            "snippet": '(def ^:private static-salt (byte-array [(byte 0x01) (byte 0x02) (byte 0x03)]))',
            "recommended_fixes": "Generate cryptographically secure random salts per entry and store alongside hashes.",
            "status": "UNVERIFIED",
        },
    ]


def simulate_mock_verify(artifacts_dir: str, finding_id: str) -> None:
    """Simulates cm verify marking the target finding as VERIFIED in findings.json and imported_findings.json."""
    os.makedirs(artifacts_dir, exist_ok=True)
    for fname in ("findings.json", "imported_findings.json"):
        fpath = os.path.join(artifacts_dir, fname)
        if os.path.exists(fpath):
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                items = data if isinstance(data, list) else data.get("findings", [data])
                for it in items:
                    it_id = str(it.get("id") or it.get("finding_id") or "")
                    if not finding_id or it_id.startswith(finding_id[:8]) or finding_id.startswith(it_id[:8]):
                        it["status"] = "VERIFIED"
                        it["confidence"] = 100
                with open(fpath, "w", encoding="utf-8") as f:
                    json.dump(items, f, indent=2)
            except Exception as e:
                print(f"[mock] Notice updating {fname}: {e}", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(description="Temporary Mock Findings for End-to-End Testing")
    parser.add_argument("--repo", default="wiz-demo/talisman")
    parser.add_argument("--output", default="")
    parser.add_argument("--mock-verify", action="store_true", help="Simulate cm verify success")
    parser.add_argument("--artifacts-dir", default="")
    parser.add_argument("--finding-id", default="")
    args = parser.parse_args()

    if args.mock_verify:
        simulate_mock_verify(args.artifacts_dir, args.finding_id)
        print("Mock verification completed successfully.")
        return

    findings = generate_mock_findings(args.repo)
    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2)
        print(f"Wrote {len(findings)} mock finding(s) to {args.output}")
    else:
        print(json.dumps(findings, indent=2))


if __name__ == "__main__":
    main()
