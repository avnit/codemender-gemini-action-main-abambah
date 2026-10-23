#!/usr/bin/env python3
"""
Unified CLI Dispatcher & Facade for CodeMender Slim Worker.
Re-exports all parsing, planning, correlation, and PR builder symbols
and provides clean CLI subcommands for entrypoint.sh and GitHub Actions workflows.
"""

import argparse
import json
import os
import sys
from typing import Optional

from common import (
    SEVERITY_ICONS,
    clean_file_path,
    format_severity,
    get_severity_label_info,
    write_json_file,
)
from parser import (
    extract_json_candidates,
    normalize_candidate_findings,
    parse_downstream_agent_output,
    parse_fallback_patterns,
)
from planner import (
    find_matching_finding_and_fix,
    generate_remediation_matrix,
    generate_remediation_tasks,
    generate_scan_matrix,
    is_finding_verified,
    resolve_imported_finding_id,
)
from pr_builder import (
    aggregate_owner_prs,
    build_pr_body,
    build_pr_title,
    render_batch_pr_body,
)

__all__ = [
    "SEVERITY_ICONS",
    "clean_file_path",
    "format_severity",
    "get_severity_label_info",
    "extract_json_candidates",
    "normalize_candidate_findings",
    "parse_downstream_agent_output",
    "parse_fallback_patterns",
    "find_matching_finding_and_fix",
    "generate_remediation_matrix",
    "generate_remediation_tasks",
    "generate_scan_matrix",
    "is_finding_verified",
    "resolve_imported_finding_id",
    "aggregate_owner_prs",
    "build_pr_body",
    "build_pr_title",
    "render_batch_pr_body",
]


def _read_text(raw: str, file_path: str) -> str:
    if raw:
        return raw
    if file_path and os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    return ""


def main() -> None:
    p = argparse.ArgumentParser(description="CodeMender Slim Worker CLI Dispatcher")
    p.add_argument("--body-file", default="")
    p.add_argument("--comment-file", default="")
    p.add_argument("--issue-body", default="")
    p.add_argument("--comment-body", default="")
    p.add_argument("--repo", default=os.environ.get("REPO", "unknown"))
    p.add_argument("--workspace", default=os.environ.get("PROJECT_DIR", "."))
    p.add_argument("--output", default="/workspace/artifacts/imported_findings.json")
    p.add_argument("--fixes-output", default="/workspace/artifacts/recommended_fixes.json")
    p.add_argument("--context-output", default="/workspace/artifacts/recommended_fixes.txt")
    p.add_argument("--artifacts-dir", default="/workspace/artifacts")
    p.add_argument("--finding-id", default="")
    p.add_argument("--vuln-id", default="")
    p.add_argument("--ref", default="main")
    p.add_argument("--base-ref", default="main")
    p.add_argument("--issue-num", default="")
    p.add_argument("--wiz-id", default="")
    p.add_argument("--wiz-url", default="")
    p.add_argument("--owner", default="")
    p.add_argument("--verify-first", default="false")

    p.add_argument("--project", default=os.environ.get("GCP_PROJECT") or os.environ.get("PROJECT_ID", ""))
    p.add_argument("--wiz-context", default="", help="Path to Wiz context JSON file for deduplication")

    # Sub-actions
    p.add_argument("--resolve-imported-id", action="store_true")
    p.add_argument("--is-verified", action="store_true")
    p.add_argument("--normalize-candidate", default="", help="Path to candidate JSON file to normalize")
    p.add_argument("--generate-tasks", action="store_true")
    p.add_argument("--tasks-output", default="")
    p.add_argument("--generate-matrix", action="store_true")
    p.add_argument("--matrix-output", default="")
    p.add_argument("--scan-matrix", default="", help="Path to scan findings.json")
    p.add_argument("--build-pr-title", action="store_true")
    p.add_argument("--build-pr-body", action="store_true")
    p.add_argument("--aggregate-prs", action="store_true")

    args = p.parse_args()

    if args.normalize_candidate:
        raw_text = _read_text("", args.normalize_candidate)
        normalized = normalize_candidate_findings(raw_text, default_vuln_id=args.vuln_id)
        write_json_file(args.output, normalized)
        return

    if args.is_verified:
        verified = is_finding_verified(args.artifacts_dir, args.finding_id, args.vuln_id)
        print("true" if verified else "false")
        return

    if args.resolve_imported_id:
        print(resolve_imported_finding_id(args.artifacts_dir))
        return

    if args.scan_matrix:
        matrix = generate_scan_matrix(
            args.scan_matrix,
            wiz_context_path=args.wiz_context,
            project_id=args.project,
        )
        print(json.dumps(matrix, separators=(",", ":")))
        return

    if args.aggregate_prs:
        matrix_raw = os.environ.get("MATRIX_JSON", "[]")
        aggregate_owner_prs(
            matrix=json.loads(matrix_raw),
            repo=args.repo,
            base_ref=args.base_ref,
            target_ref=args.ref,
            issue_num=args.issue_num,
        )
        return

    if args.generate_matrix:
        matrix = generate_remediation_matrix(
            artifacts_dir=args.artifacts_dir if os.path.exists(args.artifacts_dir) else "",
            body_text=_read_text(args.issue_body, args.body_file),
            comment_text=_read_text(args.comment_body, args.comment_file),
            repo=args.repo,
            vuln_id_filter=args.vuln_id,
            workspace_dir=args.workspace,
            verify_first=args.verify_first,
        )
        matrix_json = json.dumps(matrix, separators=(",", ":"))
        if args.matrix_output:
            os.makedirs(os.path.dirname(os.path.abspath(args.matrix_output)), exist_ok=True)
            with open(args.matrix_output, "w", encoding="utf-8") as f:
                f.write(matrix_json)
            print(f"✅ Generated {len(matrix)} matrix task(s) at {args.matrix_output}")
        else:
            print(matrix_json)
        return

    if args.generate_tasks:
        tasks = generate_remediation_tasks(args.artifacts_dir, vuln_id_filter=args.vuln_id)
        out_path = args.tasks_output or os.path.join(args.artifacts_dir, "remediation_tasks.json")
        write_json_file(out_path, tasks)
        print(f"✅ Generated {len(tasks)} remediation task(s) at {out_path}")
        return

    if args.build_pr_title:
        print(build_pr_title(args.artifacts_dir, finding_id=args.finding_id, owner=args.owner))
        return

    if args.build_pr_body:
        body = build_pr_body(
            artifacts_dir=args.artifacts_dir,
            finding_id=args.finding_id,
            repo=args.repo,
            ref=args.ref,
            base_ref=args.base_ref,
            issue_num=args.issue_num,
            wiz_id=args.wiz_id,
            wiz_url=args.wiz_url,
            owner=args.owner,
        )
        if args.output and args.output != "/workspace/artifacts/imported_findings.json":
            os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(body)
        else:
            print(body)
        return

    # Primary Action: Parse issue and extract downstream agent output
    body_text = _read_text(args.issue_body, args.body_file)
    comment_text = _read_text(args.comment_body, args.comment_file)
    combined_text = f"{body_text}\n\n{comment_text}".strip()
    if not combined_text:
        print("⚠️ No issue body or comment provided to parse.", file=sys.stderr)
        sys.exit(0)

    candidates = extract_json_candidates(combined_text)
    findings, fixes = parse_downstream_agent_output(candidates, repo=args.repo, workspace_dir=args.workspace)
    if not findings:
        findings, fixes = parse_fallback_patterns(combined_text, repo=args.repo)

    print(f"📊 Extracted {len(findings)} finding(s) and {len(fixes)} recommended fix(es).")
    write_json_file(args.output, findings)
    if fixes:
        write_json_file(args.fixes_output, fixes)
        os.makedirs(os.path.dirname(os.path.abspath(args.context_output)), exist_ok=True)
        raw_ctx = "\n\n".join(fx.get("recommended_fixes", "") for fx in fixes if fx.get("recommended_fixes"))
        with open(args.context_output, "w", encoding="utf-8") as f:
            f.write(raw_ctx)


if __name__ == "__main__":
    main()
