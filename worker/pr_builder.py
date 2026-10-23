#!/usr/bin/env python3
"""
Pull Request Authoring & Owner Branch Aggregator:
- Generates conventional commit PR titles and GitHub-Flavored Markdown bodies
- Merges isolated runner branches per owner and opens consolidated Draft PRs
"""

import base64
import json
import os
import subprocess
import sys
from typing import Any, Dict, List

from common import clean_file_path, first_of, format_severity, read_json_file
from logger import get_logger, log_error, log_header, log_info, log_success, log_warn
from planner import find_matching_finding_and_fix

logger = get_logger("codemender-pr-builder")


def build_pr_title(artifacts_dir: str, finding_id: str = "", owner: str = "") -> str:
    """Builds a conventional commit PR title for single finding or owner-aggregated remediation."""
    owner_str = str(owner).strip().lstrip("@")
    tasks = read_json_file(os.path.join(artifacts_dir, "remediation_tasks.json"), [])
    if isinstance(tasks, list) and len(tasks) > 1:
        if owner_str == "unassigned":
            return f"fix(security): resolve {len(tasks)} CodeMender findings"
        if owner_str:
            return f"fix(security): resolve {len(tasks)} CodeMender findings for @{owner_str}"
        task_owner = str(tasks[0].get("owner") or "").strip().lstrip("@")
        if task_owner and task_owner != "unassigned":
            return f"fix(security): resolve {len(tasks)} CodeMender findings for @{task_owner}"
        return f"fix(security): resolve {len(tasks)} CodeMender findings"

    if owner_str:
        if owner_str == "unassigned":
            return "fix(security): resolve unassigned CodeMender security findings"
        return f"fix(security): resolve CodeMender security findings for @{owner_str}"

    finding, _ = find_matching_finding_and_fix(artifacts_dir, finding_id=finding_id)
    title = str(first_of(finding, "title", "Title", default="security remediation")).strip()
    prefix = finding_id[:8] if finding_id else str(first_of(finding, "id", "finding_id"))[:8]
    return f"fix(security): {title} ({prefix})" if prefix else f"fix(security): {title}"


def render_batch_pr_body(
    items: List[Dict[str, Any]],
    repo: str,
    ref: str = "main",
    issue_num: str = "",
    owner: str = "",
) -> str:
    """Renders an aggregated Markdown PR body for multiple findings/tasks."""
    owner_str = str(owner).strip().lstrip("@") or str(items[0].get("owner") or "").strip().lstrip("@")
    is_unassigned = (not owner_str or owner_str == "unassigned")
    body_lines = [
        f'<!-- codemender-batch-metadata: {{"count": {len(items)}, "owner": "{owner_str}"}} -->\n',
        "## 🛡️ CodeMender Automated Security Remediation (Aggregated Draft)\n",
    ]
    if issue_num:
        body_lines.append(f"> **Closes #{issue_num}**\n")
    if not is_unassigned:
        body_lines.append(f"**Assigned Reviewer:** @{owner_str}\n")

    body_lines.extend([
        "### 📋 Remediated Security Findings\n",
        "| # | Severity | Finding ID | Target Location | Vulnerability Title |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ])
    for idx, t in enumerate(items, 1):
        t_fid = str(first_of(t, "finding_id", "short_id", "id", default=f"task-{idx}"))[:8]
        t_sev = str(first_of(t, "severity", "Severity", default="CRITICAL")).strip().upper()
        t_path = clean_file_path(t.get("file_path") or t.get("filePath") or "")
        t_line = int(t.get("line") or t.get("start_line") or 1)
        t_title = str(t.get("title") or "Security Vulnerability")
        t_link = f"[`{t_path}:{t_line}`](https://github.com/{repo}/blob/{ref}/{t_path}#L{t_line})" if t_path else "`N/A`"
        body_lines.append(f"| {idx} | **{t_sev}** | `{t_fid}` | {t_link} | {t_title} |")

    body_lines.extend(["\n---\n", "### 🔍 Remediation Details\n"])
    for idx, t in enumerate(items, 1):
        t_fid = str(first_of(t, "finding_id", "short_id", "id", default=f"task-{idx}"))[:8]
        t_title = str(t.get("title") or "Security Vulnerability")
        t_msg = str(t.get("message") or t.get("description") or "")
        t_rec = str(t.get("recommended_fixes") or "")
        body_lines.append(f"#### {idx}. `{t_fid}`: {t_title}")
        if t_msg:
            body_lines.append(f"- **Summary:** {t_msg}")
        if t_rec:
            body_lines.append(f"- **Applied Guidance:**\n```\n{t_rec}\n```")
        body_lines.append("")

    body_lines.extend([
        "---",
        "*Draft Pull Request automatically consolidated and opened by CodeMender Orchestrator.*",
    ])
    return "\n".join(body_lines)


def build_pr_body(
    artifacts_dir: str,
    finding_id: str = "",
    repo: str = "unknown",
    ref: str = "main",
    base_ref: str = "main",
    issue_num: str = "",
    wiz_id: str = "",
    wiz_url: str = "",
    owner: str = "",
) -> str:
    """Constructs a Markdown body for the Draft PR (single or multi-finding)."""
    tasks = read_json_file(os.path.join(artifacts_dir, "remediation_tasks.json"), [])
    if isinstance(tasks, list) and len(tasks) > 1:
        return render_batch_pr_body(tasks, repo=repo, ref=ref, issue_num=issue_num, owner=owner)

    finding, fix_item = find_matching_finding_and_fix(artifacts_dir, finding_id=finding_id)
    clean_path = clean_file_path(first_of(finding, "file_path", "FilePath"))
    line = int(first_of(finding, "line", "start_line", "StartLine", default=1))
    sev_formatted = format_severity(str(first_of(finding, "severity", "Severity", default="CRITICAL")).upper())
    vuln_type = str(first_of(finding, "vuln_type", "VulnType", default="Security Vulnerability"))
    msg = str(first_of(finding, "message", "Message", "analysis"))
    rec_fixes = fix_item.get("recommended_fixes") or finding.get("recommended_fixes") or ""

    file_link = f"[`{clean_path} (L{line})`](https://github.com/{repo}/blob/{ref}/{clean_path}#L{line})" if clean_path else "`N/A`"
    short_fid = finding_id[:8] if finding_id else str(first_of(finding, "id", "finding_id", default="remediation"))[:8]

    body_lines = []
    if wiz_id:
        body_lines.append(f'<!-- wiz-pentest-metadata: {{"id": "{wiz_id}", "repo": "{repo}", "cm_id": "{short_fid}"}} -->\n')
    body_lines.extend([
        f'<!-- codemender-fix-metadata: {{"finding_id": "{short_fid}", "file": "{clean_path}"}} -->\n',
        "## 🛡️ CodeMender Automated Security Remediation (Draft)\n",
    ])
    if issue_num:
        body_lines.append(f"> **Closes #{issue_num}**\n")

    body_lines.extend([
        "| Attribute | Details |",
        "| :--- | :--- |",
        f"| **Finding ID** | `{short_fid}` |",
        f"| **Severity** | **{sev_formatted}** |",
        f"| **Vulnerability Type** | `{vuln_type}` |",
        f"| **Target File** | {file_link} |",
        f"| **Target Base** | `{base_ref}` |\n",
    ])

    if wiz_id:
        wiz_link_str = f"[`{wiz_id}`]({wiz_url})" if wiz_url else f"`{wiz_id}`"
        body_lines.extend([
            "### 🛡️ Wiz Penetration Testing Ledger",
            f"- **Wiz Finding:** {wiz_link_str}",
            "- **Status:** Verified by CodeMender. Upon PR merge, this finding will automatically resolve in Wiz.\n",
        ])
    if msg:
        body_lines.extend(["### 📝 Issue Summary", f"{msg}\n"])
    if rec_fixes:
        body_lines.extend(["### 🔧 Applied Remediation Guidance", f"{rec_fixes}\n"])

    body_lines.extend([
        "---",
        "*Draft Pull Request automatically opened by CodeMender Slim Worker.*",
    ])
    return "\n".join(body_lines)


def aggregate_owner_prs(
    matrix: List[Dict[str, Any]],
    repo: str,
    base_ref: str = "main",
    target_ref: str = "main",
    issue_num: str = "",
) -> None:
    """Merges isolated runner branches per owner and opens/updates consolidated Draft PRs."""
    if not matrix:
        logger.info("No matrix tasks to aggregate.")
        return

    owners_map: Dict[str, List[Dict[str, Any]]] = {}
    for t in matrix:
        owners_map.setdefault(t.get("owner", "unassigned"), []).append(t)

    for owner, tasks in owners_map.items():
        log_header(f"📦 Aggregating remediation branches for Owner: @{owner} ({len(tasks)} runner task(s))", logger=logger)
        is_unassigned = (owner == "unassigned")
        consolidated_branch = "codemender/fix-unassigned" if is_unassigned else f"codemender/fix-owner-{owner}"
        branches_to_merge = []
        for t in tasks:
            rb = t.get("runner_branch", "")
            if rb and subprocess.run(["git", "ls-remote", "--heads", "origin", rb], capture_output=True, text=True).stdout.strip():
                branches_to_merge.append(rb)
                logger.debug(f"Found remote runner branch: origin/{rb}")

        if not branches_to_merge:
            logger.info(f"ℹ️ No runner branches found on remote for @{owner}. Skipping PR creation.")
            continue

        logger.info(f"🌿 Checking out base {base_ref} and creating consolidated branch {consolidated_branch}...")
        subprocess.run(["git", "checkout", "-f", f"origin/{base_ref}"], check=True)
        subprocess.run(["git", "checkout", "-B", consolidated_branch], check=True)

        for rb in branches_to_merge:
            logger.info(f"🔀 Merging origin/{rb} into {consolidated_branch}...")
            res = subprocess.run(
                ["git", "merge", "--no-ff", f"origin/{rb}", "-m", f"merge: CodeMender remediation from {rb}"],
                capture_output=True,
                text=True,
            )
            if res.returncode != 0:
                logger.error(f"❌ Conflict merging {rb}: {res.stderr}")
                subprocess.run(["git", "merge", "--abort"], check=False)
                sys.exit(res.returncode)

        logger.info(f"🚀 Pushing {consolidated_branch} to origin...")
        subprocess.run(["git", "push", "origin", consolidated_branch, "--force"], check=True)

        all_findings: List[Dict[str, Any]] = []
        for t in tasks:
            b64 = t.get("finding_json_b64", "")
            if b64:
                try:
                    decoded = json.loads(base64.b64decode(b64).decode("utf-8"))
                    all_findings.extend(decoded if isinstance(decoded, list) else [decoded])
                except Exception:
                    pass

        label_name = tasks[0].get("label_name", "codemender-fix:critical")
        label_color = tasks[0].get("label_color", "b60205")
        subprocess.run(
            ["gh", "label", "create", label_name, "--color", label_color, "--description", "CodeMender automated remediation", "--repo", repo, "--force"],
            check=False,
        )

        if len(all_findings) > 1:
            pr_title = (
                f"fix(security): resolve {len(all_findings)} CodeMender findings"
                if is_unassigned
                else f"fix(security): resolve {len(all_findings)} CodeMender findings for @{owner}"
            )
        else:
            t0 = all_findings[0] if all_findings else tasks[0]
            pr_title = (
                f"fix(security): resolve [{t0.get('severity', 'CRITICAL')}] {t0.get('title', 'Security Vulnerability')}"
                if is_unassigned
                else f"fix(security): resolve [{t0.get('severity', 'CRITICAL')}] {t0.get('title', 'Security Vulnerability')} for @{owner}"
            )

        pr_body_path = f"/tmp/pr_body_{owner}.md"
        with open(pr_body_path, "w", encoding="utf-8") as bf:
            bf.write(render_batch_pr_body(all_findings, repo=repo, ref=target_ref, issue_num=issue_num, owner=owner))

        existing_pr = subprocess.run(
            ["gh", "pr", "list", "--repo", repo, "--head", consolidated_branch, "--state", "open", "--json", "number", "-q", ".[0].number"],
            capture_output=True,
            text=True,
        ).stdout.strip()

        if existing_pr:
            logger.info(f"🔄 Updating existing Draft PR #{existing_pr} on {consolidated_branch}...")
            subprocess.run(["gh", "pr", "edit", existing_pr, "--repo", repo, "--title", pr_title, "--body-file", pr_body_path, "--add-label", label_name], check=True)
            logger.info(f"✅ Draft PR #{existing_pr} updated.")
        else:
            logger.info(f"🔀 Opening new Draft Pull Request on {consolidated_branch}...")
            cmd = ["gh", "pr", "create", "--draft", "--repo", repo, "--head", consolidated_branch, "--base", base_ref, "--title", pr_title, "--body-file", pr_body_path, "--label", label_name]
            if not is_unassigned:
                cmd.extend(["--assignee", owner])
            subprocess.run(cmd, check=True)
            logger.info(f"✅ Draft PR opened for @{owner}.")

        logger.info(f"🧹 Cleaning up {len(branches_to_merge)} temporary runner branch(es)...")
        for rb in branches_to_merge:
            subprocess.run(["git", "push", "origin", "--delete", rb], check=False)
        logger.info(f"✅ Cleaned up runner branches for @{owner}.")
