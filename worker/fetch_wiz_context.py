#!/usr/bin/env python3
"""
Wiz MCP Security Context Harvester for CodeMender (Slim Worker).
Interrogates Wiz MCP over HTTP JSON-RPC to discover existing cloud resources,
CVEs, SAST flaws, exposed secrets, and penetration test findings, rendering a
structured Markdown context file for 'cm find -c <file> .'.
"""

import argparse
import json
import logging
import os
from collections import defaultdict
from typing import Any, Dict

from common import (
    DEFAULT_MCP_URL,
    DEFAULT_SECRET_NAME,
    WizMcpClient,
    extract_nodes,
    load_wiz_credentials,
)
from logger import get_logger

logger = get_logger("fetch-wiz-context")


def clean_repo_target(repo: str) -> str:
    """Standardizes repo targets by stripping .git, whitespace, and URL prefixes."""
    r = repo.strip().strip("/")
    if r.endswith(".git"):
        r = r[:-4]
    if "github.com/" in r:
        r = r.split("github.com/", 1)[1]
    elif "github.com:" in r:
        r = r.split("github.com:", 1)[1]
    return r.strip("/")


def harvest_wiz_context(client: WizMcpClient, repo: str) -> Dict[str, Any]:
    """Interrogates Wiz MCP across all security domains for the specified repository."""
    context: Dict[str, Any] = {
        "repo": repo,
        "resources": [],
        "vulnerabilities": [],
        "sast_findings": [],
        "secrets": [],
        "penetration_tests": [],
    }

    repo_clean = clean_repo_target(repo)
    repo_name = repo_clean.split("/")[-1]

    # 1. Cloud Resources / Repositories
    logger.info(f"Interrogating Wiz MCP for cloud resources matching '{repo_clean}'...")
    res_items = client.call_tool("list_cloud_resources", {"search": repo_clean, "first": 20})
    nodes = extract_nodes(res_items, "graphEntities", "cloudResourcesV2")
    if not nodes and repo_name != repo_clean:
        res_items = client.call_tool("list_cloud_resources", {"search": repo_name, "first": 20})
        nodes = extract_nodes(res_items, "graphEntities", "cloudResourcesV2")

    branch_ids, repo_ids = [], []
    for node in nodes:
        nid = node.get("id")
        ntype = str(node.get("type", "")).upper()
        nname = str(node.get("name", ""))
        if nid:
            context["resources"].append({"id": nid, "type": ntype, "name": nname})
            if "BRANCH" in ntype:
                branch_ids.append(nid)
            elif "REPO" in ntype:
                repo_ids.append(nid)

    # 2. Known Vulnerabilities (Unresolved CVEs & Dependencies)
    logger.info("Interrogating Wiz MCP for unresolved vulnerability findings (CVEs)...")
    seen_vulns = set()
    vuln_targets = []
    if branch_ids:
        vuln_targets.append(("asset_id", branch_ids))
    if repo_ids:
        vuln_targets.append(("vcs_repository_id", repo_ids))
    vuln_targets.append(("asset_name", [repo_clean]))

    for param_name, target_val in vuln_targets:
        cursor = None
        while len(context["vulnerabilities"]) < 500:
            q = {param_name: target_val, "status": ["OPEN", "IN_PROGRESS"], "first": 20}
            if cursor:
                q["after"] = cursor
            v_res = client.call_tool("list_vulnerability_findings", q)
            v_nodes = extract_nodes(v_res, "vulnerabilityFindings")
            if not v_nodes:
                break
            for node in v_nodes:
                vid = node.get("id") or node.get("name")
                if str(node.get("status") or "").upper() not in ("RESOLVED", "REJECTED") and vid and vid not in seen_vulns:
                    seen_vulns.add(vid)
                    context["vulnerabilities"].append(node)
            page_info = v_res[0].get("vulnerabilityFindings", {}).get("pageInfo", {}) if v_res and isinstance(v_res[0], dict) else {}
            if not page_info.get("hasNextPage"):
                break
            cursor = page_info.get("endCursor")
            if not cursor:
                break
        if context["vulnerabilities"]:
            break

    # Group vulnerabilities by (package, file) to enrich unique dependencies without redundant calls
    vuln_groups = defaultdict(list)
    for v in context["vulnerabilities"]:
        pkg = (
            v.get("detailedName")
            or (v.get("artifactType", {}).get("hostedTechnology", {}) or {}).get("name")
            or v.get("packageName")
            or "N/A"
        )
        loc = v.get("locationPath") or v.get("filePath") or v.get("file") or "N/A"
        vuln_groups[(pkg, loc)].append(v)

    # Enrich unique dependency groups with exact line number and description from Wiz
    for (pkg, loc), v_list in vuln_groups.items():
        sample_v = v_list[0]
        vid = sample_v.get("id")
        if vid and ("lineNumber" not in sample_v or "description" not in sample_v):
            try:
                detail_res = client.call_tool("get_vulnerability_finding", {"id": vid})
                if detail_res and isinstance(detail_res[0], dict):
                    vf = detail_res[0].get("vulnerabilityFinding", {})
                    line = vf.get("lineNumber")
                    desc = vf.get("description")
                    for member in v_list:
                        if line and "lineNumber" not in member:
                            member["lineNumber"] = line
                        if desc and "description" not in member:
                            member["description"] = desc
            except Exception as e:
                logger.debug(f"Could not enrich vulnerability group {pkg}: {e}")

    # 3. Known SAST Findings
    logger.info("Interrogating Wiz MCP for unresolved SAST code findings...")
    seen_sast = set()
    sast_queries = []
    if branch_ids:
        sast_queries.append({"resource_id": branch_ids, "status": ["OPEN", "IN_PROGRESS"], "first": 50})
    if repo_ids:
        sast_queries.append({"repository_id": repo_ids, "status": ["OPEN", "IN_PROGRESS"], "first": 50})

    for q in sast_queries:
        for node in extract_nodes(client.call_tool("list_sast_findings", q), "sastFindings"):
            sid = node.get("id")
            if sid and sid not in seen_sast and str(node.get("status") or "").upper() not in ("RESOLVED", "REJECTED"):
                seen_sast.add(sid)
                context["sast_findings"].append(node)

    # 4. Known Exposed Secrets
    logger.info("Interrogating Wiz MCP for unresolved exposed secrets & tokens...")
    seen_secrets = set()
    for tid in (branch_ids + repo_ids):
        secret_items = client.call_tool("list_secret_findings", {"resource_id": [tid], "status": ["OPEN", "IN_PROGRESS"], "limit": 50})
        for node in extract_nodes(secret_items, "secretInstances"):
            scid = node.get("id")
            if scid and scid not in seen_secrets and str(node.get("status") or "").upper() not in ("RESOLVED", "REJECTED"):
                seen_secrets.add(scid)
                context["secrets"].append(node)

    # 5. Existing Penetration Test Findings
    logger.info("Interrogating Wiz MCP for open/in-progress penetration test findings...")
    pt_items = client.call_tool(
        "list_penetration_test_findings",
        {"status": ["OPEN", "IN_PROGRESS"], "tag_contains_all": [{"key": "Repository", "value": repo_clean}], "first": 200}
    )
    if not extract_nodes(pt_items, "penetrationTestFindings"):
        pt_items = client.call_tool(
            "list_penetration_test_findings",
            {"status": ["OPEN", "IN_PROGRESS"], "first": 200}
        )

    matching_res_ids = set(branch_ids + repo_ids)
    for node in extract_nodes(pt_items, "penetrationTestFindings"):
        pt_status = str(node.get("status") or node.get("statusV2") or "").upper()
        if pt_status and pt_status not in ("OPEN", "IN_PROGRESS"):
            continue
        res_id = (node.get("resource") or {}).get("id")
        tags_list = node.get("tags") or []
        p_repo = next((t.get("value", "") for t in tags_list if isinstance(t, dict) and t.get("key") in ("Repository", "Repo")), "")

        # Strict scoping: must be attached to the repo/branch resource OR explicitly tagged with this repo
        if (res_id and res_id in matching_res_ids) or (p_repo and p_repo.strip().lower() == repo_clean.lower()):
            context["penetration_tests"].append(node)

    logger.info(
        f"Context summary: {len(context['resources'])} resource(s), "
        f"{len(context['vulnerabilities'])} CVE(s), {len(context['sast_findings'])} SAST flaw(s), "
        f"{len(context['secrets'])} secret(s), {len(context['penetration_tests'])} pentest finding(s)."
    )
    return context


def format_context_markdown(ctx: Dict[str, Any]) -> str:
    """Renders the gathered Wiz context into structured Markdown for CodeMender."""
    repo = ctx.get("repo", "unknown")
    md = [
        f"# Wiz Security Graph Context for `{repo}`\n",
        "> [!IMPORTANT]",
        "> **Scan Instructions for CodeMender Agent:**",
        "> The security issues listed below are **ALREADY KNOWN** and tracked in Wiz.",
        "> When scanning this repository, your objective is to uncover **NEW, UNREPORTED** vulnerabilities,",
        "> zero-days, logic flaws, or validate whether theoretical weaknesses have exploitable code paths.",
        "> Avoid duplicating these known issues unless you identify reachability into an unhandled code sink.\n",
    ]

    if vulns := ctx.get("vulnerabilities", []):
        md.extend([
            f"## 🐛 Known Vulnerabilities (Tracked in Wiz - {len(vulns)} Total CVEs)\n",
            "| Severity | Package / Dependency | Target File & Line | Associated CVEs | Remediation Target |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ])

        groups = defaultdict(list)
        for v in vulns:
            pkg = (
                v.get("detailedName")
                or (v.get("artifactType", {}).get("hostedTechnology", {}) or {}).get("name")
                or v.get("packageName")
                or "N/A"
            )
            loc = v.get("locationPath") or v.get("filePath") or v.get("file") or "N/A"
            groups[(pkg, loc)].append(v)

        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}
        sorted_groups = sorted(
            groups.items(),
            key=lambda item: (
                min(sev_order.get(str(x.get("severity", "")).upper(), 99) for x in item[1]),
                -len(item[1])
            )
        )

        for (pkg, loc), v_list in sorted_groups:
            highest_sev = min(v_list, key=lambda x: sev_order.get(str(x.get("severity", "")).upper(), 99)).get("severity", "HIGH").upper()

            # Unique installed and target versions
            installed_vers = sorted({v.get("version") for v in v_list if v.get("version")})
            fixed_vers = sorted({v.get("fixedVersion") or v.get("recommendedVersion") for v in v_list if (v.get("fixedVersion") or v.get("recommendedVersion"))})
            inst_str = ", ".join(installed_vers) if installed_vers else ""
            fix_str = fixed_vers[-1] if fixed_vers else ""
            if inst_str and fix_str:
                pkg_str = f"`{pkg}` `({inst_str} → {fix_str})`"
            elif inst_str:
                pkg_str = f"`{pkg}` `({inst_str})`"
            else:
                pkg_str = f"`{pkg}`"

            clean_loc = loc[1:] if loc.startswith("/") else loc
            line_nums = sorted({v.get("lineNumber") for v in v_list if v.get("lineNumber")})
            line_str = f":{line_nums[0]}" if line_nums else ""
            loc_str = f"`{clean_loc}{line_str}`"

            # All CVE IDs for this package
            cve_set = sorted({v.get("name") or v.get("vulnerabilityExternalId") for v in v_list if v.get("name") or v.get("vulnerabilityExternalId")})
            if len(cve_set) > 3:
                cve_str = f"**{len(cve_set)} CVEs**: `" + "`, `".join(cve_set[:3]) + f"` *(+{len(cve_set)-3} more)*"
            elif cve_set:
                cve_str = f"**{len(cve_set)} CVEs**: `" + "`, `".join(cve_set) + "`"
            else:
                cve_str = "N/A"

            remed = f"Upgrade to `{fix_str}`" if fix_str else "Apply vendor security patch"
            md.append(f"| **{highest_sev}** | {pkg_str} | {loc_str} | {cve_str} | {remed} |")
        md.append("")

    if sast := ctx.get("sast_findings", []):
        md.extend([
            f"## 🔍 Known SAST Code Weaknesses (Tracked in Wiz - {len(sast)} Total Findings)\n",
            "| Finding | Severity | Target File | Rule / CWE |",
            "| :--- | :--- | :--- | :--- |"
        ])
        for s in sast:
            title = s.get("name") or s.get("title") or "Code Issue"
            sev = str(s.get("severity") or "HIGH").upper()
            loc = s.get("location", {})
            fpath = loc.get("path") or loc.get("file") or s.get("filePath") or "N/A"
            weaknesses = [w.get("id") for w in s.get("weaknesses", []) if isinstance(w, dict) and w.get("id")]
            rule = (
                s.get("ruleName")
                or (s.get("rule") or {}).get("name")
                or (", ".join(weaknesses) if weaknesses else "")
                or s.get("cwe")
                or "N/A"
            )
            md.append(f"| {title} | **{sev}** | `{fpath}` | `{rule}` |")
        md.append("")

    if secrets := ctx.get("secrets", []):
        md.append(f"## 🔑 Known Exposed Secrets (Tracked in Wiz - {len(secrets)} Total Findings)\n")
        for s in secrets:
            sev = str(s.get("severity") or "HIGH").upper()
            sec_name = s.get("name") or s.get("type") or "Secret"
            path = s.get("filePath") or s.get("path")
            if path and path != "N/A":
                md.append(f"- **{sec_name}** [{sev}] in `{path}`")
            else:
                sec_type = s.get("type") or "SECRET"
                md.append(f"- **{sec_name}** [{sev}] (Type: `{sec_type}`, Status: `{s.get('status', 'OPEN')}`)")
        md.append("")

    if pts := ctx.get("penetration_tests", []):
        md.extend([
            f"## 🛡️ Existing Penetration Test Findings (Tracked in Wiz - {len(pts)} Total Findings)\n",
            "| ID | Finding Title | Severity | Status |",
            "| :--- | :--- | :--- | :--- |"
        ])
        for p in pts:
            md.append(f"| `{p.get('id') or 'N/A'}` | {p.get('name') or 'Pentest Finding'} | **{str(p.get('severity') or 'HIGH').upper()}** | `{p.get('status') or p.get('statusV2') or 'OPEN'}` |")
        md.append("")

    if not (vulns or sast or secrets or pts):
        md.append("*No existing security alerts or prior findings were located in Wiz for this repository.*")
        md.append("Perform a comprehensive full security baseline audit across all code paths.\n")

    return "\n".join(md)


def main() -> None:
    p = argparse.ArgumentParser(description="Gather Wiz Security Context for CodeMender")
    p.add_argument("--repo", required=True)
    p.add_argument("--output", default="/tmp/wiz_context.md")
    p.add_argument("--json-output", default="")
    p.add_argument("--project", default=None)
    p.add_argument("--secret", default=DEFAULT_SECRET_NAME)
    p.add_argument("--mcp-url", default=None, help=f"Override the Wiz MCP URL (default: secret's mcp_url, else {DEFAULT_MCP_URL})")
    args = p.parse_args()

    creds = load_wiz_credentials(project_id=args.project, secret_name=args.secret)
    client = WizMcpClient(args.mcp_url, creds)
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    if args.json_output:
        os.makedirs(os.path.dirname(os.path.abspath(args.json_output)), exist_ok=True)

    if not client.initialize():
        logger.warning(f"⚠️  Skipping Wiz MCP security context: {client.last_error}")
        logger.warning("Proceeding with a minimal scan context (no known Wiz findings will be excluded).")
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(f"# Security Scan Context for `{args.repo}`\n\nPerform full discovery scan.\n")
        if args.json_output:
            with open(args.json_output, "w", encoding="utf-8") as f:
                f.write("{}\n")
        return

    raw_ctx = harvest_wiz_context(client, args.repo)
    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump(raw_ctx, f, indent=2)
        logger.info(f"✅ Wrote raw Wiz context JSON to {args.json_output}")

    md_content = format_context_markdown(raw_ctx)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(md_content)
    logger.info(f"✅ Wrote Wiz security context to {args.output} ({len(md_content)} bytes)")


if __name__ == "__main__":
    main()
