#!/usr/bin/env python3
"""
Remediation Task & Matrix Planner:
- Correlates CodeMender findings across imported_findings.json, findings.json, and SQLite state.db
- Checks verification status (VERIFIED)
- Generates ordered remediation tasks and parallel GitHub Actions execution matrices
"""

import base64
import json
import os
import sqlite3
from typing import Any, Dict, List, Optional, Tuple

from common import clean_file_path, first_of, get_severity_label_info, read_json_file
from logger import get_logger
from parser import extract_json_candidates, parse_downstream_agent_output, parse_fallback_patterns

logger = get_logger("codemender-planner")


def _db_paths(artifacts_dir: str) -> List[str]:
    return [
        os.path.join(artifacts_dir, ".codemender", "state.db"),
        os.path.join(artifacts_dir, "state.db"),
        os.path.expanduser("~/.codemender/state.db"),
        "/root/.codemender/state.db",
        "/workspace/repo/.codemender/state.db",
    ]


def load_artifact_sets(artifacts_dir: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Loads (imported_items, cm_items, fixes_items) from an artifacts directory."""
    imp_raw = read_json_file(os.path.join(artifacts_dir, "imported_findings.json"), [])
    imported_items = imp_raw if isinstance(imp_raw, list) else [imp_raw] if isinstance(imp_raw, dict) else []

    cm_raw = read_json_file(os.path.join(artifacts_dir, "findings.json"), [])
    cm_items = cm_raw if isinstance(cm_raw, list) else cm_raw.get("findings", []) if isinstance(cm_raw, dict) else []

    fix_raw = read_json_file(os.path.join(artifacts_dir, "recommended_fixes.json"), [])
    fixes_items = fix_raw if isinstance(fix_raw, list) else [fix_raw] if isinstance(fix_raw, dict) else []

    return imported_items, cm_items, fixes_items


def resolve_imported_finding_id(artifacts_dir: str) -> str:
    """Resolves the CodeMender FindingID from SQLite state.db or findings.json."""
    logger.debug(f"Resolving CodeMender Finding ID from artifacts directory: {artifacts_dir}")
    imported_items, cm_findings, _ = load_artifact_sets(artifacts_dir)

    if cm_findings:
        # 1. Match by file path and title
        for imp in imported_items:
            imp_path = clean_file_path(first_of(imp, "file_path", "FilePath", "path"))
            imp_title = str(first_of(imp, "title", "Title")).strip().lower()
            for cm_f in cm_findings:
                if not isinstance(cm_f, dict):
                    continue
                cm_path = clean_file_path(first_of(cm_f, "FilePath", "file_path"))
                cm_title = str(first_of(cm_f, "Title", "title")).strip().lower()
                if imp_path and cm_path and (imp_path in cm_path or cm_path in imp_path):
                    if not imp_title or imp_title in cm_title or cm_title in imp_title:
                        fid = str(first_of(cm_f, "FindingID", "id", "finding_id")).strip()
                        if fid:
                            logger.info(f"Resolved Finding ID '{fid}' via path/title match ({cm_path})")
                            return fid

        # 2. Match by import session ID
        for cm_f in reversed(cm_findings):
            if isinstance(cm_f, dict) and str(cm_f.get("SessionID") or "").startswith("import_"):
                fid = str(first_of(cm_f, "FindingID", "id", "finding_id")).strip()
                if fid:
                    logger.info(f"Resolved Finding ID '{fid}' via import session ID")
                    return fid

        # 3. Fallback to latest finding in report
        for cm_f in reversed(cm_findings):
            if isinstance(cm_f, dict):
                fid = str(first_of(cm_f, "FindingID", "id", "finding_id")).strip()
                if fid:
                    logger.info(f"Resolved Finding ID '{fid}' from latest finding in report")
                    return fid

    # 4. Query local SQLite state database
    for db_file in _db_paths(artifacts_dir):
        if os.path.exists(db_file):
            conn = None
            try:
                conn = sqlite3.connect(db_file)
                cur = conn.cursor()
                cols = [c[1] for c in cur.execute("PRAGMA table_info(findings)").fetchall()]
                id_col = "finding_id" if "finding_id" in cols else ("id" if "id" in cols else None)
                if id_col:
                    if "session_id" in cols:
                        row = cur.execute(
                            f"SELECT {id_col} FROM findings WHERE session_id LIKE 'import_%' ORDER BY rowid DESC LIMIT 1"
                        ).fetchone()
                        if row and row[0]:
                            res = str(row[0]).strip()
                            logger.info(f"Resolved Finding ID '{res}' from SQLite state DB ({db_file}) via session_id")
                            return res
                    row = cur.execute(f"SELECT {id_col} FROM findings ORDER BY rowid DESC LIMIT 1").fetchone()
                    if row and row[0]:
                        res = str(row[0]).strip()
                        logger.info(f"Resolved Finding ID '{res}' from SQLite state DB ({db_file})")
                        return res
            except Exception as e:
                logger.debug(f"Error querying SQLite DB ({db_file}): {e}")
            finally:
                if conn:
                    conn.close()

    logger.warning("Could not resolve CodeMender Finding ID from report or SQLite database.")
    return ""


def is_finding_verified(artifacts_dir: str, *target_ids: str) -> bool:
    """Checks whether any of `target_ids` has status VERIFIED in SQLite or findings.json."""
    targets = {t.strip().lower() for t in target_ids if t and t.strip()}
    if not targets:
        return False

    def _matches(fid: str, status: str) -> bool:
        fl = fid.strip().lower()
        return (
            status.strip().upper() == "VERIFIED"
            and bool(fl)
            and any(fl == t or fl.startswith(t) or t.startswith(fl[:8]) for t in targets)
        )

    for db_file in _db_paths(artifacts_dir):
        if os.path.exists(db_file):
            conn = None
            try:
                conn = sqlite3.connect(db_file)
                cur = conn.cursor()
                cols = [c[1] for c in cur.execute("PRAGMA table_info(findings)").fetchall()]
                id_col = "finding_id" if "finding_id" in cols else ("id" if "id" in cols else None)
                stat_col = "status" if "status" in cols else ("state" if "state" in cols else None)
                if id_col and stat_col:
                    for fid, stat in cur.execute(f"SELECT {id_col}, {stat_col} FROM findings").fetchall():
                        if _matches(str(fid), str(stat)):
                            logger.info(f"Finding '{fid}' confirmed VERIFIED in SQLite state DB ({db_file}).")
                            return True
            except Exception as e:
                logger.debug(f"Error checking verification in SQLite DB ({db_file}): {e}")
            finally:
                if conn:
                    conn.close()

    _, cm_items, _ = load_artifact_sets(artifacts_dir)
    for it in cm_items:
        fid = str(first_of(it, "id", "FindingID", "finding_id"))
        stat = str(first_of(it, "status", "Status"))
        if _matches(fid, stat):
            logger.info(f"Finding '{fid}' confirmed VERIFIED in findings report.")
            return True
    logger.info(f"No matching VERIFIED status found for targets: {targets}")
    return False


def find_matching_finding_and_fix(artifacts_dir: str, finding_id: str = "") -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Locates the specific finding and recommended fix matching `finding_id`."""
    imported_items, cm_items, fixes_items = load_artifact_sets(artifacts_dir)
    target_finding: Dict[str, Any] = {}
    fid_lower = str(finding_id).strip().lower()

    if fid_lower:
        for collection in (cm_items, imported_items):
            for item in collection:
                cid = str(first_of(item, "finding_id", "FindingID", "id")).strip().lower()
                if cid and (cid.startswith(fid_lower) or fid_lower.startswith(cid[:8])):
                    target_finding = item
                    break
            if target_finding:
                break

    if not target_finding:
        target_finding = imported_items[0] if imported_items else (cm_items[0] if cm_items else {})

    target_fix: Dict[str, Any] = {}
    if target_finding:
        tf_path = clean_file_path(first_of(target_finding, "file_path", "FilePath"))
        tf_line = int(first_of(target_finding, "line", "start_line", "StartLine", default=1))
        for fix in fixes_items:
            ff_path = clean_file_path(fix.get("file_path") or "")
            ff_line = int(fix.get("line") or 1)
            if tf_path and ff_path and (tf_path in ff_path or ff_path in tf_path) and abs(tf_line - ff_line) <= 5:
                target_fix = fix
                break
        if not target_fix and fixes_items:
            target_fix = fixes_items[0]

    return target_finding, target_fix


def generate_remediation_tasks(artifacts_dir: str, vuln_id_filter: str = "") -> List[Dict[str, Any]]:
    """Generates an ordered list of remediation tasks for 1-n findings."""
    imported_items, cm_items, fixes_items = load_artifact_sets(artifacts_dir)
    source_items = imported_items if imported_items else cm_items
    v_filter = str(vuln_id_filter).strip().lower()
    tasks: List[Dict[str, Any]] = []

    for idx, item in enumerate(source_items):
        item_path = clean_file_path(first_of(item, "file_path", "FilePath"))
        item_line = int(first_of(item, "line", "start_line", "StartLine", default=1))
        item_title = str(first_of(item, "title", "Title", default="Security Vulnerability")).strip()
        item_sev = str(first_of(item, "severity", "Severity", default="CRITICAL")).strip().upper()
        item_vuln_type = str(first_of(item, "vuln_type", "VulnType", default="Vulnerability")).strip()

        cm_fid = ""
        for cm_f in cm_items:
            cm_path = clean_file_path(first_of(cm_f, "file_path", "FilePath"))
            cm_line = int(first_of(cm_f, "start_line", "StartLine", "line", default=1))
            cm_title = str(first_of(cm_f, "title", "Title")).strip().lower()
            if item_path and cm_path and (item_path in cm_path or cm_path in item_path):
                if abs(item_line - cm_line) <= 5 or not cm_title or item_title.lower() in cm_title:
                    cm_fid = str(first_of(cm_f, "finding_id", "FindingID", "id")).strip()
                    if cm_fid:
                        break

        cm_fid = cm_fid or str(first_of(item, "id", "finding_id", default=f"remediate-{idx+1}")).strip()
        short_id = cm_fid[:8] if cm_fid else f"fix-{idx+1}"

        if v_filter and v_filter != "all" and len(source_items) > 1:
            item_id = str(first_of(item, "id", "finding_id")).lower()
            if not (
                cm_fid.lower().startswith(v_filter)
                or v_filter.startswith(short_id.lower())
                or item_id.startswith(v_filter)
                or v_filter.startswith(item_id[:8])
            ):
                continue

        rec_fixes = ""
        for fix in fixes_items:
            f_path = clean_file_path(fix.get("file_path") or "")
            f_line = int(fix.get("line") or 1)
            if item_path and f_path and (item_path in f_path or f_path in item_path) and abs(item_line - f_line) <= 5:
                rec_fixes = str(fix.get("recommended_fixes") or "").strip()
                break
        if not rec_fixes and idx < len(fixes_items):
            rec_fixes = str(fixes_items[idx].get("recommended_fixes") or "").strip()

        if not rec_fixes:
            rec_fixes = str(item.get("recommended_fixes") or "").strip()

        owner_val = str(item.get("owner") or "").strip().lstrip("@")
        if not owner_val:
            for fix in fixes_items:
                if fix.get("finding_id") == cm_fid or (fix.get("file_path") == item_path and fix.get("line") == item_line):
                    owner_val = str(fix.get("owner") or "").strip().lstrip("@")
                    if owner_val:
                        break

        wiz_id = str(first_of(item, "wiz_id", "wiz_pentest_id", "WizPentestID", default="")).strip()
        label_name, label_color = get_severity_label_info(item_sev)
        tasks.append({
            "task_index": idx + 1,
            "finding_id": cm_fid,
            "short_id": short_id,
            "file_path": item_path,
            "line": item_line,
            "title": item_title,
            "severity": item_sev,
            "vuln_type": item_vuln_type,
            "message": str(first_of(item, "message", "Message", default=f"{item_title} in {item_path}")),
            "owner": owner_val,
            "recommended_fixes": rec_fixes,
            "label_name": label_name,
            "label_color": label_color,
            "wiz_id": wiz_id,
        })
    logger.info(f"Generated {len(tasks)} remediation task(s) (filter: '{v_filter or 'none'}').")
    return tasks


def generate_remediation_matrix(
    artifacts_dir: str = "",
    body_text: str = "",
    comment_text: str = "",
    repo: str = "unknown",
    vuln_id_filter: str = "",
    workspace_dir: Optional[str] = None,
    verify_first: str = "false",
) -> List[Dict[str, Any]]:
    """Generates a matrix of isolated (owner, file_path) remediation tasks for GitHub Actions."""
    findings: List[Dict[str, Any]] = []
    fixes: List[Dict[str, Any]] = []

    if artifacts_dir:
        imp, cm, fixes = load_artifact_sets(artifacts_dir)
        findings = imp if imp else cm

    if not findings:
        combined_text = f"{body_text}\n\n{comment_text}".strip()
        if combined_text:
            candidates = extract_json_candidates(combined_text)
            findings, fixes = parse_downstream_agent_output(candidates, repo=repo, workspace_dir=workspace_dir)
            if not findings:
                findings, fixes = parse_fallback_patterns(combined_text, repo=repo)

    v_filter = str(vuln_id_filter).strip().lower()
    if v_filter and v_filter != "all":
        findings = [
            f for f in findings
            if str(f.get("id", "")).lower().startswith(v_filter)
            or v_filter.startswith(str(f.get("id", ""))[:8].lower())
        ]

    if not findings and v_filter and v_filter != "all":
        short_id = v_filter[:8]
        findings = [{
            "id": v_filter,
            "file_path": "",
            "line": 1,
            "title": f"Vulnerability {short_id}",
            "severity": "CRITICAL",
            "vuln_type": "Vulnerability",
            "message": f"Remediation task for finding {v_filter}",
            "snippet": "",
        }]

    groups: Dict[str, List[Tuple[Dict[str, Any], str, str]]] = {}
    for idx, item in enumerate(findings):
        fid = str(first_of(item, "id", "finding_id", default=f"task-{idx+1}")).strip()
        clean_path = clean_file_path(first_of(item, "file_path", "FilePath"))
        line = int(first_of(item, "line", "start_line", "StartLine", default=1))
        title = str(first_of(item, "title", "Title", default="Security Vulnerability")).strip()
        sev = str(first_of(item, "severity", "Severity", default="CRITICAL")).strip().upper()
        vuln_type = str(first_of(item, "vuln_type", "VulnType", default="Vulnerability")).strip()
        msg = str(first_of(item, "message", "Message", default=f"{title} in {clean_path}"))

        rec_fixes = ""
        for fx in fixes:
            f_path = clean_file_path(fx.get("file_path") or "")
            f_line = int(fx.get("line") or 1)
            f_id = str(fx.get("finding_id") or "").strip()
            if (fid and f_id and fid.lower() == f_id.lower()) or (
                clean_path and f_path and (clean_path in f_path or f_path in clean_path) and abs(line - f_line) <= 5
            ):
                rec_fixes = str(fx.get("recommended_fixes") or "").strip()
                break
        if not rec_fixes and idx < len(fixes):
            rec_fixes = str(fixes[idx].get("recommended_fixes") or "").strip()

        if not rec_fixes:
            rec_fixes = str(item.get("recommended_fixes") or "").strip()

        owner_val = str(item.get("owner") or "").strip().lstrip("@")
        if not owner_val:
            for fx in fixes:
                if fx.get("finding_id") == fid or (clean_path and fx.get("file_path") == clean_path and abs(line - fx.get("line", 1)) <= 5):
                    owner_val = str(fx.get("owner") or "").strip().lstrip("@")
                    if owner_val:
                        break
        owner_key = owner_val if owner_val else "unassigned"
        group_key = f"{owner_key}::{clean_path}"

        single_finding = {
            "file_path": clean_path,
            "line": line,
            "start_line": line,
            "end_line": int(item.get("end_line") or line),
            "title": title,
            "message": msg,
            "severity": sev,
            "vuln_type": vuln_type,
            "snippet": str(item.get("snippet") or f"// Vulnerable code in {clean_path} at line {line}"),
            "id": fid,
            "owner": owner_val,
        }
        if rec_fixes:
            single_finding["recommended_fixes"] = rec_fixes

        groups.setdefault(group_key, []).append((single_finding, rec_fixes, fid))

    matrix: List[Dict[str, Any]] = []
    for grp_idx, (group_key, items) in enumerate(groups.items(), 1):
        owner_name, file_path = group_key.split("::", 1)
        group_findings = [it[0] for it in items]
        finding_json_b64 = base64.b64encode(json.dumps(group_findings).encode("utf-8")).decode("utf-8")

        all_fixes = [it[1] for it in items if it[1]]
        combined_fixes = "\n\n---\n\n".join(all_fixes) if all_fixes else ""
        rec_fixes_b64 = base64.b64encode(combined_fixes.encode("utf-8")).decode("utf-8") if combined_fixes else ""

        first_finding, _, first_fid = items[0]
        short_id = first_fid[:8] if first_fid else f"grp-{grp_idx}"
        first_sev = first_finding.get("severity", "CRITICAL")
        label_name, label_color = get_severity_label_info(first_sev)
        runner_id = f"runner-{grp_idx}"

        file_display = os.path.basename(file_path) if file_path else "repository"
        display_title = (
            f"Fix in {file_display} for @{owner_name} ({len(items)} issues)"
            if owner_name != "unassigned"
            else f"Fix in {file_display} ({len(items)} issues)"
        )

        matrix.append({
            "task_index": grp_idx,
            "runner_id": runner_id,
            "runner_branch": f"codemender/patch-{owner_name}-{runner_id}",
            "owner": owner_name,
            "findings_count": len(items),
            "finding_id": first_fid,
            "short_id": short_id,
            "title": display_title,
            "severity": first_sev,
            "vuln_type": first_finding.get("vuln_type", "Vulnerability"),
            "file_path": file_path,
            "line": first_finding.get("line", 1),
            "label_name": label_name,
            "label_color": label_color,
            "finding_json_b64": finding_json_b64,
            "recommended_fixes_b64": rec_fixes_b64,
            "verify_first": verify_first,
        })
    return matrix


def generate_scan_matrix(
    findings_path: str,
    wiz_context_path: str = "",
    project_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Generates a parallel verification matrix from scan candidate findings, filtering out findings that already exist in Wiz."""
    raw = read_json_file(findings_path, [])
    items = raw if isinstance(raw, list) else raw.get("findings", []) if isinstance(raw, dict) else []

    # Load existing Wiz findings across all domains if available
    existing_wiz_findings: List[Dict[str, Any]] = []
    if wiz_context_path and os.path.exists(wiz_context_path):
        w_raw = read_json_file(wiz_context_path, {})
        if isinstance(w_raw, list):
            existing_wiz_findings = w_raw
        elif isinstance(w_raw, dict):
            for domain_key, domain_name in [
                ("penetration_tests", "PENETRATION_TEST"),
                ("sast_findings", "SAST"),
                ("vulnerabilities", "VULNERABILITY"),
                ("secrets", "SECRET"),
            ]:
                for item in w_raw.get(domain_key, []):
                    if isinstance(item, dict):
                        norm = dict(item)
                        norm["domain"] = domain_name
                        existing_wiz_findings.append(norm)

        if existing_wiz_findings:
            logger.info(f"Loaded {len(existing_wiz_findings)} open Wiz finding(s) across all domains for pre-verification deduplication.")

    matrix = []
    for idx, item in enumerate(items, 1):
        if not isinstance(item, dict):
            continue
        fid = str(first_of(item, "id", "FindingID", "finding_id", default=f"cand-{idx}")).strip()
        loc = item.get("location") if isinstance(item.get("location"), dict) else {}
        file_path = str(first_of(item, "file_path", "path", default=loc.get("path", ""))).lstrip("/")
        line = int(first_of(item, "line", "start_line", default=loc.get("line", 1)))
        title = str(first_of(item, "title", "description", default="Security Vulnerability")).strip()
        sev = str(item.get("severity") or "CRITICAL").upper()
        vuln_type = str(first_of(item, "vuln_type", "cwe", default="")).strip()
        snippet = str(first_of(item, "snippet", default="")).strip()
        analysis = str(first_of(item, "message", "description", "analysis", default="")).strip()
        short_id = fid[:8]

        # Pre-verification deduplication against existing Wiz findings via Gemini semantic reasoning
        if existing_wiz_findings:
            finding_title = f"[CodeMender] {title} in {file_path}" if file_path else f"[CodeMender] {title}"
            try:
                from ingest_wiz_pentest import find_semantic_match_with_gemini
                cand_dict = {
                    "title": finding_title,
                    "file_path": file_path,
                    "line": line,
                    "severity": sev,
                    "cwe": vuln_type,
                    "snippet": snippet,
                    "analysis": analysis,
                    "recommended_fixes": str(first_of(item, "recommended_fixes", "fixes", default="")),
                }
                matched_id = find_semantic_match_with_gemini(
                    candidate=cand_dict,
                    existing_findings=existing_wiz_findings,
                    project_id=project_id,
                )
                if matched_id:
                    matched_pt = next((p for p in existing_wiz_findings if p.get("id") == matched_id or p.get("name") == matched_id), {})
                    matched_name = matched_pt.get("name", matched_id)
                    matched_domain = matched_pt.get("domain", "Wiz")
                    logger.info(f"⏩ Scan candidate '{short_id}' semantically matches existing {matched_domain} finding {matched_id} ('{matched_name}'). Skipping verification job.")
                    continue
            except Exception as e:
                logger.debug(f"Pre-verification semantic check notice: {e}")

        logger.info(f"✅ Candidate '{short_id}' ({title} in {file_path or 'repo'}) confirmed new/untracked in Wiz. Added to verification matrix.")
        b64 = base64.b64encode(json.dumps(item).encode("utf-8")).decode("utf-8")
        matrix.append({
            "candidate_id": fid,
            "short_id": short_id,
            "title": title,
            "severity": sev,
            "file_path": file_path,
            "line": line,
            "candidate_json_b64": b64,
        })
    return matrix

