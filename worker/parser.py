#!/usr/bin/env python3
"""
Issue & Candidate Finding Parser:
- Extracts JSON structures from markdown fences, escaped strings, or raw text
- Normalizes downstream agent output into CodeMender findings & recommended fixes
- Provides deterministic regex fallback for plain-text vulnerability reports
"""

import ast
import hashlib
import json
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from common import clean_file_path, first_of, load_json_loose
from logger import get_logger

logger = get_logger("codemender-parser")


def extract_json_candidates(text: str) -> List[Any]:
    """Extracts valid JSON objects or arrays from text, markdown fences, or raw strings."""
    if not text or not text.strip():
        return []

    direct = load_json_loose(text)
    if isinstance(direct, (dict, list)):
        logger.debug("Parsed entire text as direct JSON payload.")
        return [direct]

    fence_candidates = []
    for fm in re.findall(r"```(?:json)?\s*([\s\S]*?)\s*```", text, re.IGNORECASE):
        parsed = load_json_loose(fm)
        if isinstance(parsed, (dict, list)):
            fence_candidates.append(parsed)
    if fence_candidates:
        logger.debug(f"Extracted {len(fence_candidates)} candidate structure(s) from markdown fences.")
        return fence_candidates

    # Scan for embedded balanced JSON objects ({ ... })
    candidates: List[Any] = []
    idx = 0
    while idx < len(text):
        start = text.find("{", idx)
        if start == -1:
            break
        depth, in_str, escape, end = 0, False, False, -1
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_str = False
            elif ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        if end != -1:
            parsed = load_json_loose(text[start:end])
            if isinstance(parsed, dict) and parsed not in candidates:
                candidates.append(parsed)
            idx = end
        else:
            idx = start + 1
    return candidates


def parse_downstream_agent_output(
    candidates: List[Any],
    repo: str = "unknown",
    workspace_dir: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Extracts and deduplicates findings and recommended fixes from structured candidates."""
    findings: List[Dict[str, Any]] = []
    fixes: List[Dict[str, Any]] = []
    seen_signatures: Set[str] = set()

    for obj in candidates:
        if isinstance(obj, list):
            raw_items = obj
        elif isinstance(obj, dict):
            ar = first_of(obj, "actionResult", "action_result", default=None)
            container = ar if isinstance(ar, dict) else obj
            so = first_of(container, "structuredOutput", "structured_output", default=container)
            raw_items = so if isinstance(so, list) else [so] if isinstance(so, dict) else []
        else:
            continue

        for item in raw_items:
            if not isinstance(item, dict):
                continue
            has_file = any(k in item for k in ("file_path", "filePath", "file", "path"))
            has_vuln = any(k in item for k in ("vuln_type", "recommended_fixes", "severity", "title", "message"))
            if not (has_file or has_vuln):
                continue

            item_copy = dict(item)
            clean_path = clean_file_path(first_of(item_copy, "file_path", "filePath", "path", "file"))
            item_copy["file_path"] = clean_path
            for k in ("filePath", "path", "file", "conversationId", "conversation_id", "actionResult", "action_result"):
                item_copy.pop(k, None)

            try:
                line = int(first_of(item_copy, "line", "start_line", default=1))
            except (ValueError, TypeError):
                line = 1
            item_copy["line"] = item_copy["start_line"] = line
            try:
                item_copy["end_line"] = int(item_copy.get("end_line") or line)
            except (ValueError, TypeError):
                item_copy["end_line"] = line

            title = str(item_copy.get("title") or "Security Vulnerability").strip()
            item_copy["title"] = title

            sig = f"{clean_path}:{line}:{title.lower()}"
            if sig in seen_signatures:
                logger.debug(f"Skipping duplicate finding signature: {sig}")
                continue
            seen_signatures.add(sig)

            owner_val = str(item_copy.get("owner") or "").strip().lstrip("@")
            item_copy["owner"] = owner_val

            rec_fixes = item_copy.get("recommended_fixes") or ""
            if isinstance(rec_fixes, list):
                rec_fixes_str = "\n".join(str(x) for x in rec_fixes).strip()
            elif isinstance(rec_fixes, dict):
                rec_fixes_str = json.dumps(rec_fixes, indent=2).strip()
            else:
                rec_fixes_str = str(rec_fixes).strip()

            item_copy["recommended_fixes"] = rec_fixes_str

            sev = str(item_copy.get("severity") or "CRITICAL").strip().upper()
            vuln_type = str(first_of(item_copy, "vuln_type", "cwe", "vuln_id", default="Vulnerability")).strip()
            msg = str(first_of(item_copy, "message", "explanation", default=f"{title} in {clean_path}")).strip()
            fid = hashlib.sha256(f"{repo}:{clean_path}:{line}:{title}".lower().encode("utf-8")).hexdigest()[:8]

            snippet = first_of(item_copy, "snippet", "vulnerable_snippet", "current_code")
            if not snippet and workspace_dir and clean_path:
                full_path = os.path.join(workspace_dir, clean_path)
                if os.path.isfile(full_path):
                    try:
                        with open(full_path, "r", encoding="utf-8", errors="ignore") as sf:
                            lines = sf.readlines()
                        s_idx = max(0, line - 1)
                        snippet = "".join(lines[s_idx : min(len(lines), s_idx + 5)]).strip()
                    except Exception:
                        pass
            snippet = snippet or f"// Vulnerable code in {clean_path} at line {line}"

            item_copy.update({
                "id": fid,
                "severity": sev,
                "vuln_type": vuln_type,
                "message": msg,
                "snippet": snippet,
                "vulnerable_snippet": snippet,
                "recommended_fixes": rec_fixes_str,
            })
            findings.append(item_copy)
            fixes.append({
                "finding_id": fid,
                "file_path": clean_path,
                "line": line,
                "title": title,
                "severity": sev,
                "vuln_type": vuln_type,
                "owner": owner_val,
                "recommended_fixes": rec_fixes_str,
            })
            logger.debug(f"Parsed finding [{sev}] {fid}: {title} at {clean_path}:{line}")

    logger.info(f"Extracted {len(findings)} structured finding(s) and {len(fixes)} fix recommendation(s).")
    return findings, fixes


def parse_fallback_patterns(text: str, repo: str = "unknown") -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Lightweight deterministic fallback for unformatted text issue bodies."""
    m_pkg = re.search(
        r"File:\s*[`\"']?([^\s,`\"']+)[`\"']?,\s*lines?\s*(\d+)(?:\s*(?:and|-)\s*(\d+)(?:-(\d+))?)?",
        text,
        re.IGNORECASE,
    )
    if not m_pkg:
        return [], []

    fpath = clean_file_path(m_pkg.group(1))
    s_line = int(m_pkg.group(2))
    e_line = int(m_pkg.group(4) or m_pkg.group(3) or s_line)

    m_fix = re.search(r"Fixed code:\s*\n?(.*?)(?=\n\s*Explanation:|$)", text, re.DOTALL | re.IGNORECASE)
    fix_code = m_fix.group(1).strip() if m_fix else ""
    m_exp = re.search(r"Explanation:\s*(.*)", text, re.DOTALL | re.IGNORECASE)
    expl = m_exp.group(1).strip() if m_exp else ""
    rec_text = f"{fix_code}\n\n{expl}".strip()

    m_cve = re.search(r"(CVE-\d{4}-\d+)", f"{expl} {text}")
    title = f"Vulnerable Dependency ({m_cve.group(1)})" if m_cve else "Vulnerable Dependency"
    cwe = m_cve.group(1) if m_cve else "Vulnerability"
    sev = "CRITICAL" if "critical" in text.lower() else "HIGH"
    fid = hashlib.sha256(f"{repo}:{fpath}:{s_line}:{title}".lower().encode("utf-8")).hexdigest()[:8]
    snippet = f"// Vulnerable code in {fpath} at line {s_line}"

    finding = {
        "id": fid,
        "file_path": fpath,
        "line": s_line,
        "start_line": s_line,
        "end_line": e_line,
        "title": title,
        "message": expl or f"Vulnerability detected in {fpath}",
        "severity": sev,
        "vuln_type": cwe,
        "snippet": snippet,
        "vulnerable_snippet": snippet,
        "recommended_fixes": rec_text,
    }
    fix = {
        "finding_id": fid,
        "file_path": fpath,
        "line": s_line,
        "title": title,
        "severity": sev,
        "vuln_type": cwe,
        "recommended_fixes": rec_text,
    }
    return [finding], [fix]


def normalize_candidate_findings(raw_text: str, default_vuln_id: str = "") -> List[Dict[str, Any]]:
    """Normalizes candidate discovery payloads (JSON, escaped strings, or Python literals) for cm report import."""
    data = load_json_loose(raw_text)
    if data is None:
        for candidate in (raw_text, raw_text.replace("\r\n", "\\n").replace("\n", "\\n")):
            try:
                data = ast.literal_eval(candidate)
                break
            except Exception:
                pass
    raw_items = data if isinstance(data, list) else [data] if data else []
    normalized = []
    for it in raw_items:
        if not isinstance(it, dict):
            continue
        title = str(first_of(it, "title", "Title", default="Security Flaw"))
        snip = str(first_of(it, "snippet", "Snippet", "vulnerable_snippet", default=f"// {title}"))
        normalized.append({
            "id": str(first_of(it, "id", "finding_id", "FindingID", "vuln_id", "VulnID", default=default_vuln_id)),
            "file_path": clean_file_path(first_of(it, "file_path", "FilePath", "path")),
            "line": int(first_of(it, "line", "start_line", "StartLine", default=1)),
            "title": title,
            "severity": str(first_of(it, "severity", "Severity", default="CRITICAL")),
            "message": str(first_of(it, "message", "description", "analysis", default=title)),
            "vuln_type": str(first_of(it, "vuln_type", "VulnType", default="Vulnerability")),
            "snippet": snip,
            "vulnerable_snippet": snip,
            "recommended_fixes": str(it.get("recommended_fixes") or "").strip(),
        })
    logger.info(f"Normalized {len(normalized)} candidate finding(s) for CodeMender verification/import.")
    return normalized
