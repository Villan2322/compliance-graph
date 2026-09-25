"""Scanner adapters. Each returns normalized findings; a missing binary is a
warning, not a crash, so the loop still runs on a laptop with only Semgrep."""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..config import ROOT
from ..ids import cve, cwe

SEV = {"critical": "critical", "high": "high", "error": "high", "medium": "medium", "moderate": "medium",
       "warning": "medium", "low": "low", "info": "low", "inventory": "low"}


def _fid(*parts) -> str:
    return "F-" + hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()[:16]


def _rel(target: Path, p: str) -> str:
    try:
        return str(Path(p).resolve().relative_to(target.resolve()))
    except ValueError:
        return p


def semgrep(target: Path, extra_configs: str = "") -> tuple[list[dict], list[str]]:
    if not shutil.which("semgrep"):
        return [], ["semgrep not installed: static analysis skipped"]
    cmd = ["semgrep", "scan", "--json", "--quiet", "--metrics=off", "--config", str(ROOT / "rules" / "semgrep")]
    for c in extra_configs.split():
        cmd += ["--config", c]
    cmd.append(str(target))
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    try:
        data = json.loads(p.stdout or "{}")
    except json.JSONDecodeError:
        return [], [f"semgrep output unreadable (exit {p.returncode}): {p.stderr[-300:]}"]
    out = []
    for r in data.get("results", []):
        meta = r.get("extra", {}).get("metadata", {})
        cw = meta.get("cwe", [])
        cw = [cw] if isinstance(cw, str) else cw
        tail = r["check_id"].rsplit(".", 1)[-1]
        rule = tail if tail.startswith("cg-") else r["check_id"]  # our rules: short id; registry: full id
        f, line = _rel(target, r["path"]), r["start"]["line"]
        out.append({
            "findingId": _fid("semgrep", rule, f, line), "tool": "semgrep", "ruleId": rule,
            "ruleKey": f"semgrep:{rule}", "title": " ".join(r["extra"].get("message", "").split())[:300],
            "severity": SEV.get(r["extra"].get("severity", "").lower(), "medium"),
            "file": f, "line": line, "cwes": [c for c in (cwe(x) for x in cw) if c], "cves": [],
            "package": None, "cweSource": "rule-metadata",
        })
    warns = [f"semgrep: {e.get('message', '')[:200]}" for e in data.get("errors", [])[:5]]
    return out, warns


def gitleaks(target: Path) -> tuple[list[dict], list[str]]:
    if not shutil.which("gitleaks"):
        return [], ["gitleaks not installed: secret scanning skipped"]
    with tempfile.TemporaryDirectory() as td:
        rpt = Path(td) / "gl.json"
        base = ["--report-format", "json", "--report-path", str(rpt), "--exit-code", "0", "--redact", "--no-banner"]
        p = subprocess.run(["gitleaks", "dir", *base, str(target)], capture_output=True, text=True, timeout=900)
        if p.returncode != 0 or not rpt.exists():  # older gitleaks without `dir`
            subprocess.run(["gitleaks", "detect", "--no-git", "--source", str(target), *base],
                           capture_output=True, text=True, timeout=900)
        data = json.loads(rpt.read_text() or "[]") if rpt.exists() else []
    out = []
    for r in data:
        f, line = _rel(target, r.get("File", "")), r.get("StartLine", 0)
        out.append({
            "findingId": _fid("gitleaks", r.get("RuleID"), f, line), "tool": "gitleaks",
            "ruleId": r.get("RuleID", "secret"), "ruleKey": "gitleaks:*",
            "title": f"Secret detected: {r.get('Description', r.get('RuleID', ''))}",
            "severity": "high", "file": f, "line": line, "cwes": ["CWE-798"], "cves": [],
            "package": None, "cweSource": "tool-default",
        })
    return out, []


def osv(target: Path) -> tuple[list[dict], list[str]]:
    if not shutil.which("osv-scanner"):
        return [], ["osv-scanner not installed: dependency scanning skipped"]
    p = subprocess.run(["osv-scanner", "scan", "source", "-r", "--format", "json", str(target)],
                       capture_output=True, text=True, timeout=1800)
    if p.returncode not in (0, 1):
        return [], [f"osv-scanner exit {p.returncode}: {p.stderr[-300:]}"]
    try:
        data = json.loads(p.stdout or "{}")
    except json.JSONDecodeError:
        return [], ["osv-scanner output unreadable"]
    out = []
    for res in data.get("results", []):
        src = _rel(target, res.get("source", {}).get("path", ""))
        for pkg in res.get("packages", []):
            meta = pkg.get("package", {})
            name, ver, eco = meta.get("name"), meta.get("version"), meta.get("ecosystem", "")
            purl = f"pkg:{eco.lower()}/{name}@{ver}"
            sev_by_id = {i: g.get("max_severity") for g in pkg.get("groups", []) for i in g.get("ids", [])}
            for v in pkg.get("vulnerabilities", []):
                ids = [v.get("id", "")] + v.get("aliases", [])
                cves = sorted({c for c in (cve(i) for i in ids) if c})
                try:
                    score = float(sev_by_id.get(v.get("id")) or 0)
                except ValueError:
                    score = 0.0
                sev = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
                cw = [cwe(x) for x in (v.get("database_specific", {}) or {}).get("cwe_ids", [])]
                out.append({
                    "findingId": _fid("osv", v.get("id"), purl), "tool": "osv-scanner", "ruleId": v.get("id"),
                    "ruleKey": "osv:*", "title": f"{name} {ver}: {v.get('summary') or v.get('id')}"[:300],
                    "severity": sev, "file": src, "line": 0,
                    "cwes": ["CWE-1395"] + [c for c in cw if c], "cves": cves, "package": purl,
                    "cweSource": "tool-default",
                })
    return out, []


SCANNERS = {"semgrep": semgrep, "gitleaks": gitleaks, "osv-scanner": osv}
