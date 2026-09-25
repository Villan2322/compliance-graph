"""Risk scoring: 5x5 likelihood x impact. Deterministic and explainable on
purpose — every point in the score has a stated reason an auditor can check."""
from __future__ import annotations

import hashlib
from collections import defaultdict

SEV_L = {"critical": 5, "high": 4, "medium": 3, "low": 2}
DATA_I = {"public": 2, "internal": 3, "confidential": 4, "restricted": 5, "regulated": 5}
HIGH_IMPACT_CWES = {"CWE-798", "CWE-259", "CWE-321", "CWE-89", "CWE-78", "CWE-94", "CWE-502", "CWE-306", "CWE-862"}


def rating(score: int) -> str:
    return "Critical" if score >= 20 else "High" if score >= 15 else "Medium" if score >= 8 else "Low"


def risk_id(repo_id: str, cwe: str) -> str:
    return "R-" + hashlib.sha1(f"{repo_id}|{cwe}".encode()).hexdigest()[:10]


def score_group(cwe: str, findings: list[dict], ctx: dict, cve_info: dict) -> tuple[int, int, list[str]]:
    why = []
    L = max(SEV_L.get(f["severity"], 3) for f in findings)
    why.append(f"likelihood {L} from highest finding severity")
    cves = {c for f in findings for c in f.get("cves", [])}
    if any(cve_info.get(c, {}).get("kev") for c in cves):
        L = 5
        why.append("likelihood 5: CVE is on CISA KEV (known exploited)")
    else:
        pct = max((cve_info.get(c, {}).get("epssPercentile") or 0) for c in cves) if cves else 0
        if pct >= 0.9:
            L = min(5, L + 1)
            why.append(f"likelihood +1: EPSS percentile {pct:.2f}")
    exposure = ctx.get("internet_facing")
    if exposure is True:
        L = min(5, L + 1) if L < 5 else L
        why.append("likelihood +1: internet-facing")
    elif exposure is False:
        L = max(1, L - 1)
        why.append("likelihood -1: not internet-facing")
    cls = str(ctx.get("data_classification", "internal")).lower()
    impact = DATA_I.get(cls, 3)
    why.append(f"impact {impact} from data classification '{cls}'")
    if cwe in HIGH_IMPACT_CWES and impact < 4:
        impact = 4
        why.append(f"impact raised to 4: {cwe} typically enables full compromise")
    return L, impact, why


def build_risks(state: dict) -> list[dict]:
    ctx, enr = state.get("context", {}), state.get("enrichment", {})
    groups: dict[str, list[dict]] = defaultdict(list)
    for f in state.get("findings", []):
        for c in (f["cwes"][:1] or ["UNMAPPED"]):  # primary CWE drives grouping
            groups[c].append(f)
    risks = []
    for cwe, fs in groups.items():
        info = enr.get("cwe", {}).get(cwe, {})
        L, I, why = score_group(cwe, fs, ctx, enr.get("cve", {}))
        s = L * I
        files = sorted({f["file"] for f in fs if f["file"]})
        name = info.get("name") or cwe
        asset = ctx.get("asset_name") or state.get("repo_id")
        controls = (info.get("direct") or [])[:4] + (info.get("threat") or [])[:3]
        risks.append({
            "riskId": risk_id(state["repo_id"], cwe), "cwe": cwe, "cweName": name,
            "statement": (f"{name} ({cwe}) in {len(fs)} location(s) of {asset} "
                          f"could let an attacker compromise the confidentiality, integrity, "
                          f"or availability of {ctx.get('data_description', 'the data it processes')}."),
            "findingIds": [f["findingId"] for f in fs], "files": files[:20],
            "tools": sorted({f["tool"] for f in fs}), "rules": sorted({f["ruleId"] for f in fs})[:10],
            "cves": sorted({c for f in fs for c in f.get("cves", [])})[:20],
            "likelihood": L, "impact": I, "score": s, "rating": rating(s), "scoringRationale": why,
            "controls": controls,
            "techniques": [t["attackId"] for t in (info.get("techniques") or [])][:8],
            "aiTechniques": [t["atlasId"] for t in (info.get("aiTechniques") or [])],
            "crosswalk": info.get("crosswalk", {}),
            "mappingReviewed": all(c.get("reviewed", True) for c in controls if c.get("path") == "direct"),
            "owner": ctx.get("control_owner", "Unassigned"),
            "status": "open", "decision": None,
        })
    return sorted(risks, key=lambda r: -r["score"])
