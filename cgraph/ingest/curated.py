"""Our own layer: CWE -> control mappings, detection rules, and secure-coding
topics. This is the part no upstream publishes, and the part to review hardest."""
from __future__ import annotations

from pathlib import Path

import yaml

from ..config import ROOT
from ..ids import attack_technique, capec, cwe, nist_req


def _semgrep_rules() -> list[dict]:
    out = []
    for f in sorted((ROOT / "rules" / "semgrep").glob("*.y*ml")):
        for r in (yaml.safe_load(f.read_text()) or {}).get("rules", []):
            meta = r.get("metadata", {})
            cwes = meta.get("cwe", [])
            cwes = [cwes] if isinstance(cwes, str) else cwes
            out.append({"ruleId": f"semgrep:{r['id']}", "tool": "semgrep", "severity": r.get("severity", "WARNING"),
                        "message": " ".join(str(r.get("message", "")).split()),
                        "cwes": [c for c in (cwe(x) for x in cwes) if c], "file": f.name})
    # Built-in mappings for non-Semgrep scanners.
    out.append({"ruleId": "gitleaks:*", "tool": "gitleaks", "severity": "ERROR",
                "message": "Secret committed to source", "cwes": ["CWE-798"], "file": ""})
    out.append({"ruleId": "osv:*", "tool": "osv-scanner", "severity": "WARNING",
                "message": "Dependency with known vulnerability", "cwes": ["CWE-1395"], "file": ""})
    return out


def parse(path: Path | None = None) -> dict:
    cm = yaml.safe_load((ROOT / "mappings" / "cwe_to_controls.yaml").read_text())
    edges = []
    for m in cm["mappings"]:
        w = cwe(m["cwe"])
        for c in m["controls"]:
            edges.append({"cwe": w, "req": nist_req(c["id"]), "confidence": float(c.get("confidence", 0.7)),
                          "rationale": c.get("why", ""), "reviewed": bool(m.get("reviewed", False))})
    topics = yaml.safe_load((ROOT / "mappings" / "secure_coding_topics.yaml").read_text())["topics"]
    atlas = [{"cwe": cwe(x["cwe"]), "atlas": x["atlas"], "why": x.get("why", "")}
             for x in yaml.safe_load((ROOT / "mappings" / "cwe_to_atlas.yaml").read_text())["links"]]
    capec_attack = [{"capec": capec(x["capec"]), "tech": attack_technique(x["attack"]), "why": x.get("why", "")}
                     for x in yaml.safe_load((ROOT / "mappings" / "capec_to_attack.yaml").read_text())["links"]]
    return {"edges": edges, "rules": _semgrep_rules(), "topics": topics, "atlas": atlas,
            "capecAttack": capec_attack, "version": cm.get("version")}


def load(graph, data: dict, spec) -> dict:
    sid = spec.id
    missing = graph.run("""
        UNWIND $rows AS r
        OPTIONAL MATCH (w:Weakness {cweId: r.cwe}) OPTIONAL MATCH (q:Requirement {reqId: r.req})
        WITH r WHERE w IS NULL OR q IS NULL RETURN r.cwe AS cwe, r.req AS req""", rows=data["edges"])
    n = graph.batch("""
        UNWIND $rows AS r
        MATCH (w:Weakness {cweId: r.cwe}), (q:Requirement {reqId: r.req})
        MERGE (w)-[x:ADDRESSED_BY]->(q)
        SET x.sourceId = $sid, x.confidence = r.confidence, x.rationale = r.rationale,
            x.reviewed = r.reviewed, x.authority = 'cgraph-curated', x.establishedAt = datetime(),
            x.flaggedForReview = NOT r.reviewed""", data["edges"], sid=sid)
    graph.batch("""
        UNWIND $rows AS r MERGE (d:DetectionRule {ruleId: r.ruleId})
        SET d.tool = r.tool, d.severity = r.severity, d.message = r.message, d.file = r.file,
            d.sourceId = $sid, d.ingestedAt = datetime()
        WITH d, r UNWIND r.cwes AS c MATCH (w:Weakness {cweId: c})
        MERGE (d)-[x:DETECTS]->(w) SET x.sourceId = $sid""", data["rules"], sid=sid)
    graph.batch("""
        UNWIND $rows AS r MERGE (t:SecureCodingTopic {topicId: r.id})
        SET t.name = r.name, t.keywords = r.keywords, t.guidance = r.guidance, t.sourceId = $sid
        WITH t, r UNWIND r.cwes AS c MATCH (w:Weakness {cweId: c})
        MERGE (t)-[x:CONCERNS]->(w) SET x.sourceId = $sid""", data["topics"], sid=sid)
    graph.batch("""
        UNWIND $rows AS r MATCH (w:Weakness {cweId: r.cwe}), (a:AITechnique {atlasId: r.atlas})
        MERGE (w)-[x:RELATES_TO]->(a)
        SET x.sourceId = $sid, x.rationale = r.why, x.reviewed = false, x.authority = 'cgraph-curated'""",
        data["atlas"], sid=sid)
    graph.batch("""
        UNWIND $rows AS r MATCH (a:AttackPattern {capecId: r.capec}), (t:Technique {attackId: r.tech})
        MERGE (a)-[x:MAPS_TO]->(t)
        SET x.sourceId = $sid, x.rationale = r.why, x.reviewed = false, x.authority = 'cgraph-curated'""",
        data["capecAttack"], sid=sid)
    return {"cweToControl": n, "cweToAtlas": len(data["atlas"]), "rules": len(data["rules"]), "topics": len(data["topics"]),
            "capecToAttack": len(data["capecAttack"]), "unresolved": len(missing), "version": data.get("version")}
