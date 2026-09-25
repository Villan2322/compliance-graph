"""MITRE CAPEC XML -> (:AttackPattern)-[:EXPLOITS]->(:Weakness), -[:MAPS_TO]->(:Technique).
This is the bridge that connects a code weakness to adversary behavior."""
from __future__ import annotations

from pathlib import Path

from ..ids import attack_technique, capec, cwe
from ._xml import open_xml, text


def parse(path: Path) -> dict:
    root = open_xml(path)
    patterns, exploits, maps = [], [], []
    for a in root.iter("Attack_Pattern"):
        status = a.get("Status", "")
        if status == "Deprecated":
            continue
        cid = capec(a.get("ID"))
        patterns.append({
            "capecId": cid, "name": a.get("Name", ""), "abstraction": a.get("Abstraction", ""),
            "status": status, "description": text(a.find("Description")),
            "likelihood": text(a.find("Likelihood_Of_Attack")),
            "severity": text(a.find("Typical_Severity")),
        })
        for r in a.iter("Related_Weakness"):
            exploits.append({"capec": cid, "cwe": cwe(r.get("CWE_ID"))})
        for m in a.iter("Taxonomy_Mapping"):
            if (m.get("Taxonomy_Name") or "").upper() == "ATTACK":
                t = attack_technique(text(m.find("Entry_ID")))
                if t:
                    maps.append({"capec": cid, "tech": t})
    return {"patterns": patterns, "exploits": exploits, "maps": maps, "version": root.get("Version")}


def load(graph, data: dict, spec) -> dict:
    sid = spec.id
    graph.batch("""
        UNWIND $rows AS r MERGE (a:AttackPattern {capecId: r.capecId})
        SET a.name = r.name, a.abstraction = r.abstraction, a.status = r.status,
            a.description = r.description, a.likelihood = r.likelihood, a.severity = r.severity,
            a.sourceId = $sid, a.ingestedAt = datetime(), a.isActive = true""", data["patterns"], sid=sid)
    e = graph.batch("""
        UNWIND $rows AS r MATCH (a:AttackPattern {capecId: r.capec}), (w:Weakness {cweId: r.cwe})
        MERGE (a)-[x:EXPLOITS]->(w) SET x.sourceId = $sid""", data["exploits"], sid=sid)
    m = graph.batch("""
        UNWIND $rows AS r MATCH (a:AttackPattern {capecId: r.capec}), (t:Technique {attackId: r.tech})
        MERGE (a)-[x:MAPS_TO]->(t) SET x.sourceId = $sid""", data["maps"], sid=sid)
    return {"patterns": len(data["patterns"]), "exploits": e, "attackMaps": m, "capecVersion": data["version"]}
