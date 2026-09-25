"""MITRE ATLAS (threats to AI/LLM systems) -> AITactic, AITechnique, AIMitigation."""
from __future__ import annotations

from pathlib import Path

import yaml

from ..ids import attack_technique


def parse(path: Path) -> dict:
    d = yaml.safe_load(Path(path).read_text())
    tactics, techniques, mitigations, mit_edges = [], [], [], []
    for m in d.get("matrices", []):
        for t in m.get("tactics", []):
            tactics.append({"atlasId": t["id"], "name": t["name"], "description": t.get("description", "")})
        for t in m.get("techniques", []):
            ref = t.get("ATT&CK-reference") or {}
            parent = t["id"].rsplit(".", 1)[0] if t["id"].count(".") >= 2 else None
            techniques.append({
                "atlasId": t["id"], "name": t["name"], "description": t.get("description", ""),
                "maturity": t.get("maturity"), "tactics": t.get("tactics", []),
                "attackRef": attack_technique(ref.get("id")) if ref else None, "parent": parent,
            })
        for mt in m.get("mitigations", []):
            mitigations.append({"atlasId": mt["id"], "name": mt["name"], "description": mt.get("description", "")})
            for tt in mt.get("techniques", []):
                mit_edges.append({"m": mt["id"], "t": tt["id"], "use": (tt.get("use") or "").strip()})
    return {"tactics": tactics, "techniques": techniques, "mitigations": mitigations,
            "mitigates": mit_edges, "version": d.get("version")}


def load(graph, data: dict, spec) -> dict:
    sid = spec.id
    graph.batch("""UNWIND $rows AS r MERGE (t:AITactic {atlasId: r.atlasId})
        SET t.name = r.name, t.description = r.description, t.sourceId = $sid, t.ingestedAt = datetime()""",
        data["tactics"], sid=sid)
    graph.batch("""UNWIND $rows AS r MERGE (t:AITechnique {atlasId: r.atlasId})
        SET t.name = r.name, t.description = r.description, t.maturity = r.maturity,
            t.sourceId = $sid, t.ingestedAt = datetime(), t.isActive = true
        WITH t, r UNWIND r.tactics AS ta MATCH (x:AITactic {atlasId: ta})
        MERGE (t)-[e:IN_TACTIC]->(x) SET e.sourceId = $sid""", data["techniques"], sid=sid)
    graph.batch("""UNWIND $rows AS r MATCH (c:AITechnique {atlasId: r.atlasId}), (p:AITechnique {atlasId: r.parent})
        MERGE (c)-[e:SUBTECHNIQUE_OF]->(p) SET e.sourceId = $sid""",
        [t for t in data["techniques"] if t["parent"]], sid=sid)
    graph.batch("""UNWIND $rows AS r MATCH (a:AITechnique {atlasId: r.atlasId}), (t:Technique {attackId: r.attackRef})
        MERGE (a)-[e:MAPS_TO]->(t) SET e.sourceId = $sid""",
        [t for t in data["techniques"] if t["attackRef"]], sid=sid)
    graph.batch("""UNWIND $rows AS r MERGE (m:AIMitigation {atlasId: r.atlasId})
        SET m.name = r.name, m.description = r.description, m.sourceId = $sid, m.ingestedAt = datetime()""",
        data["mitigations"], sid=sid)
    graph.batch("""UNWIND $rows AS r MATCH (m:AIMitigation {atlasId: r.m}), (t:AITechnique {atlasId: r.t})
        MERGE (m)-[e:MITIGATES]->(t) SET e.sourceId = $sid, e.use = r.use""", data["mitigates"], sid=sid)
    return {k: len(v) for k, v in data.items() if isinstance(v, list)} | {"atlasVersion": data["version"]}
