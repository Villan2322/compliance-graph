"""CTID Mappings Explorer: NIST 800-53 r5 controls that mitigate ATT&CK techniques."""
from __future__ import annotations

import json
from pathlib import Path

from ..ids import attack_technique, nist_req


def parse(path: Path) -> dict:
    d = json.loads(Path(path).read_text())
    rows = []
    for o in d["mapping_objects"]:
        if o.get("status") != "complete" or o.get("mapping_type") != "mitigates":
            continue
        req, tech = nist_req(o.get("capability_id") or ""), attack_technique(o.get("attack_object_id"))
        if req and tech:
            rows.append({"req": req, "tech": tech, "comment": o.get("comments") or ""})
    return {"mitigates": rows, "attackVersion": d["metadata"].get("attack_version")}


def load(graph, data: dict, spec) -> dict:
    n = graph.batch("""
        UNWIND $rows AS r
        MATCH (q:Requirement {reqId: r.req}), (t:Technique {attackId: r.tech})
        MERGE (q)-[x:MITIGATES]->(t)
        SET x.sourceId = $sid, x.rationale = r.comment, x.mappingType = 'mitigates',
            x.authority = 'ctid', x.confidence = 0.9, x.establishedAt = datetime()""",
        data["mitigates"], sid=spec.id)
    return {"edges": n, "attackVersion": data["attackVersion"]}
