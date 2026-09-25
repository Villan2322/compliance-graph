"""MITRE ATT&CK Enterprise STIX 2.1 -> Tactic, Technique, Mitigation and their edges."""
from __future__ import annotations

import json
from pathlib import Path


def _ext_id(obj: dict) -> str | None:
    for r in obj.get("external_references", []):
        if r.get("source_name") == "mitre-attack":
            return r.get("external_id")
    return None


def _live(obj: dict) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def parse(path: Path) -> dict:
    bundle = json.loads(Path(path).read_text())
    objs = bundle["objects"]
    stix_to_ext: dict[str, str] = {}
    tactics, techniques, mitigations = [], [], []
    version = None
    for o in objs:
        t = o.get("type")
        if t == "x-mitre-collection":
            version = o.get("x_mitre_version")
        if not _live(o):
            continue
        ext = _ext_id(o)
        if not ext:
            continue
        stix_to_ext[o["id"]] = ext
        if t == "x-mitre-tactic":
            tactics.append({"attackId": ext, "name": o["name"], "shortname": o.get("x_mitre_shortname"),
                            "description": o.get("description", "")})
        elif t == "attack-pattern":
            techniques.append({
                "attackId": ext, "name": o["name"], "description": o.get("description", ""),
                "isSubtechnique": bool(o.get("x_mitre_is_subtechnique")),
                "platforms": o.get("x_mitre_platforms", []),
                "tactics": [k["phase_name"] for k in o.get("kill_chain_phases", [])
                            if k.get("kill_chain_name") == "mitre-attack"],
                "detection": o.get("x_mitre_detection", ""),
            })
        elif t == "course-of-action":
            mitigations.append({"attackId": ext, "name": o["name"], "description": o.get("description", "")})
    mitigates, subs = [], []
    for o in objs:
        if o.get("type") != "relationship" or not _live(o):
            continue
        s, d = stix_to_ext.get(o["source_ref"]), stix_to_ext.get(o["target_ref"])
        if not s or not d:
            continue
        if o["relationship_type"] == "mitigates" and s.startswith("M") and d.startswith("T"):
            mitigates.append({"m": s, "t": d, "note": o.get("description", "")})
        elif o["relationship_type"] == "subtechnique-of":
            subs.append({"child": s, "parent": d})
    return {"tactics": tactics, "techniques": techniques, "mitigations": mitigations,
            "mitigates": mitigates, "subtechnique_of": subs, "version": version}


def load(graph, data: dict, spec) -> dict:
    sid = spec.id
    graph.batch("""
        UNWIND $rows AS r MERGE (t:Tactic {attackId: r.attackId})
        SET t.name = r.name, t.shortname = r.shortname, t.description = r.description,
            t.sourceId = $sid, t.ingestedAt = datetime(), t.isActive = true""", data["tactics"], sid=sid)
    graph.batch("""
        UNWIND $rows AS r MERGE (t:Technique {attackId: r.attackId})
        SET t.name = r.name, t.description = r.description, t.isSubtechnique = r.isSubtechnique,
            t.platforms = r.platforms, t.detection = r.detection,
            t.sourceId = $sid, t.ingestedAt = datetime(), t.isActive = true
        WITH t, r UNWIND r.tactics AS sn
        MATCH (ta:Tactic {shortname: sn})
        MERGE (t)-[x:IN_TACTIC]->(ta) SET x.sourceId = $sid""", data["techniques"], sid=sid)
    graph.batch("""
        UNWIND $rows AS r MERGE (m:Mitigation {attackId: r.attackId})
        SET m.name = r.name, m.description = r.description,
            m.sourceId = $sid, m.ingestedAt = datetime(), m.isActive = true""", data["mitigations"], sid=sid)
    graph.batch("""
        UNWIND $rows AS r
        MATCH (m:Mitigation {attackId: r.m}), (t:Technique {attackId: r.t})
        MERGE (m)-[x:MITIGATES]->(t) SET x.sourceId = $sid, x.note = r.note""", data["mitigates"], sid=sid)
    graph.batch("""
        UNWIND $rows AS r
        MATCH (c:Technique {attackId: r.child}), (p:Technique {attackId: r.parent})
        MERGE (c)-[x:SUBTECHNIQUE_OF]->(p) SET x.sourceId = $sid""", data["subtechnique_of"], sid=sid)
    return {k: len(v) for k, v in data.items() if isinstance(v, list)} | {"attackVersion": data.get("version")}
