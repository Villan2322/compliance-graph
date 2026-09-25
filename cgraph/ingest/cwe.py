"""MITRE CWE XML -> (:Weakness) with CHILD_OF hierarchy (Research view 1000)."""
from __future__ import annotations

from pathlib import Path

from ..ids import cwe
from ._xml import open_xml, text


def parse(path: Path) -> dict:
    root = open_xml(path)
    weaknesses, child_of = [], []
    for w in root.iter("Weakness"):
        cid = cwe(w.get("ID"))
        status = w.get("Status", "")
        weaknesses.append({
            "cweId": cid, "name": w.get("Name", ""), "abstraction": w.get("Abstraction", ""),
            "status": status, "isActive": status not in ("Deprecated", "Obsolete"),
            "description": text(w.find("Description")),
            "extended": text(w.find("Extended_Description"))[:4000],
        })
        for r in w.iter("Related_Weakness"):
            if r.get("Nature") == "ChildOf" and r.get("View_ID") == "1000":
                child_of.append({"child": cid, "parent": cwe(r.get("CWE_ID")),
                                 "primary": r.get("Ordinal") == "Primary"})
    return {"weaknesses": weaknesses, "child_of": child_of, "version": root.get("Version")}


def load(graph, data: dict, spec) -> dict:
    graph.batch("""
        UNWIND $rows AS r MERGE (w:Weakness {cweId: r.cweId})
        SET w.name = r.name, w.abstraction = r.abstraction, w.status = r.status,
            w.isActive = r.isActive, w.description = r.description, w.extended = r.extended,
            w.sourceId = $sid, w.ingestedAt = datetime(), w.lastVerifiedAt = datetime()""",
        data["weaknesses"], sid=spec.id)
    graph.batch("""
        UNWIND $rows AS r
        MATCH (c:Weakness {cweId: r.child}), (p:Weakness {cweId: r.parent})
        MERGE (c)-[x:CHILD_OF]->(p) SET x.sourceId = $sid, x.primary = r.primary""",
        data["child_of"], sid=spec.id)
    return {"weaknesses": len(data["weaknesses"]), "childOf": len(data["child_of"]), "cweVersion": data["version"]}
