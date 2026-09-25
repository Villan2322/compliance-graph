"""CISA KEV -> (:Vulnerability {kev:true})-[:HAS_WEAKNESS]->(:Weakness)."""
from __future__ import annotations

import json
from pathlib import Path

from ..ids import cve, cwe


def parse(path: Path) -> dict:
    d = json.loads(Path(path).read_text())
    rows = []
    for v in d.get("vulnerabilities", []):
        cid = cve(v.get("cveID"))
        if not cid:
            continue
        rows.append({
            "cveId": cid, "vendor": v.get("vendorProject", ""), "product": v.get("product", ""),
            "name": v.get("vulnerabilityName", ""), "description": v.get("shortDescription", ""),
            "dateAdded": v.get("dateAdded"), "dueDate": v.get("dueDate"),
            "requiredAction": v.get("requiredAction", ""),
            "ransomware": (v.get("knownRansomwareCampaignUse") or "").lower() == "known",
            "cwes": [c for c in (cwe(x) for x in v.get("cwes", [])) if c],
        })
    return {"vulns": rows, "catalogVersion": d.get("catalogVersion")}


def load(graph, data: dict, spec) -> dict:
    graph.run("MATCH (v:Vulnerability {kev: true}) SET v.kev = false, v.kevRemoved = true")
    n = graph.batch("""
        UNWIND $rows AS r MERGE (v:Vulnerability {cveId: r.cveId})
        SET v.kev = true, v.kevRemoved = null, v.vendor = r.vendor, v.product = r.product,
            v.name = r.name, v.description = r.description,
            v.kevDateAdded = date(r.dateAdded), v.kevDueDate = date(r.dueDate),
            v.requiredAction = r.requiredAction, v.ransomware = r.ransomware,
            v.sourceId = $sid, v.lastVerifiedAt = datetime()
        WITH v, r UNWIND r.cwes AS c MATCH (w:Weakness {cweId: c})
        MERGE (v)-[x:HAS_WEAKNESS]->(w) SET x.sourceId = $sid""", data["vulns"], sid=spec.id)
    return {"kev": n, "catalogVersion": data["catalogVersion"]}
