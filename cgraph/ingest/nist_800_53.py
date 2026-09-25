"""NIST SP 800-53 r5 from OSCAL JSON -> (:Requirement)-[:PART_OF]->(:Framework)."""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..ids import nist_80053

FW = "NIST-800-53-r5"
_INSERT = re.compile(r"\{\{\s*insert:\s*param,\s*([\w.\-]+)\s*\}\}")


def _label(ctrl: dict) -> str:
    for p in ctrl.get("props", []):
        if p.get("name") == "label" and p.get("class") not in ("zero-padded", "sp800-53a"):
            return p["value"]
    return nist_80053(ctrl["id"]) or ctrl["id"].upper()


def _params(ctrl: dict) -> dict[str, str]:
    out = {}
    for p in ctrl.get("params", []):
        if p.get("label"):
            out[p["id"]] = f"[Assignment: {p['label']}]"
        elif p.get("select"):
            out[p["id"]] = "[Selection: " + "; ".join(map(str, p["select"].get("choice", []))) + "]"
        else:
            out[p["id"]] = "[Assignment]"
    return out


def _prose(part: dict, params: dict[str, str], depth: int = 0) -> str:
    label = next((p["value"] for p in part.get("props", []) if p.get("name") == "label"), "")
    text = part.get("prose", "")
    text = _INSERT.sub(lambda m: params.get(m.group(1), "[Assignment]"), text)
    line = (f"{label} " if label else "") + text
    lines = [("  " * depth + line).rstrip()] if line.strip() else []
    for sub in part.get("parts", []):
        lines.append(_prose(sub, params, depth + 1))
    return "\n".join(x for x in lines if x)


def _walk(ctrl: dict, family: str, family_title: str, parent: str | None, rows: list[dict]) -> None:
    params = _params(ctrl)
    for sub in ctrl.get("controls", []):
        params.update(_params(sub))
    parts = {p.get("name"): p for p in ctrl.get("parts", [])}
    status = next((p["value"] for p in ctrl.get("props", []) if p.get("name") == "status"), "active")
    native = nist_80053(_label(ctrl)) or _label(ctrl)
    rows.append({
        "reqId": f"{FW}:{native}",
        "nativeId": native,
        "oscalId": ctrl["id"],
        "title": ctrl.get("title", ""),
        "text": _prose(parts["statement"], params) if "statement" in parts else "",
        "guidance": _prose(parts["guidance"], params) if "guidance" in parts else "",
        "family": family,
        "familyTitle": family_title,
        "isEnhancement": parent is not None,
        "parent": parent,
        "isActive": status != "withdrawn",
        "status": status,
    })
    for sub in ctrl.get("controls", []):
        _walk(sub, family, family_title, f"{FW}:{native}", rows)


def parse(path: Path) -> dict:
    cat = json.loads(Path(path).read_text())["catalog"]
    rows: list[dict] = []
    for g in cat["groups"]:
        for c in g.get("controls", []):
            _walk(c, g["id"].upper(), g.get("title", ""), None, rows)
    return {"requirements": rows, "version": cat.get("metadata", {}).get("version")}


def load(graph, data: dict, spec) -> dict:
    n = graph.batch(
        """
        UNWIND $rows AS r
        MERGE (q:Requirement {reqId: r.reqId})
        SET q.frameworkId = $fw, q.nativeId = r.nativeId, q.oscalId = r.oscalId,
            q.title = r.title, q.text = r.text, q.guidance = r.guidance,
            q.family = r.family, q.familyTitle = r.familyTitle,
            q.isEnhancement = r.isEnhancement, q.isActive = r.isActive, q.status = r.status,
            q.textLicensed = true, q.sourceId = $sid, q.ingestedAt = datetime(),
            q.lastVerifiedAt = datetime()
        WITH q
        MATCH (f:Framework {frameworkId: $fw})
        MERGE (q)-[p:PART_OF]->(f)
        SET p.sourceId = $sid
        """,
        data["requirements"], fw=FW, sid=spec.id,
    )
    e = graph.batch(
        """
        UNWIND $rows AS r
        MATCH (c:Requirement {reqId: r.reqId}), (p:Requirement {reqId: r.parent})
        MERGE (c)-[x:ENHANCES]->(p)
        SET x.sourceId = $sid
        """,
        [r for r in data["requirements"] if r["parent"]], sid=spec.id,
    )
    return {"requirements": n, "enhancements": e, "catalogVersion": data.get("version")}
