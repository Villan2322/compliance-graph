"""Read-side queries shared by the audit loop and the MCP server.
All traversals are parameterized Cypher; nothing is string-built from input."""
from __future__ import annotations

from .ids import cve as norm_cve
from .ids import cwe as norm_cwe

Q_CONTROLS_FOR_CWE = """
MATCH (w:Weakness {cweId: $cwe})
OPTIONAL MATCH (w)-[:CHILD_OF*0..2]->(anc:Weakness)-[a:ADDRESSED_BY]->(q:Requirement)
WITH w, collect(DISTINCT CASE WHEN q IS NULL THEN null ELSE {
    reqId: q.reqId, nativeId: q.nativeId, oscalId: q.oscalId, title: q.title,
    confidence: a.confidence * CASE WHEN anc = w THEN 1.0 ELSE 0.8 END,
    reviewed: a.reviewed, rationale: a.rationale, via: anc.cweId, path: 'direct'} END) AS direct
OPTIONAL MATCH (w)<-[:EXPLOITS]-(:AttackPattern)-[:MAPS_TO]->(t:Technique)<-[:MITIGATES]-(q2:Requirement)
WITH w, direct, q2, count(DISTINCT t) AS hits, collect(DISTINCT t.attackId)[..5] AS techs
ORDER BY hits DESC
WITH w, direct, collect(CASE WHEN q2 IS NULL THEN null ELSE {
    reqId: q2.reqId, nativeId: q2.nativeId, oscalId: q2.oscalId, title: q2.title,
    hits: hits, techniques: techs, path: 'threat'} END)[..$limit] AS threat
RETURN w.cweId AS cwe, w.name AS name, w.description AS description, direct, threat
"""

Q_TECHNIQUES_FOR_CWE = """
MATCH (w:Weakness {cweId: $cwe})<-[:EXPLOITS]-(ap:AttackPattern)
OPTIONAL MATCH (ap)-[:MAPS_TO]->(t:Technique)
RETURN collect(DISTINCT {capec: ap.capecId, name: ap.name, severity: ap.severity}) AS patterns,
       collect(DISTINCT CASE WHEN t IS NULL THEN null ELSE {attackId: t.attackId, name: t.name} END) AS techniques
"""

Q_AI_FOR_CWE = """
MATCH (w:Weakness {cweId: $cwe})-[:RELATES_TO]->(a:AITechnique)
OPTIONAL MATCH (m:AIMitigation)-[:MITIGATES]->(a)
RETURN collect(DISTINCT {atlasId: a.atlasId, name: a.name}) AS aiTechniques,
       collect(DISTINCT CASE WHEN m IS NULL THEN null ELSE {atlasId: m.atlasId, name: m.name} END) AS aiMitigations
"""

Q_CROSSWALK = """
UNWIND $reqIds AS rid
MATCH (q:Requirement {reqId: rid})
OPTIONAL MATCH (q)-[:MAPS_TO]->(s:SCFControl)
OPTIONAL MATCH (s)<-[:MAPS_TO]-(o:Requirement)
WHERE o.frameworkId <> q.frameworkId AND ($frameworks IS NULL OR o.frameworkId IN $frameworks)
RETURN rid AS reqId,
       collect(DISTINCT CASE WHEN s IS NULL THEN null ELSE {scfId: s.scfId, title: s.title} END) AS scf,
       collect(DISTINCT CASE WHEN o IS NULL THEN null ELSE {frameworkId: o.frameworkId, nativeId: o.nativeId} END) AS mapped
"""

Q_CVES = """
UNWIND $cves AS c
OPTIONAL MATCH (v:Vulnerability {cveId: c})
RETURN c AS cveId, coalesce(v.kev, false) AS kev, v.epss AS epss, v.epssPercentile AS epssPercentile,
       coalesce(v.ransomware, false) AS ransomware, v.kevDueDate AS kevDueDate
"""

Q_TOPIC = """
MATCH (t:SecureCodingTopic)
WHERE t.topicId = $q OR toLower(t.name) CONTAINS toLower($q)
   OR any(k IN t.keywords WHERE toLower($q) CONTAINS k OR k CONTAINS toLower($q))
MATCH (t)-[:CONCERNS]->(w:Weakness)
RETURN t.topicId AS topicId, t.name AS name, t.guidance AS guidance,
       collect(DISTINCT {cweId: w.cweId, name: w.name}) AS weaknesses
"""

Q_SEARCH_CONTROLS = """
CALL db.index.fulltext.queryNodes('control_text', $q) YIELD node, score
WHERE $frameworks IS NULL OR node.frameworkId IN $frameworks OR node:SCFControl
RETURN coalesce(node.reqId, 'SCF:' + node.scfId) AS id, node.title AS title,
       left(coalesce(node.text, ''), 400) AS text, labels(node)[0] AS kind, score
ORDER BY score DESC LIMIT $limit
"""


class Knowledge:
    def __init__(self, graph):
        self.g = graph

    def controls_for_cwe(self, cwe: str, limit: int = 8) -> dict:
        c = norm_cwe(cwe)
        rows = self.g.run(Q_CONTROLS_FOR_CWE, cwe=c, limit=limit)
        if not rows:
            return {"cwe": c, "known": False, "direct": [], "threat": []}
        r = rows[0]
        r["direct"] = sorted(r["direct"], key=lambda x: -(x.get("confidence") or 0))
        return {"known": True, **r}

    def techniques_for_cwe(self, cwe: str) -> dict:
        rows = self.g.run(Q_TECHNIQUES_FOR_CWE, cwe=norm_cwe(cwe))
        out = rows[0] if rows else {"patterns": [], "techniques": []}
        ai = self.g.run(Q_AI_FOR_CWE, cwe=norm_cwe(cwe))
        out.update(ai[0] if ai else {"aiTechniques": [], "aiMitigations": []})
        return out

    def crosswalk(self, req_ids: list[str], frameworks: list[str] | None = None) -> dict[str, dict]:
        if not req_ids:
            return {}
        rows = self.g.run(Q_CROSSWALK, reqIds=list(req_ids), frameworks=frameworks)
        return {r["reqId"]: {"scf": r["scf"], "mapped": r["mapped"]} for r in rows}

    def cves(self, cves: list[str]) -> dict[str, dict]:
        ids = sorted({c for c in (norm_cve(x) for x in cves) if c})
        return {r["cveId"]: r for r in self.g.run(Q_CVES, cves=ids)} if ids else {}

    def topic(self, q: str) -> list[dict]:
        return self.g.run(Q_TOPIC, q=q.strip())

    def search_controls(self, q: str, frameworks: list[str] | None = None, limit: int = 10) -> list[dict]:
        # Lucene syntax: escape special chars so user text can't break the query.
        safe = "".join(ch if ch.isalnum() or ch.isspace() else " " for ch in q).strip() or "*"
        return self.g.run(Q_SEARCH_CONTROLS, q=safe, frameworks=frameworks, limit=limit)
