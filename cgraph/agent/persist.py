"""Write an audit run back into the graph so risk history compounds across runs."""
from __future__ import annotations

from .. import ONTOLOGY_VERSION

EVIDENCE_SUPPORTS = {"semgrep": "NIST-800-53-r5:SA-11(1)", "osv-scanner": "NIST-800-53-r5:RA-5",
                     "gitleaks": "NIST-800-53-r5:IA-5(7)"}


def persist(graph, state: dict) -> dict:
    run, repo = state["run_id"], state["repo_id"]
    graph.run("""
        MERGE (r:Repository {repoId: $repo})
        SET r.path = $path, r.name = $name, r.lastAuditAt = datetime(), r.context = $ctx
        MERGE (a:AuditRun {runId: $run})
        SET a.startedAt = datetime($started), a.finishedAt = datetime(), a.scope = $scope,
            a.tools = $tools, a.warnings = $warnings, a.ontologyVersion = $ov,
            a.findingCount = $nf, a.riskCount = $nr
        MERGE (a)-[:SCANNED]->(r)""",
        repo=repo, path=state["target"], name=repo.split("/")[-1],
        ctx=[f"{k}={v}" for k, v in state.get("context", {}).items()], run=run, started=state["started_at"],
        scope=state.get("scope", "full"), tools=state.get("tools_run", []), warnings=state.get("warnings", []),
        ov=ONTOLOGY_VERSION, nf=len(state.get("findings", [])), nr=len(state.get("risks", [])))
    graph.batch("""
        UNWIND $rows AS f
        MERGE (x:Finding {findingId: f.findingId})
        ON CREATE SET x.firstSeen = datetime()
        SET x.tool = f.tool, x.ruleId = f.ruleId, x.title = f.title, x.severity = f.severity,
            x.file = f.file, x.line = f.line, x.package = f.package, x.cweSource = f.cweSource,
            x.lastSeen = datetime(), x.status = 'open'
        WITH x, f
        MATCH (a:AuditRun {runId: $run}), (r:Repository {repoId: $repo})
        MERGE (a)-[:PRODUCED]->(x) MERGE (x)-[:IN]->(r)
        WITH x, f
        OPTIONAL MATCH (d:DetectionRule {ruleId: f.ruleKey})
        FOREACH (_ IN CASE WHEN d IS NULL THEN [] ELSE [1] END | MERGE (x)-[:RAISED_BY]->(d))
        WITH x, f
        UNWIND (CASE WHEN size(f.cwes) = 0 THEN [null] ELSE f.cwes END) AS c
        OPTIONAL MATCH (w:Weakness {cweId: c})
        FOREACH (_ IN CASE WHEN w IS NULL THEN [] ELSE [1] END | MERGE (x)-[:INSTANCE_OF]->(w))""",
        state.get("findings", []), run=run, repo=repo)
    graph.batch("""
        UNWIND $rows AS f
        MATCH (x:Finding {findingId: f.findingId}), (r:Repository {repoId: $repo})
        MERGE (c:Component {purl: f.package})
        MERGE (x)-[:AFFECTS]->(c) MERGE (r)-[:DEPENDS_ON]->(c)
        WITH x, f UNWIND f.cves AS cv
        MERGE (v:Vulnerability {cveId: cv}) ON CREATE SET v.kev = false
        MERGE (x)-[:INVOLVES]->(v)""",
        [f for f in state.get("findings", []) if f.get("package")], repo=repo)
    if state.get("scope", "full") == "full":
        graph.run("""
            MATCH (x:Finding {status: 'open'})-[:IN]->(:Repository {repoId: $repo})
            WHERE NOT (x)<-[:PRODUCED]-(:AuditRun {runId: $run})
            SET x.status = 'resolved', x.resolvedAt = datetime()""", repo=repo, run=run)
    risks = [{**r, "controlReqs": [c["reqId"] for c in r["controls"] if c.get("reqId")],
              "scfIds": sorted({s["scfId"] for v in r["crosswalk"].values() for s in v.get("scf", [])})}
             for r in state.get("risks", [])]
    graph.batch("""
        UNWIND $rows AS r
        MERGE (k:Risk {riskId: r.riskId})
        ON CREATE SET k.firstIdentified = datetime()
        SET k.cwe = r.cwe, k.statement = r.statement, k.likelihood = r.likelihood, k.impact = r.impact,
            k.score = r.score, k.rating = r.rating, k.status = r.status, k.decision = r.decision,
            k.owner = r.owner, k.scoringRationale = r.scoringRationale, k.mappingReviewed = r.mappingReviewed,
            k.lastAssessed = datetime(), k.lastRunId = $run
        WITH k, r
        OPTIONAL MATCH (k)-[old:ARISES_FROM]->() DELETE old
        WITH DISTINCT k, r
        UNWIND r.findingIds AS fid MATCH (x:Finding {findingId: fid}) MERGE (k)-[:ARISES_FROM]->(x)
        WITH DISTINCT k, r
        UNWIND (CASE WHEN size(r.controlReqs) = 0 THEN [null] ELSE r.controlReqs END) AS rid
        OPTIONAL MATCH (q:Requirement {reqId: rid})
        FOREACH (_ IN CASE WHEN q IS NULL THEN [] ELSE [1] END | MERGE (k)-[:IMPLICATES]->(q))
        WITH DISTINCT k, r
        UNWIND (CASE WHEN size(r.scfIds) = 0 THEN [null] ELSE r.scfIds END) AS sid
        OPTIONAL MATCH (s:SCFControl {scfId: sid})
        FOREACH (_ IN CASE WHEN s IS NULL THEN [] ELSE [1] END | MERGE (k)-[:TREATED_BY]->(s))""",
        risks, run=run)
    ev = [{"evidenceId": f"{run}:{t}", "tool": t, "req": EVIDENCE_SUPPORTS.get(t)} for t in state.get("tools_run", [])]
    graph.batch("""
        UNWIND $rows AS e
        MERGE (v:Evidence {evidenceId: e.evidenceId})
        SET v.type = 'automated-scan', v.tool = e.tool, v.collectedAt = datetime(), v.artifact = $artifact
        WITH v, e MATCH (a:AuditRun {runId: $run}) MERGE (v)-[:PRODUCED_BY]->(a)
        WITH v, e OPTIONAL MATCH (q:Requirement {reqId: e.req})
        FOREACH (_ IN CASE WHEN q IS NULL THEN [] ELSE [1] END | MERGE (v)-[:SUPPORTS]->(q))""",
        ev, run=run, artifact=state.get("outputs", {}).get("json", ""))
    return {"findings": len(state.get("findings", [])), "risks": len(risks)}
