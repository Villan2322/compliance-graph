"""cgraph — command line for the compliance knowledge graph."""
from __future__ import annotations

import argparse
import json
import logging
import sqlite3
import sys
from pathlib import Path

from . import __version__
from .config import ROOT, settings

log = logging.getLogger("cgraph")


def _graph():
    from .db import Graph
    g = Graph()
    g.verify()
    return g


def cmd_init(a) -> int:
    with _graph() as g:
        g.run_file(ROOT / "ontology" / "schema.cypher")
        g.run_file(ROOT / "ontology" / "seed.cypher")
    print("ontology applied (schema + seed)")
    return 0


def cmd_fetch(a) -> int:
    from .sources import fetch, load_manifest
    rc = 0
    for s in load_manifest():
        if a.only and s.id not in a.only:
            continue
        if a.tier and s.tier > a.tier:
            continue
        try:
            p = fetch(s, force=a.force)
            print(f"{s.id:26} {'ok ' + str(p) if p else 'skipped (local/manual)'}")
        except Exception as e:
            print(f"{s.id:26} FAILED {e}")
            rc = 1 if s.tier == 1 else rc  # tier 2 feeds are best-effort
    return rc


def cmd_ingest(a) -> int:
    from .ingest import get
    from .sources import load_manifest, ordered, record_source
    rc = 0
    with _graph() as g:
        for s in ordered(load_manifest()):
            if a.only and s.id not in a.only:
                continue
            if a.tier and s.tier > a.tier:
                continue
            if not s.local and not s.path.exists():
                print(f"{s.id:26} skipped: {s.path} missing (run `cgraph fetch`{' — manual download' if s.manual else ''})")
                continue
            try:
                mod = get(s.loader)
                data = mod.parse(None if s.local else s.path)
                stats = mod.load(g, data, s)
                record_source(g, s, None if s.local else s.path, stats)
                print(f"{s.id:26} {json.dumps(stats, default=str)}")
            except Exception as e:
                log.exception("ingest failed for %s", s.id)
                print(f"{s.id:26} FAILED {e}")
                rc = 1
    return rc


CHECKS = [
    ("frameworks seeded", "MATCH (f:Framework) RETURN count(f) AS n", lambda n: n >= 10),
    ("NIST 800-53 requirements", "MATCH (q:Requirement {frameworkId:'NIST-800-53-r5'}) WHERE q.text IS NOT NULL RETURN count(q) AS n", lambda n: n > 1000),
    ("ATT&CK techniques", "MATCH (t:Technique) RETURN count(t) AS n", lambda n: n > 500),
    ("CTID control→technique edges", "MATCH (:Requirement)-[r:MITIGATES]->(:Technique) RETURN count(r) AS n", lambda n: n > 1000),
    ("CWE weaknesses", "MATCH (w:Weakness) RETURN count(w) AS n", lambda n: n > 900),
    ("CAPEC→CWE edges", "MATCH (:AttackPattern)-[r:EXPLOITS]->(:Weakness) RETURN count(r) AS n", lambda n: n > 500),
    ("curated CWE→control edges", "MATCH (:Weakness)-[r:ADDRESSED_BY]->() RETURN count(r) AS n", lambda n: n > 80),
    ("ATLAS AI techniques", "MATCH (t:AITechnique) RETURN count(t) AS n", lambda n: n > 50),
    ("SCF controls (optional)", "MATCH (c:SCFControl) RETURN count(c) AS n", lambda n: True),
    ("KEV vulnerabilities (tier 2)", "MATCH (v:Vulnerability {kev:true}) RETURN count(v) AS n", lambda n: True),
    ("nodes missing provenance", "MATCH (n) WHERE (n:Requirement OR n:Weakness OR n:Technique OR n:AttackPattern) AND n.sourceId IS NULL RETURN count(n) AS n", lambda n: n == 0),
    ("end-to-end: CWE-89 reaches a control", "MATCH p=(:Weakness {cweId:'CWE-89'})-[:ADDRESSED_BY]->(:Requirement) RETURN count(p) AS n", lambda n: n > 0),
    ("end-to-end: CWE-89 threat path", "MATCH p=(:Weakness {cweId:'CWE-89'})<-[:EXPLOITS]-(:AttackPattern)-[:MAPS_TO]->(:Technique)<-[:MITIGATES]-(:Requirement) RETURN count(p) AS n", lambda n: n > 0),
]


def cmd_verify(a) -> int:
    bad = 0
    with _graph() as g:
        for name, q, ok in CHECKS:
            n = g.run(q)[0]["n"]
            good = ok(n)
            bad += 0 if good else 1
            print(f"{'PASS' if good else 'FAIL'}  {name:42} {n}")
        for s in g.run("MATCH (s:Source) RETURN s.sourceId AS id, s.retrievedAt AS at ORDER BY id"):
            print(f"      source {s['id']:26} {s['at']}")
    return 1 if bad else 0


def cmd_purge(a) -> int:
    """Remove data before writing a public release dump: nodes tagged with a
    given sourceId (e.g. a source whose license doesn't clear redistribution),
    and/or the audit-run layer (Repository/Component/AuditRun/Finding/Risk --
    per-repo audit history, not general knowledge-graph content)."""
    with _graph() as g:
        if a.source:
            n = g.run("MATCH (n {sourceId: $sid}) RETURN count(n) AS n", sid=a.source)[0]["n"]
            g.run("MATCH (n {sourceId: $sid}) DETACH DELETE n", sid=a.source)
            print(f"purged {n} node(s) tagged sourceId={a.source!r} (and their relationships)")
        if a.audit_history:
            n = g.run("""MATCH (n) WHERE n:Repository OR n:Component OR n:AuditRun OR n:Finding OR n:Risk
                         RETURN count(n) AS n""")[0]["n"]
            g.run("MATCH (n) WHERE n:Repository OR n:Component OR n:AuditRun OR n:Finding OR n:Risk DETACH DELETE n")
            print(f"purged {n} audit-history node(s) (Repository/Component/AuditRun/Finding/Risk)")
    return 0


def cmd_audit(a) -> int:
    from langgraph.checkpoint.sqlite import SqliteSaver
    from langgraph.types import Command
    from .agent.graph import build
    from .llm import get_llm
    cfg = settings()
    cfg.state_dir.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(cfg.state_dir / "checkpoints.sqlite", check_same_thread=False)
    with _graph() as g:
        app = build(g, llm=get_llm(), checkpointer=SqliteSaver(conn))
        from datetime import datetime, timezone
        import uuid
        run_id = a.resume or f"run-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:6]}"
        config = {"configurable": {"thread_id": run_id}}
        print(f"run {run_id} (resume an interrupted run with: cgraph audit {a.path} --resume {run_id})", file=sys.stderr)
        init = {"target": a.path, "non_interactive": a.non_interactive, "scope": a.scope, "run_id": run_id}
        result = app.invoke(None if a.resume else init, config)
        while result.get("__interrupt__"):
            req = result["__interrupt__"][0].value
            if a.decisions:
                answers = json.loads(Path(a.decisions).read_text())
            else:
                print(f"\n{len(req['risks'])} risk(s) at or above {req['threshold']} need a decision.")
                print(req["instructions"])
                answers = {}
                for r in req["risks"]:
                    print(f"\n[{r['rating']} {r['score']}] {r['riskId']} {r['cwe']}\n  {r['statement']}\n"
                          f"  files: {', '.join(r['files'])}\n  controls: {', '.join(r['controls'])}")
                    ans = input("  decision [mitigate]: ").strip() or "mitigate"
                    answers[r["riskId"]] = ans
            result = app.invoke(Command(resume=answers), config)
    print(json.dumps({"runId": result.get("run_id"), "outputs": result.get("outputs"),
                      "risks": [(r["riskId"], r["rating"], r["score"], r["cwe"]) for r in result.get("risks", [])],
                      "warnings": result.get("warnings", [])}, indent=2))
    worst = max((r["score"] for r in result.get("risks", []) if r.get("status") == "open"), default=0)
    return 2 if a.fail_on and worst >= a.fail_on else 0


def cmd_mcp(a) -> int:
    from .mcp_server import serve
    serve(a.transport, a.host, a.port)
    return 0


def cmd_embed(a) -> int:
    try:
        from fastembed import TextEmbedding
    except ImportError:
        print("pip install 'compliance-graph[embed]' first")
        return 1
    cfg = settings()
    model = TextEmbedding(cfg.embed_model)
    with _graph() as g:
        for label, key, text in [("Requirement", "reqId", "coalesce(n.title,'') + '. ' + coalesce(n.text,'')"),
                                 ("Weakness", "cweId", "coalesce(n.name,'') + '. ' + coalesce(n.description,'')")]:
            rows = g.run(f"MATCH (n:{label}) WHERE n.embedding IS NULL RETURN n.{key} AS id, {text} AS t")
            for i in range(0, len(rows), 256):
                chunk = rows[i:i + 256]
                vecs = list(model.embed([r["t"][:2000] for r in chunk]))
                g.run(f"UNWIND $rows AS r MATCH (n:{label} {{{key}: r.id}}) "
                      "CALL db.create.setNodeVectorProperty(n, 'embedding', r.v)",
                      rows=[{"id": r["id"], "v": [float(x) for x in v]} for r, v in zip(chunk, vecs)])
            print(f"embedded {len(rows)} {label} nodes")
    return 0


def cmd_scf_headers(a) -> int:
    from .ingest.scf import headers
    from .sources import load_manifest
    spec = next(s for s in load_manifest() if s.id == "scf")
    for sheet, hs in headers(spec.path).items():
        print(f"== {sheet}")
        for h in hs:
            print("   ", h)
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="cgraph", description="Compliance knowledge graph")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("-v", "--verbose", action="store_true")
    sp = p.add_subparsers(dest="cmd", required=True)
    sp.add_parser("init", help="apply ontology schema + seed").set_defaults(fn=cmd_init)
    f = sp.add_parser("fetch", help="download sources to sources/raw")
    f.add_argument("--only", nargs="*")
    f.add_argument("--tier", type=int)
    f.add_argument("--force", action="store_true")
    f.set_defaults(fn=cmd_fetch)
    i = sp.add_parser("ingest", help="load sources into the graph")
    i.add_argument("--only", nargs="*")
    i.add_argument("--tier", type=int)
    i.set_defaults(fn=cmd_ingest)
    sp.add_parser("verify", help="graph health checks").set_defaults(fn=cmd_verify)
    au = sp.add_parser("audit", help="run the LangGraph audit loop on a path")
    au.add_argument("path")
    au.add_argument("--non-interactive", action="store_true", help="mark high risks pending_review instead of prompting")
    au.add_argument("--decisions", help="JSON file {riskId: decision} to answer the review gate")
    au.add_argument("--scope", choices=["full", "diff"], default="full")
    au.add_argument("--resume", help="thread id of an interrupted run")
    au.add_argument("--fail-on", type=int, help="exit 2 if any open risk scores >= N (CI gate)")
    au.set_defaults(fn=cmd_audit)
    m = sp.add_parser("mcp", help="serve MCP tools")
    m.add_argument("--transport", choices=["stdio", "streamable-http", "sse"], default="stdio")
    m.add_argument("--host", default="127.0.0.1")
    m.add_argument("--port", type=int, default=8765)
    m.set_defaults(fn=cmd_mcp)
    sp.add_parser("embed", help="populate vector embeddings (optional)").set_defaults(fn=cmd_embed)
    sp.add_parser("scf-headers", help="print SCF workbook headers to fix scf_columns.yaml").set_defaults(fn=cmd_scf_headers)
    pu = sp.add_parser("purge", help="remove data before a public release dump (see NOTICE)")
    pu.add_argument("--source", help="delete every node tagged sourceId=<id> and its relationships")
    pu.add_argument("--audit-history", action="store_true",
                     help="delete Repository/Component/AuditRun/Finding/Risk nodes (per-repo audit runs)")
    pu.set_defaults(fn=cmd_purge)
    a = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
