"""MCP server: the prevention side. Coding agents (Claude Code, Cursor, etc.)
query the graph BEFORE writing code, and can run the audit loop AFTER."""
from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from .db import Graph
from .ids import attack_technique
from .knowledge import Knowledge

INSTRUCTIONS = """Security & compliance knowledge graph (NIST 800-53, SCF crosswalks, MITRE CWE/CAPEC/ATT&CK/ATLAS, CISA KEV, EPSS).
Before writing code that touches auth, data access, files, shell, network, crypto, logging, dependencies or LLMs:
call secure_coding_checklist with the topic. When you see or suspect a weakness, call controls_for_cwe.
After changes, call run_audit on the repo and address High/Critical risks before finishing."""

mcp = FastMCP("compliance-graph", instructions=INSTRUCTIONS)
_graph: Graph | None = None


def kb() -> Knowledge:
    global _graph
    if _graph is None:
        _graph = Graph()
    return Knowledge(_graph)


@mcp.tool()
def secure_coding_checklist(topic: str) -> dict:
    """Guidance, CWEs to avoid, and the controls they implicate for a coding topic
    (e.g. 'authentication', 'sql', 'file upload', 'llm', 'dependencies')."""
    k = kb()
    topics = k.topic(topic)
    for t in topics:
        for w in t["weaknesses"]:
            c = k.controls_for_cwe(w["cweId"], limit=3)
            w["controls"] = [x["nativeId"] for x in c.get("direct", [])[:3]]
    return {"topic": topic, "matches": topics,
            "hint": None if topics else "No curated topic matched. Try search_controls with keywords."}


@mcp.tool()
def controls_for_cwe(cwe_id: str, include_crosswalk: bool = True) -> dict:
    """NIST 800-53 controls for a CWE (curated direct mappings + CWE→CAPEC→ATT&CK→control
    threat paths), the attack techniques it enables, and optional SCF crosswalk to ISO/SOC 2/PCI."""
    k = kb()
    out = k.controls_for_cwe(cwe_id)
    out.update(k.techniques_for_cwe(cwe_id))
    if include_crosswalk and out.get("known"):
        ids = [c["reqId"] for c in out["direct"][:4] + out["threat"][:3]]
        out["crosswalk"] = k.crosswalk(ids)
    return out


@mcp.tool()
def technique_mitigations(attack_id: str) -> list[dict]:
    """Controls and ATT&CK mitigations for an ATT&CK technique (e.g. T1190)."""
    return kb().g.run("""
        MATCH (t:Technique {attackId: $t})
        OPTIONAL MATCH (q:Requirement)-[:MITIGATES]->(t)
        OPTIONAL MATCH (m:Mitigation)-[:MITIGATES]->(t)
        RETURN t.attackId AS technique, t.name AS name,
               collect(DISTINCT q.nativeId) AS nistControls,
               collect(DISTINCT m.attackId + ' ' + m.name) AS attackMitigations""", t=attack_technique(attack_id))


@mcp.tool()
def crosswalk(requirement_ids: list[str], frameworks: list[str] | None = None) -> dict:
    """Map requirement IDs (e.g. 'NIST-800-53-r5:AC-3') to other frameworks through SCF.
    frameworks filter example: ['ISO-27001-2022','SOC2-TSC-2017']."""
    return kb().crosswalk(requirement_ids, frameworks)


@mcp.tool()
def cve_risk(cve_ids: list[str]) -> dict:
    """KEV status, EPSS probability/percentile and ransomware use for CVEs."""
    return kb().cves(cve_ids)


@mcp.tool()
def search_controls(query: str, frameworks: list[str] | None = None, limit: int = 10) -> list[dict]:
    """Keyword search over control and requirement text."""
    return kb().search_controls(query, frameworks, min(limit, 50))


@mcp.tool()
def open_risks(repo_id: str | None = None, min_score: int = 1) -> list[dict]:
    """Open risks recorded by previous audit runs, highest first."""
    return kb().g.run("""
        MATCH (k:Risk)-[:ARISES_FROM]->(:Finding)-[:IN]->(r:Repository)
        WHERE k.status = 'open' AND k.score >= $min AND ($repo IS NULL OR r.repoId = $repo)
        OPTIONAL MATCH (k)-[:IMPLICATES]->(q:Requirement)
        RETURN DISTINCT k.riskId AS riskId, r.repoId AS repo, k.rating AS rating, k.score AS score,
               k.cwe AS cwe, k.statement AS statement, collect(DISTINCT q.nativeId) AS controls
        ORDER BY score DESC LIMIT 100""", repo=repo_id, min=min_score)


@mcp.tool()
def run_audit(path: str) -> dict:
    """Run the full audit loop on a local path (non-interactive: high risks are marked
    pending_review for a human). Returns risk summary and paths to the RCM outputs."""
    from .agent.graph import build
    from .llm import get_llm
    g = build(kb().g, llm=get_llm())
    s = g.invoke({"target": path, "non_interactive": True})
    return {"runId": s["run_id"], "outputs": s.get("outputs", {}), "warnings": s.get("warnings", []),
            "risks": [{k: r[k] for k in ("riskId", "rating", "score", "cwe", "cweName", "files")} |
                      {"controls": [c["nativeId"] for c in r["controls"][:4]]} for r in s.get("risks", [])]}


def serve(transport: str = "stdio", host: str = "127.0.0.1", port: int = 8765) -> None:
    mcp.settings.host, mcp.settings.port = host, port
    mcp.run(transport=transport)
