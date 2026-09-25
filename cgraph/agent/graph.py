"""The audit loop as a LangGraph StateGraph.

intake -> scan -> map_cwe -> enrich -> score -> [review]* -> report -> persist
* review interrupts for a human decision when any risk scores >= threshold.
"""
from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path

import yaml
from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from ..config import settings
from ..ids import cwe as norm_cwe
from ..knowledge import Knowledge
from ..llm import classify_cwe, summarize
from . import rcm
from .persist import persist
from .scanners import SCANNERS
from .scoring import build_risks
from .state import AuditState

log = logging.getLogger(__name__)
DECISIONS = {"accept", "mitigate", "false_positive", "transfer", "pending_review"}


def build(graph_db, llm=None, checkpointer=None, scanners=None, threshold: int | None = None):
    cfg = settings()
    kb = Knowledge(graph_db)
    scanners = scanners if scanners is not None else SCANNERS
    threshold = cfg.review_threshold if threshold is None else threshold

    def intake(state: AuditState) -> dict:
        target = Path(state["target"]).resolve()
        if not target.exists():
            raise FileNotFoundError(target)
        ctx_file = target / ".cgraph.yaml"
        ctx = yaml.safe_load(ctx_file.read_text()) if ctx_file.exists() else {}
        repo_id = ctx.get("repo_id") or f"local/{target.name}"
        return {"target": str(target), "context": ctx or {}, "repo_id": repo_id,
                "run_id": state.get("run_id") or f"run-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:6]}",
                "started_at": datetime.now(timezone.utc).isoformat(), "scope": state.get("scope", "full"),
                "warnings": [] if ctx_file.exists() else
                ["no .cgraph.yaml in target: using default context (internal data, exposure unknown)"]}

    def scan(state: AuditState) -> dict:
        findings, warns, ran = [], list(state.get("warnings", [])), []
        skip = set(state.get("context", {}).get("skip_tools", []))
        for name, fn in scanners.items():
            if name in skip:
                continue
            args = (Path(state["target"]), cfg.semgrep_extra_configs) if name == "semgrep" else (Path(state["target"]),)
            got, w = fn(*args)
            warns += w
            if not any("not installed" in x for x in w):
                ran.append(name)
            findings += got
        dedup = {f["findingId"]: f for f in findings}
        return {"findings": list(dedup.values()), "warnings": warns, "tools_run": ran}

    def map_cwe(state: AuditState) -> dict:
        out = []
        for f in state["findings"]:
            f = dict(f)
            f["cwes"] = [c for c in (norm_cwe(x) for x in f["cwes"]) if c]
            if not f["cwes"] and llm is not None:
                guess = classify_cwe(llm, f)
                if guess and kb.controls_for_cwe(guess)["known"]:
                    f["cwes"], f["cweSource"] = [guess], "llm (unverified)"
            out.append(f)
        return {"findings": out}

    def enrich(state: AuditState) -> dict:
        cwes = sorted({c for f in state["findings"] for c in f["cwes"][:1]})
        cwe_info = {}
        for c in cwes:
            info = kb.controls_for_cwe(c)
            info.update(kb.techniques_for_cwe(c))
            req_ids = [x["reqId"] for x in info.get("direct", [])[:4] + info.get("threat", [])[:3]]
            info["crosswalk"] = kb.crosswalk(req_ids)
            cwe_info[c] = info
        warns = list(state.get("warnings", []))
        unknown = [c for c, i in cwe_info.items() if not i.get("known")]
        if unknown:
            warns.append(f"CWEs not in graph (run `cgraph ingest`?): {', '.join(unknown)}")
        cves = kb.cves([c for f in state["findings"] for c in f.get("cves", [])])
        return {"enrichment": {"cwe": cwe_info, "cve": cves}, "warnings": warns}

    def score(state: AuditState) -> dict:
        return {"risks": build_risks(state)}

    def route(state: AuditState) -> str:
        return "review" if any(r["score"] >= threshold for r in state["risks"]) else "report"

    def review(state: AuditState) -> dict:
        pending = [r for r in state["risks"] if r["score"] >= threshold]
        if state.get("non_interactive"):
            decisions = {r["riskId"]: "pending_review" for r in pending}
        else:
            answer = interrupt({
                "type": "risk_review", "threshold": threshold,
                "instructions": f"Decide each risk: {sorted(DECISIONS)}",
                "risks": [{"riskId": r["riskId"], "rating": r["rating"], "score": r["score"], "cwe": r["cwe"],
                           "statement": r["statement"], "files": r["files"][:5],
                           "controls": [c["nativeId"] for c in r["controls"][:4]]} for r in pending],
            })
            decisions = {k: (v if v in DECISIONS else "pending_review") for k, v in (answer or {}).items()}
        risks = []
        for r in state["risks"]:
            d = decisions.get(r["riskId"])
            status = {"false_positive": "closed-false-positive", "accept": "accepted"}.get(d, "open")
            risks.append({**r, "decision": d, "status": status})
        return {"risks": risks, "decisions": decisions}

    def persist_node(state: AuditState) -> dict:
        persist(graph_db, state)
        return {}

    def report(state: AuditState) -> dict:
        out = cfg.out_dir / state["run_id"]
        out.mkdir(parents=True, exist_ok=True)
        meta = {"run_id": state["run_id"], "repo_id": state["repo_id"], "target": state["target"],
                "started_at": state["started_at"], "tools": state.get("tools_run", []),
                "warnings": state.get("warnings", []),
                "tool_uuid": str(uuid.UUID(hashlib.md5(b"compliance-graph").hexdigest()))}
        risks = state["risks"]
        paths = {
            "xlsx": str(rcm.write_xlsx(risks, out / "rcm.xlsx", meta)),
            "csv": str(rcm.write_csv(risks, out / "rcm.csv")),
            "oscal": str(rcm.write_oscal(risks, out / "assessment-results.oscal.json", meta)),
            "markdown": str(rcm.write_markdown(risks, out / "summary.md", meta, summarize(llm, risks, state["repo_id"]))),
        }
        (out / "findings.json").write_text(json.dumps(state["findings"], indent=2))
        paths["json"] = str(out / "findings.json")
        return {"outputs": paths}

    b = StateGraph(AuditState)
    for name, fn in [("intake", intake), ("scan", scan), ("map_cwe", map_cwe), ("enrich", enrich),
                     ("score", score), ("review", review), ("persist", persist_node), ("report", report)]:
        b.add_node(name, fn)
    b.add_edge(START, "intake")
    b.add_edge("intake", "scan")
    b.add_edge("scan", "map_cwe")
    b.add_edge("map_cwe", "enrich")
    b.add_edge("enrich", "score")
    b.add_conditional_edges("score", route, ["review", "report"])
    b.add_edge("review", "report")
    b.add_edge("report", "persist")  # report first so evidence nodes can point at the artifact
    b.add_edge("persist", END)
    return b.compile(checkpointer=checkpointer)
