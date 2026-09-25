"""Audit loop end-to-end with a fake graph and fake scanners (no Neo4j needed)."""
import json

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command

from cgraph.agent.graph import build
from conftest import ROOT


class FakeGraph:
    def __init__(self):
        self.writes = []

    def run(self, q, **p):
        if "ADDRESSED_BY]->(q:Requirement)" in q:
            c = p["cwe"]
            if c == "CWE-9999":
                return []
            return [{"cwe": c, "name": f"Name of {c}", "description": "",
                     "direct": [{"reqId": "NIST-800-53-r5:SI-10", "nativeId": "SI-10", "oscalId": "si-10",
                                 "title": "Information Input Validation", "confidence": 0.9, "reviewed": False,
                                 "rationale": "x", "via": c, "path": "direct"}],
                     "threat": [{"reqId": "NIST-800-53-r5:SC-7", "nativeId": "SC-7", "oscalId": "sc-7",
                                 "title": "Boundary Protection", "hits": 2, "techniques": ["T1190"], "path": "threat"}]}]
        if "EXPLOITS]-(ap:AttackPattern)" in q:
            return [{"patterns": [{"capec": "CAPEC-66"}], "techniques": [{"attackId": "T1190", "name": "Exploit"}]}]
        if "RELATES_TO]->(a:AITechnique)" in q:
            return [{"aiTechniques": [], "aiMitigations": []}]
        if "UNWIND $reqIds" in q:
            return [{"reqId": r, "scf": [{"scfId": "TDA-02", "title": "x"}],
                     "mapped": [{"frameworkId": "ISO-27001-2022", "nativeId": "A.8.28"}]} for r in p["reqIds"]]
        if "UNWIND $cves" in q:
            return [{"cveId": c, "kev": c == "CVE-2021-44228", "epss": 0.9, "epssPercentile": 0.99,
                     "ransomware": False, "kevDueDate": None} for c in p["cves"]]
        self.writes.append(q)
        return []

    def batch(self, q, rows, size=2000, **p):
        self.writes.append((q, len(list(rows))))
        return 0


def fake_semgrep(target, extra=""):
    return [{"findingId": "F-1", "tool": "semgrep", "ruleId": "cg-py-sql-string-format", "ruleKey": "semgrep:cg-py-sql-string-format",
             "title": "SQL", "severity": "high", "file": "app.py", "line": 22, "cwes": ["CWE-89"], "cves": [],
             "package": None, "cweSource": "rule-metadata"},
            {"findingId": "F-2", "tool": "semgrep", "ruleId": "cg-py-weak-hash", "ruleKey": "semgrep:cg-py-weak-hash",
             "title": "md5", "severity": "low", "file": "app.py", "line": 51, "cwes": ["CWE-328"], "cves": [],
             "package": None, "cweSource": "rule-metadata"}], []


def fake_osv(target):
    return [{"findingId": "F-3", "tool": "osv-scanner", "ruleId": "GHSA-jfh8", "ruleKey": "osv:*", "title": "log4j",
             "severity": "critical", "file": "pom.xml", "line": 0, "cwes": ["CWE-1395"], "cves": ["CVE-2021-44228"],
             "package": "pkg:maven/log4j@2.14.0", "cweSource": "tool-default"}], []


def test_loop_interrupts_and_resumes(tmp_path, monkeypatch):
    monkeypatch.setenv("CGRAPH_OUT_DIR", str(tmp_path))
    g = FakeGraph()
    app = build(g, checkpointer=InMemorySaver(), scanners={"semgrep": fake_semgrep, "osv-scanner": fake_osv}, threshold=15)
    cfg = {"configurable": {"thread_id": "t1"}}
    r = app.invoke({"target": str(ROOT / "eval" / "vulnerable_app"), "run_id": "run-test"}, cfg)
    assert r.get("__interrupt__"), "high risks must pause for human review"
    pending = r["__interrupt__"][0].value["risks"]
    kev_risk = next(x for x in pending if x["cwe"] == "CWE-1395")
    assert kev_risk["score"] >= 15
    r = app.invoke(Command(resume={x["riskId"]: "mitigate" for x in pending}), cfg)
    assert not r.get("__interrupt__")
    risks = {x["cwe"]: x for x in r["risks"]}
    assert risks["CWE-1395"]["likelihood"] == 5  # KEV forces likelihood 5
    assert risks["CWE-89"]["decision"] == "mitigate"
    assert risks["CWE-89"]["controls"][0]["nativeId"] == "SI-10"
    out = r["outputs"]
    for k in ("xlsx", "csv", "oscal", "markdown", "json"):
        assert (tmp_path / "run-test").exists() and out[k]
    oscal = json.loads(open(out["oscal"]).read())
    assert oscal["assessment-results"]["results"][0]["findings"]
    assert any("Risk" in (w[0] if isinstance(w, tuple) else w) for w in g.writes), "risks persisted"


def test_non_interactive_marks_pending(tmp_path, monkeypatch):
    monkeypatch.setenv("CGRAPH_OUT_DIR", str(tmp_path))
    app = build(FakeGraph(), scanners={"osv-scanner": fake_osv}, threshold=15)
    r = app.invoke({"target": str(ROOT / "eval" / "vulnerable_app"), "run_id": "run-ci", "non_interactive": True})
    assert r["risks"][0]["decision"] == "pending_review" and r["risks"][0]["status"] == "open"
