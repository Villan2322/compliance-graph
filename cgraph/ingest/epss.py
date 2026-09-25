"""FIRST EPSS -> probability/percentile on (:Vulnerability). Loads every scored CVE
(~300k small nodes) so offline audits can score dependency CVEs without a network call."""
from __future__ import annotations

import csv
import gzip
import io
from pathlib import Path


def parse(path: Path) -> dict:
    raw = gzip.open(path, "rt") if str(path).endswith(".gz") else open(path)
    with raw as f:
        first = f.readline()
        meta = {}
        if first.startswith("#"):
            for kv in first.lstrip("#").strip().split(","):
                if ":" in kv:
                    k, v = kv.split(":", 1)
                    meta[k.strip()] = v.strip()
            body = f.read()
        else:
            body = first + f.read()
    rows = [{"cveId": r["cve"].upper(), "epss": float(r["epss"]), "pct": float(r["percentile"])}
            for r in csv.DictReader(io.StringIO(body))]
    return {"scores": rows, "scoreDate": meta.get("score_date"), "model": meta.get("model_version")}


def load(graph, data: dict, spec) -> dict:
    n = graph.batch("""
        UNWIND $rows AS r MERGE (v:Vulnerability {cveId: r.cveId})
        ON CREATE SET v.kev = false
        SET v.epss = r.epss, v.epssPercentile = r.pct, v.epssDate = $d""",
        data["scores"], size=10000, d=data["scoreDate"])
    return {"scored": n, "scoreDate": data["scoreDate"], "model": data["model"]}
