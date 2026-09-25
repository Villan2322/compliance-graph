import pytest

from cgraph.db import split_cypher
from cgraph.ingest import capec, curated, cwe, epss, kev
from conftest import FIX, RAW, ROOT


def test_cwe_fixture():
    d = cwe.parse(FIX / "cwe_sample.xml")
    by = {w["cweId"]: w for w in d["weaknesses"]}
    assert by["CWE-89"]["isActive"] and not by["CWE-1"]["isActive"]
    assert d["child_of"] == [{"child": "CWE-89", "parent": "CWE-943", "primary": True}]  # view 1003 ignored
    assert d["version"] == "4.18"


def test_capec_fixture():
    d = capec.parse(FIX / "capec_sample.xml")
    assert [p["capecId"] for p in d["patterns"]] == ["CAPEC-66"]  # deprecated dropped
    assert {"capec": "CAPEC-66", "cwe": "CWE-89"} in d["exploits"]
    assert d["maps"] == [{"capec": "CAPEC-66", "tech": "T1190"}]  # WASC ignored


def test_kev_epss_fixture():
    k = kev.parse(FIX / "kev_sample.json")["vulns"][0]
    assert k["cveId"] == "CVE-2021-44228" and k["ransomware"] and "CWE-502" in k["cwes"]
    e = epss.parse(FIX / "epss_sample.csv.gz")
    assert e["scoreDate"].startswith("2026-09-24") and e["scores"][0]["pct"] > 0.99


def test_curated_mappings_resolve_ids():
    d = curated.parse()
    assert d["edges"] and all(e["req"] and e["req"].startswith("NIST-800-53-r5:") for e in d["edges"])
    assert all(0 < e["confidence"] <= 1 for e in d["edges"])
    rule_cwes = {c for r in d["rules"] for c in r["cwes"]}
    mapped = {e["cwe"] for e in d["edges"]}
    assert rule_cwes <= mapped, f"rules detect CWEs with no control mapping: {rule_cwes - mapped}"
    topic_cwes = {c for t in d["topics"] for c in t["cwes"]}
    assert topic_cwes <= mapped, f"topics reference unmapped CWEs: {topic_cwes - mapped}"
    assert d["capecAttack"] and all(e["capec"] and e["tech"] for e in d["capecAttack"])


def test_cypher_files_split():
    s = split_cypher((ROOT / "ontology" / "schema.cypher").read_text())
    assert len(s) > 30 and all(x.split()[0] == "CREATE" for x in s)
    seed = split_cypher((ROOT / "ontology" / "seed.cypher").read_text())
    assert len(seed) == 2


# ---- Real upstream data (run after `cgraph fetch`; skipped in fresh clones) ----
def _need(name):
    p = RAW / name
    if not p.exists():
        pytest.skip(f"{name} not fetched")
    return p


def test_real_nist():
    from cgraph.ingest import nist_800_53
    d = nist_800_53.parse(_need("nist-800-53-r5.json"))
    by = {r["nativeId"]: r for r in d["requirements"]}
    assert len(by) > 1100 and by["IA-5(7)"]["parent"] == "NIST-800-53-r5:IA-5"
    assert "[Assignment" in by["AC-2"]["text"]
    ids_in_curated = {e["req"] for e in curated.parse()["edges"]}
    missing = {r for r in ids_in_curated if r.split(":", 1)[1] not in by}
    assert not missing, f"curated mappings reference unknown controls: {missing}"


def test_real_attack_ctid_atlas():
    from cgraph.ingest import atlas, attack, ctid
    a = attack.parse(_need("enterprise-attack.json"))
    techs = {t["attackId"] for t in a["techniques"]}
    assert "T1190" in techs and len(a["mitigates"]) > 500
    c = ctid.parse(_need("ctid-800-53-attack.json"))
    assert len(c["mitigates"]) > 4000
    assert len({m["tech"] for m in c["mitigates"]} - techs) < 50  # nearly all resolve
    x = atlas.parse(_need("ATLAS.yaml"))
    assert any(t["atlasId"] == "AML.T0051" for t in x["techniques"])


def test_curated_capec_attack_resolve_real_ids():
    from cgraph.ingest import attack, capec as capec_ingest
    capecs = {p["capecId"] for p in capec_ingest.parse(_need("capec_latest.xml"))["patterns"]}
    techs = {t["attackId"] for t in attack.parse(_need("enterprise-attack.json"))["techniques"]}
    rows = curated.parse()["capecAttack"]
    assert not {r["capec"] for r in rows} - capecs
    assert not {r["tech"] for r in rows} - techs
