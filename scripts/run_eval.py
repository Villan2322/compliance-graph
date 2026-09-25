"""Known-answer eval: audit the deliberately vulnerable app against the real
graph and check recall per tool plus control coverage per CWE."""
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cgraph.agent.graph import build  # noqa: E402
from cgraph.db import Graph  # noqa: E402

exp = yaml.safe_load((ROOT / "eval" / "expected.yaml").read_text())
with Graph() as g:
    s = build(g).invoke({"target": str(ROOT / exp["target"]), "non_interactive": True, "run_id": "eval"})
found = {}
for f in s["findings"]:
    for c in f["cwes"]:
        found.setdefault(f["tool"], set()).add(c)
fail = 0
for tool, cwes in exp["expected_cwes"].items():
    if tool not in s.get("tools_run", []):
        print(f"SKIP {tool}: not installed")
        continue
    miss = set(cwes) - found.get(tool, set())
    print(f"{'PASS' if not miss else 'FAIL'} {tool}: recall {len(cwes) - len(miss)}/{len(cwes)}" + (f" missing {sorted(miss)}" if miss else ""))
    fail += bool(miss)
for r in s["risks"]:
    ok = len([c for c in r["controls"] if c["path"] == "direct"]) >= exp["min_controls"]
    fail += not ok
    print(f"{'PASS' if ok else 'FAIL'} {r['cwe']:9} -> {', '.join(c['nativeId'] for c in r['controls'][:5])}")
print("outputs:", s["outputs"])
sys.exit(1 if fail else 0)
