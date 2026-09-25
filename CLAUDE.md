# CLAUDE.md — working in compliance-graph

## What this is
Neo4j (Community 5.26) knowledge graph of controls, weaknesses and threats, plus a
LangGraph audit loop and an MCP server. Python 3.12, package `cgraph`.

## Commands
- `make up` — full bootstrap (Docker). `make verify`, `make eval`, `make test`.
- Local dev without Docker for the app: `pip install -e ".[all]"`, run Neo4j via compose,
  export `NEO4J_URI=bolt://localhost:7687 NEO4J_PASSWORD=<from .env>`, then `cgraph ...`.
- `cgraph init | fetch | ingest [--only id ...] | verify | audit PATH | mcp | embed | scf-headers`

## Rules that keep the graph trustworthy
1. Every node and edge a loader writes has `sourceId`. `cgraph verify` enforces it.
2. `MERGE`, never `CREATE`, in loaders. Re-ingest must be idempotent.
3. Parameterized Cypher only. Never format user or file input into a query string.
4. Never write Tier 3 text (ISO, AICPA, PCI, CIS) into the graph or a dump. IDs only.
5. Curated mappings (`mappings/*.yaml`) start `reviewed: false`. Only a human flips it.
6. Every Semgrep rule needs `metadata.cwe`, and that CWE needs a control mapping
   (`tests/test_parsers.py::test_curated_mappings_resolve_ids` enforces this).
7. Loader = pure `parse(path)` + `load(graph, data, spec)`. Test `parse` offline.
8. LangGraph code: check current docs (Context7) before changing state, interrupts
   or checkpointers. The loop must still run with `CGRAPH_LLM_PROVIDER=none`.

## Where things are
- Ontology: `ontology/` (schema, seed, docs). Change the doc when you change the schema.
- Sources: `sources/manifest.yaml`. New source = manifest entry + loader + fixture test.
- Audit loop: `cgraph/agent/graph.py` (nodes), `scoring.py`, `rcm.py`, `persist.py`.
- Agent-facing queries: `cgraph/knowledge.py` (shared by MCP and the loop).
