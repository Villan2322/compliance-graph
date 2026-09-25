# compliance-graph

A security and compliance knowledge graph for coding agents.

It loads NIST SP 800-53, the Secure Controls Framework crosswalks, MITRE CWE, CAPEC,
ATT&CK and ATLAS, CISA KEV, and FIRST EPSS into Neo4j Community Edition. Then it gives
agents two things:

1. **Prevention.** An MCP server agents query *before* writing code: "what controls
   apply to file uploads?", "what does CWE-918 implicate?".
2. **Detection.** A LangGraph audit loop that scans a repo, climbs each finding from
   CWE to attack technique to control, scores the risk, pauses for a human on the
   serious ones, and writes a **risk control matrix** (XLSX, CSV, OSCAL-shaped JSON).

Every run is written back to the graph, so audit history compounds.

## Quickstart

Needs Docker and `make`.

```bash
git clone https://github.com/Villan2322/compliance-graph && cd compliance-graph
make up
```

That builds the image, starts Neo4j, applies the ontology, fetches and ingests the
sources (or loads the [prebuilt release dump](https://github.com/Villan2322/compliance-graph/releases)
set via `CGRAPH_DUMP_URL` in `.env.example` -- seconds instead of minutes), verifies
the graph, and starts the MCP server.

The release dump excludes the Secure Controls Framework (SCF is CC BY-ND 4.0 --
see `NOTICE`); everything else in the quickstart list above is included. To add SCF
crosswalks locally: download the free workbook from `securecontrolsframework.com`,
save it as `sources/raw/scf.xlsx`, then `cgraph ingest --only scf`.

```bash
make verify                               # graph health checks
make audit TARGET=/path/to/your/repo      # interactive audit + RCM
make eval                                 # known-answer test on eval/vulnerable_app
```

- Neo4j Browser: http://localhost:7474 (password in `.env`)
- MCP: http://localhost:8765/mcp
- Outputs: `out/<run-id>/rcm.xlsx`, `rcm.csv`, `assessment-results.oscal.json`, `summary.md`

## Use it from Claude Code

This repo ships `.mcp.json`, so Claude Code picks up the server here automatically.
For any other repo:

```bash
claude mcp add --transport http compliance-graph http://localhost:8765/mcp
```

Then paste [docs/CLAUDE_SNIPPET.md](docs/CLAUDE_SNIPPET.md) into that repo's `CLAUDE.md`
so the agent checks the graph before it writes risky code and audits after.

| MCP tool | What it answers |
|---|---|
| `secure_coding_checklist(topic)` | Guidance, CWEs to avoid, controls implicated |
| `controls_for_cwe(cwe_id)` | Direct + threat-path controls, techniques, crosswalk |
| `technique_mitigations(attack_id)` | NIST controls and ATT&CK mitigations |
| `crosswalk(requirement_ids, frameworks)` | NIST → ISO / SOC 2 / PCI / … via SCF |
| `cve_risk(cve_ids)` | KEV, EPSS, ransomware use |
| `search_controls(query)` | Full-text over control text |
| `open_risks(repo_id)` | Open risks from prior runs |
| `run_audit(path)` | Full loop, non-interactive |

## How a finding becomes an RCM row

```
semgrep rule cg-py-sql-string-format  (metadata.cwe = CWE-89)
  → Weakness CWE-89
      → ADDRESSED_BY  SI-10(6) Injection Prevention         (curated, confidence 0.9)
      → CAPEC-66 → T1190 Exploit Public-Facing Application → MITIGATES ← controls (CTID)
  → SCF crosswalk → ISO 27001, SOC 2, PCI DSS IDs
  → score: likelihood (severity, KEV, EPSS, exposure) × impact (data classification)
  → review gate if score ≥ 15 → RCM row with test procedure and evidence required
```

Per-repo context lives in `.cgraph.yaml` at the audited repo's root
(see `eval/vulnerable_app/.cgraph.yaml`).

## Sources and licenses

| Source | Tier | License |
|---|---|---|
| NIST SP 800-53 r5 (OSCAL) | 1 | Public domain |
| MITRE ATT&CK, CWE, CAPEC | 1 | MITRE terms of use (notice required) |
| MITRE ATLAS | 1 | See upstream |
| CTID Mappings Explorer (800-53 ↔ ATT&CK) | 1 | See upstream |
| Secure Controls Framework | 1 | CC BY 4.0 (manual download) |
| CISA KEV | 2 | Public domain |
| FIRST EPSS | 2 | Free with attribution |
| ISO 27001, SOC 2 TSC, PCI DSS, CIS | 3 | **IDs only.** Bring your own licensed text. |

Full attribution in [NOTICE](NOTICE). Details in [ontology/ontology.md](ontology/ontology.md).

## Repo layout

```
ontology/     schema.cypher, seed.cypher, ontology.md, queries.cypher
sources/      manifest.yaml (every dataset, license, tier), scf_columns.yaml
mappings/     curated CWE→control, CWE→ATLAS, secure-coding topics  ← review these
rules/        Semgrep rules; every rule carries metadata.cwe
cgraph/       ingest loaders, knowledge queries, LangGraph audit loop, MCP server, CLI
eval/         deliberately vulnerable app + expected findings
scripts/      bootstrap.sh, run_eval.py
```

## Status and honesty

v0.1. The curated CWE→control mappings ship with `reviewed: false` and appear as
"flagged for review" in every RCM until a qualified reviewer signs off. Output is
decision support for an assessor, not an attestation. The OSCAL file is
OSCAL-*shaped*; validate it with `oscal-cli` before importing into a GRC tool.

## License

Code: Apache-2.0. Data: each source's own license (see NOTICE).
