# Roadmap

## v0.2
- SCF STRM tabs (NIST IR 8477 relationship types) instead of main-sheet columns only
- OWASP ASVS 5.0 loader; MITRE D3FEND via n10s (countermeasure layer)
- NIST CSF 2.0, SSDF, AI RMF requirement text from NIST CPRT exports
- Validate OSCAL output with oscal-cli in CI
- Release workflow: build graph in CI → `neo4j-admin database dump` → attach to GitHub release
- `--scope diff` driven by `git diff` (scan only changed files)

## v0.3
- BYOL importers for licensed text (ISO, SOC 2, PCI, CIS), local-only, never dumped
- Embedding-based CWE suggestion for findings without CWE metadata
- Semgrep rule packs for JS/TS, Go, Java, IaC (Terraform, K8s) with CWE metadata
- Evidence collection connectors (CI artifacts, PR links) and control-owner attestations

## Always
- Human review of curated mappings (`reviewed: true` requires a named reviewer in the PR)
