# Contributing

The most valuable contributions are **reviewed mappings**. If you have audit or AppSec
experience, pick a line in `mappings/cwe_to_controls.yaml`, check the rationale against
the control text, and open a PR flipping `reviewed: true` with your name and reasoning.

Other good first contributions: a loader from the roadmap, Semgrep rules for a new
language (each rule needs `metadata.cwe`), or a new eval fixture.

Every PR: `make test` passes; new sources have a manifest entry with license and tier;
nothing from Tier 3 sources enters the repo or a dump.
