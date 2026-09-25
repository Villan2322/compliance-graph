from __future__ import annotations

from typing import Any

from typing_extensions import TypedDict


class AuditState(TypedDict, total=False):
    run_id: str
    target: str
    repo_id: str
    scope: str                 # "full" | "diff"
    started_at: str
    context: dict[str, Any]    # from <target>/.cgraph.yaml
    non_interactive: bool
    findings: list[dict]
    warnings: list[str]
    tools_run: list[str]
    enrichment: dict[str, Any]  # cwe -> controls/techniques; cve -> kev/epss
    risks: list[dict]
    decisions: dict[str, str]   # riskId -> accept | mitigate | false_positive | pending_review
    outputs: dict[str, str]
