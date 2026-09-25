"""Optional LLM. The loop works without one; with one, it classifies
findings that arrive without a CWE and writes the executive summary."""
from __future__ import annotations

import json
import logging
import re

from .config import settings

log = logging.getLogger(__name__)


def get_llm():
    cfg = settings()
    if cfg.llm_provider in ("", "none"):
        return None
    from langchain.chat_models import init_chat_model
    kw = {"temperature": 0}
    if cfg.llm_provider == "ollama":
        kw["base_url"] = cfg.ollama_base_url
    try:
        return init_chat_model(cfg.llm_model, model_provider=cfg.llm_provider, **kw)
    except Exception as e:  # missing key / provider package: degrade, don't crash
        log.warning("LLM disabled: %s", e)
        return None


def classify_cwe(llm, finding: dict) -> str | None:
    msg = (
        "Classify this static-analysis finding with the single most specific MITRE CWE ID.\n"
        'Reply with JSON only: {"cwe": "CWE-<number>"} or {"cwe": null} if unsure.\n\n'
        f"Tool: {finding['tool']}\nRule: {finding['ruleId']}\nMessage: {finding['title']}"
    )
    try:
        text = llm.invoke(msg).content
        text = text if isinstance(text, str) else json.dumps(text)
        m = re.search(r"CWE-\d+", text)
        return m.group(0) if m else None
    except Exception as e:
        log.warning("LLM classify failed: %s", e)
        return None


def summarize(llm, risks: list[dict], repo: str) -> str | None:
    if not llm or not risks:
        return None
    lines = [f"- {r['riskId']} {r['rating']} ({r['score']}): {r['cweName']} [{', '.join(c['nativeId'] for c in r['controls'][:3])}]"
             for r in risks[:15]]
    msg = ("Write a 5-sentence executive summary of this application security risk assessment for an auditor. "
           "Plain language, no marketing. State the top risks, the controls they implicate, and what to fix first.\n\n"
           f"Application: {repo}\n" + "\n".join(lines))
    try:
        return llm.invoke(msg).content
    except Exception as e:
        log.warning("LLM summary failed: %s", e)
        return None
