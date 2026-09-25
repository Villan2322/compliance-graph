"""Runtime settings, all from environment (see .env.example)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(os.environ.get("CGRAPH_ROOT", Path(__file__).resolve().parent.parent))


def _bool(v: str | None, default: bool = False) -> bool:
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    neo4j_uri: str = field(default_factory=lambda: os.environ.get("NEO4J_URI", "bolt://localhost:7687"))
    neo4j_user: str = field(default_factory=lambda: os.environ.get("NEO4J_USER", "neo4j"))
    neo4j_password: str = field(default_factory=lambda: os.environ.get("NEO4J_PASSWORD", "change-me-please"))
    neo4j_database: str = field(default_factory=lambda: os.environ.get("NEO4J_DATABASE", "neo4j"))

    raw_dir: Path = field(default_factory=lambda: Path(os.environ.get("CGRAPH_RAW_DIR", ROOT / "sources" / "raw")))
    out_dir: Path = field(default_factory=lambda: Path(os.environ.get("CGRAPH_OUT_DIR", ROOT / "out")))
    state_dir: Path = field(default_factory=lambda: Path(os.environ.get("CGRAPH_STATE_DIR", ROOT / "state")))

    # LLM is optional. "none" keeps the audit loop fully deterministic.
    llm_provider: str = field(default_factory=lambda: os.environ.get("CGRAPH_LLM_PROVIDER", "none"))
    llm_model: str = field(default_factory=lambda: os.environ.get("CGRAPH_LLM_MODEL", "llama3.1:8b"))
    ollama_base_url: str = field(default_factory=lambda: os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434"))

    review_threshold: int = field(default_factory=lambda: int(os.environ.get("CGRAPH_REVIEW_THRESHOLD", "15")))
    semgrep_extra_configs: str = field(default_factory=lambda: os.environ.get("CGRAPH_SEMGREP_CONFIGS", ""))
    embed_model: str = field(default_factory=lambda: os.environ.get("CGRAPH_EMBED_MODEL", "BAAI/bge-small-en-v1.5"))
    offline: bool = field(default_factory=lambda: _bool(os.environ.get("CGRAPH_OFFLINE")))


def settings() -> Settings:
    return Settings()
