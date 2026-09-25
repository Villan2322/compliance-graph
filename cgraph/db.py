"""Thin Neo4j wrapper: schema application, batched MERGE, read helpers."""
from __future__ import annotations

import logging
import re
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable, Iterator

from neo4j import Driver, GraphDatabase

from .config import Settings, settings

log = logging.getLogger(__name__)


def split_cypher(text: str) -> list[str]:
    """Split a .cypher file into statements on ';' at end of line.
    Strips // comments that sit on their own lines."""
    lines = [ln for ln in text.splitlines() if not ln.strip().startswith("//")]
    body = "\n".join(lines)
    parts = re.split(r";\s*(?:\n|$)", body)
    return [p.strip() for p in parts if p.strip()]


class Graph:
    def __init__(self, cfg: Settings | None = None, driver: Driver | None = None):
        self.cfg = cfg or settings()
        self.driver = driver or GraphDatabase.driver(
            self.cfg.neo4j_uri, auth=(self.cfg.neo4j_user, self.cfg.neo4j_password)
        )

    def close(self) -> None:
        self.driver.close()

    def __enter__(self) -> "Graph":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---- basic ops -------------------------------------------------------
    def verify(self) -> None:
        self.driver.verify_connectivity()

    def run(self, query: str, **params: Any) -> list[dict]:
        records, _, _ = self.driver.execute_query(query, params, database_=self.cfg.neo4j_database)
        return [r.data() for r in records]

    def run_file(self, path: Path) -> int:
        stmts = split_cypher(Path(path).read_text())
        for s in stmts:
            self.run(s)
        log.info("applied %d statements from %s", len(stmts), path)
        return len(stmts)

    def batch(self, query: str, rows: Iterable[dict], size: int = 2000, **params: Any) -> int:
        """UNWIND-based batched write. `query` must reference `$rows`."""
        buf: list[dict] = []
        total = 0
        for row in rows:
            buf.append(row)
            if len(buf) >= size:
                self.run(query, rows=buf, **params)
                total += len(buf)
                buf = []
        if buf:
            self.run(query, rows=buf, **params)
            total += len(buf)
        return total

    @contextmanager
    def session(self) -> Iterator:
        with self.driver.session(database=self.cfg.neo4j_database) as s:
            yield s
