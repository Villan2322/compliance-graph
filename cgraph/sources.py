"""Source manifest, downloads with checksum pinning, and (:Source) provenance."""
from __future__ import annotations

import hashlib
import logging
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml

from .config import ROOT, settings

log = logging.getLogger(__name__)
MANIFEST = ROOT / "sources" / "manifest.yaml"
USER_AGENT = "compliance-graph/0.1 (+https://github.com/)"


@dataclass
class SourceSpec:
    id: str
    loader: str
    name: str
    publisher: str
    url: str
    file: str
    license: str
    tier: int
    manual: bool = False
    local: bool = False
    version: str | None = None
    sha256: str | None = None
    depends_on: list[str] = field(default_factory=list)

    @property
    def path(self) -> Path:
        return settings().raw_dir / self.file


def load_manifest(path: Path = MANIFEST) -> list[SourceSpec]:
    data = yaml.safe_load(Path(path).read_text())
    return [SourceSpec(**s) for s in data["sources"]]


def ordered(specs: list[SourceSpec]) -> list[SourceSpec]:
    """Topological order by depends_on so edges always find their endpoints."""
    by_id = {s.id: s for s in specs}
    seen: set[str] = set()
    out: list[SourceSpec] = []

    def visit(s: SourceSpec) -> None:
        if s.id in seen:
            return
        seen.add(s.id)
        for d in s.depends_on:
            if d in by_id:
                visit(by_id[d])
        out.append(s)

    for s in specs:
        visit(s)
    return out


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(spec: SourceSpec, force: bool = False) -> Path | None:
    if spec.local:
        return None
    dest = spec.path
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and not force:
        log.info("[%s] cached at %s", spec.id, dest)
    elif not spec.url:
        if spec.manual:
            log.warning("[%s] manual source: place the file at %s", spec.id, dest)
            return dest if dest.exists() else None
        raise ValueError(f"{spec.id}: no url")
    else:
        log.info("[%s] downloading %s", spec.id, spec.url)
        req = urllib.request.Request(spec.url, headers={"User-Agent": USER_AGENT})
        tmp = dest.with_suffix(dest.suffix + ".part")
        with urllib.request.urlopen(req, timeout=300) as r, open(tmp, "wb") as f:
            while chunk := r.read(1 << 20):
                f.write(chunk)
        tmp.replace(dest)
    if spec.sha256:
        got = sha256(dest)
        if got != spec.sha256:
            raise ValueError(f"{spec.id}: checksum mismatch ({got} != pinned {spec.sha256})")
    return dest


# Loaders don't share a version key name (each upstream format calls it
# something different) -- checked in this priority order against the load()
# stats dict when manifest.yaml hasn't pinned spec.version explicitly.
_VERSION_KEYS = ("version", "catalogVersion", "attackVersion", "cweVersion",
                 "capecVersion", "atlasVersion", "scoreDate")


def record_source(graph, spec: SourceSpec, path: Path | None, stats: dict) -> None:
    version = spec.version or next((str(stats[k]) for k in _VERSION_KEYS if stats.get(k)), None)
    graph.run(
        """
        MERGE (s:Source {sourceId: $id})
        SET s.name = $name, s.publisher = $publisher, s.url = $url, s.license = $license,
            s.tier = $tier, s.version = $version, s.sha256 = $sha,
            s.retrievedAt = datetime($ts), s.loader = $loader, s.stats = $stats
        """,
        id=spec.id, name=spec.name, publisher=spec.publisher, url=spec.url, license=spec.license,
        tier=spec.tier, version=version, loader=spec.loader,
        sha=(sha256(path) if path and path.exists() else None),
        ts=datetime.now(timezone.utc).isoformat(),
        stats=[f"{k}={v}" for k, v in stats.items()],
    )
