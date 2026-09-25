"""Loaders. Each module exposes parse(path) -> dict and load(graph, data, spec) -> stats.
parse() is pure (tested offline against fixtures); load() does the MERGEs."""
from importlib import import_module

LOADERS = ["nist_800_53", "attack", "ctid", "cwe", "capec", "atlas", "scf", "kev", "epss", "curated"]


def get(name: str):
    if name not in LOADERS:
        raise KeyError(name)
    return import_module(f"cgraph.ingest.{name}")
