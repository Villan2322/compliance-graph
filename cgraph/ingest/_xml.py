"""Namespace-agnostic XML helpers (CWE and CAPEC bump schema namespaces)."""
from __future__ import annotations

import io
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path


def open_xml(path: Path) -> ET.Element:
    path = Path(path)
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as z:
            name = next(n for n in z.namelist() if n.endswith(".xml"))
            data = z.read(name)
    else:
        data = path.read_bytes()
    it = ET.iterparse(io.BytesIO(data))
    for _, el in it:
        if "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    return it.root


def text(el: ET.Element | None) -> str:
    if el is None:
        return ""
    return " ".join("".join(el.itertext()).split())
