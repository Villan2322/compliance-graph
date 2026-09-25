"""Identifier normalization. Every loader and the agent go through here so
IDs from different publishers join cleanly in the graph."""
from __future__ import annotations

import re

_NIST = re.compile(r"^\s*([A-Za-z]{2})-0*(\d+)(?:[.(]\s*0*(\d+)\)?)?\s*$")


def nist_80053(raw: str) -> str | None:
    """'ac-2.1' | 'AC-02(01)' | 'AC-2 (1)' | 'ac-02' -> 'AC-2(1)' / 'AC-2'."""
    if not raw:
        return None
    m = _NIST.match(raw.replace(" ", ""))
    if not m:
        return None
    fam, num, enh = m.group(1).upper(), int(m.group(2)), m.group(3)
    return f"{fam}-{num}({int(enh)})" if enh else f"{fam}-{num}"


def nist_req(raw: str) -> str | None:
    n = nist_80053(raw)
    return f"NIST-800-53-r5:{n}" if n else None


def req_id(framework_id: str, native_id: str) -> str:
    return f"{framework_id}:{native_id.strip()}"


def cwe(raw) -> str | None:
    """'79' | 'CWE-79' | 'CWE-79: Improper Neutralization…' -> 'CWE-79'."""
    if raw is None:
        return None
    m = re.search(r"(?:CWE[-_ ]?)?(\d+)", str(raw), re.I)
    return f"CWE-{int(m.group(1))}" if m else None


def capec(raw) -> str | None:
    m = re.search(r"(\d+)", str(raw or ""))
    return f"CAPEC-{int(m.group(1))}" if m else None


def attack_technique(raw) -> str | None:
    """'1574.010' | 'T1574.010' -> 'T1574.010'."""
    m = re.match(r"^\s*T?(\d{4})(?:\.(\d{3}))?\s*$", str(raw or ""), re.I)
    if not m:
        return None
    return f"T{m.group(1)}" + (f".{m.group(2)}" if m.group(2) else "")


def cve(raw) -> str | None:
    m = re.search(r"CVE-\d{4}-\d{4,}", str(raw or ""), re.I)
    return m.group(0).upper() if m else None
