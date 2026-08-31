"""Static string extraction.

Cheap, no-dependency implementation: pulls printable ASCII / UTF-16LE
runs above a minimum length. Real implementation (Phase 2+) will use
FLOSS / `strings` / radare2.
"""
from __future__ import annotations

import re
from pathlib import Path

from ..registry import tool
from ...models.common import RiskLevel

ASCII_RE = re.compile(rb"[\x20-\x7e]{%d,}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}")


@tool(
    "static_strings",
    description="Extract printable ASCII + UTF-16LE strings from a file.",
    risk_level=RiskLevel.LOW,
    requires_target=True,
    parameters_schema={"path": "absolute file path", "min_length": "int (default 6)"},
)
def static_strings(path: str, min_length: int = 6) -> dict:
    data = Path(path).read_bytes()
    strings = set()
    for m in ASCII_RE.finditer(data):
        s = m.group(0).decode("ascii", errors="replace")
        if len(s) >= min_length:
            strings.add(s)
    for m in UTF16_RE.finditer(data):
        s = m.group(0).decode("utf-16-le", errors="replace")
        if len(s) >= min_length:
            strings.add(s)
    sorted_strings = sorted(strings)
    return {
        "count": len(sorted_strings),
        "strings": sorted_strings[:512],  # cap for MVP
        "truncated": len(sorted_strings) > 512,
    }
