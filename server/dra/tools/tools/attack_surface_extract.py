"""Attack surface extraction.

Phase 0/1 uses heuristic rules driven by the analyze_pe + static_strings
output. Real implementation (Phase 2+) will use Ghidra scripts.
"""
from __future__ import annotations

from ..registry import tool
from ...models.common import RiskLevel

# Tokens that suggest an IOCTL dispatch / driver entry surface.
IOCTL_HINTS = {
    "IoCreateDevice",
    "IoCreateSymbolicLink",
    "IoDeviceIoControl",
    "IRP_MJ_DEVICE_CONTROL",
    "DriverEntry",
    "AddDevice",
}

# Strings that often embed IOCTL codes or device names.
DEVICE_HINTS = ("\\\\Device\\\\", "\\\\DosDevices\\\\")


@tool(
    "attack_surface_extract",
    description="Heuristically derive attack surface from analyze_pe + strings.",
    risk_level=RiskLevel.LOW,
    parameters_schema={"pe": "analyze_pe result dict", "strings": "static_strings result dict"},
)
def attack_surface_extract(pe: dict, strings: dict) -> dict:
    items: list[dict] = []
    imports = pe.get("imports", [])
    exports = pe.get("exports", [])
    string_list = strings.get("strings", [])

    for name in imports:
        if any(h.lower() in name.lower() for h in IOCTL_HINTS):
            items.append({
                "kind": "import",
                "name": name,
                "reachability": "unprivileged_user",  # assume; refine later
            })
    for name in exports:
        items.append({
            "kind": "export",
            "name": name,
            "reachability": "unprivileged_user",
        })
    for s in string_list:
        for hint in DEVICE_HINTS:
            if hint in s:
                items.append({
                    "kind": "device_name",
                    "name": s,
                    "reachability": "unprivileged_user",
                })
                break
    # De-duplicate by (kind, name)
    seen = set()
    deduped: list[dict] = []
    for it in items:
        key = (it["kind"], it["name"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(it)
    return {"items": deduped, "count": len(deduped)}
