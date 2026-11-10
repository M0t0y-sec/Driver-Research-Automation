"""Attack surface extraction driven by real static facts.

The old implementation labelled every item ``unprivileged_user`` on the
assumption that IOCTL surfaces are user reachable.  That assumption is
gone: reachability is derived from evidence produced by
``ioctl_extract`` (device names, an installed
``IRP_MJ_DEVICE_CONTROL`` handler, IOCTL-code comparisons).  When the
available evidence cannot establish what privilege a caller needs, the
value is ``"unknown"`` -- never a fabricated privilege level.

Facts are taken from, in order:

  1. the ``ioctl`` argument (a previous ``ioctl_extract`` result),
  2. ``pe["ioctl_analysis"]`` if a caller embedded one,
  3. a fresh ``ioctl_extract`` run on ``path`` / ``pe["source_path"]``,
  4. the PE/strings dictionaries alone (no disassembly), with
     reachability left at ``"unknown"``.
"""
from __future__ import annotations

from ..registry import tool
from ...models.common import RiskLevel
from .ioctl_extract import ioctl_extract as _run_ioctl_extract

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
DEVICE_HINTS = ("\\Device\\", "\\DosDevices\\")

UNKNOWN_PRIVILEGE = "unknown"


def _reachability(
    *,
    access_conditions: list[str],
    interface_exposure: str | None = None,
) -> dict:
    """Build a reachability record with an honest, undetermined privilege."""
    return {
        "required_privilege": UNKNOWN_PRIVILEGE,
        "attack_actor": "unknown",
        "access_conditions": access_conditions,
        "interface_exposure": interface_exposure,
        "basis": "static evidence insufficient to determine ACL/access checks",
    }


def _fetch_facts(pe: dict, path: str | None, ioctl: dict | None, notes: list[str]) -> tuple[dict | None, str]:
    facts = ioctl if isinstance(ioctl, dict) else None
    basis = "ioctl_extract" if facts is not None else "none"
    if facts is None:
        embedded = pe.get("ioctl_analysis") if isinstance(pe, dict) else None
        if isinstance(embedded, dict):
            facts = embedded
            basis = "ioctl_extract(embedded)"
    if facts is None:
        source = path or (pe.get("source_path") if isinstance(pe, dict) else None)
        if source:
            try:
                facts = _run_ioctl_extract(source)
                basis = "ioctl_extract"
            except Exception as exc:  # noqa: BLE001 - surface analysis must not crash
                notes.append(f"ioctl_extract failed on {source!r}: {type(exc).__name__}: {exc}")
    if facts is None:
        notes.append(
            "no ioctl_extract facts available (no path/source_path supplied); "
            "falling back to PE/strings evidence and leaving reachability unknown"
        )
    return facts, basis


def _export_display_name(export: dict) -> str:
    name = export.get("name")
    if name:
        return str(name)
    return f"ordinal_{export.get('ordinal', '?')}"


@tool(
    "attack_surface_extract",
    description=(
        "Derive attack-surface items from PE parsing plus ioctl_extract facts. "
        "Reachability is left 'unknown' unless the evidence determines it."
    ),
    risk_level=RiskLevel.LOW,
    parameters_schema={
        "pe": "analyze_pe result dict",
        "strings": "static_strings result dict (optional)",
        "ioctl": "ioctl_extract result dict (optional)",
        "path": "absolute driver path (optional; enables ioctl_extract)",
    },
)
def attack_surface_extract(
    pe: dict,
    strings: dict | None = None,
    ioctl: dict | None = None,
    path: str | None = None,
) -> dict:
    notes: list[str] = []
    facts, basis = _fetch_facts(pe, path, ioctl, notes)
    items: list[dict] = []

    if facts:
        device_names = list(facts.get("device_names") or [])
        handler_rva = facts.get("device_control_handler_rva")
        handler_va = facts.get("device_control_handler_va")
        device_refs = {
            ref.get("name"): ref.get("rva")
            for ref in (facts.get("device_name_refs") or [])
            if isinstance(ref, dict)
        }

        # --- IOCTL code comparisons -------------------------------
        all_codes = list(facts.get("ioctl_codes") or [])
        plausible = [c for c in all_codes if c.get("plausible")]
        for code in plausible:
            code_value = int(code.get("code", 0))
            conditions = ["IRP_MJ_DEVICE_CONTROL dispatch handler observed statically"]
            if device_names:
                conditions.append(
                    "caller must obtain a handle to one of: " + ", ".join(device_names)
                )
            else:
                conditions.append("no device name resolved; handle acquisition unknown")
            conditions.append("device ACL / access checks not analysed")
            items.append(
                {
                    "kind": "ioctl",
                    "name": f"IOCTL 0x{code_value:08X}",
                    "address_or_offset": f"ref_va=0x{int(code.get('ref_va', 0)):X}",
                    "reachability": UNKNOWN_PRIVILEGE,
                    "reachability_detail": _reachability(access_conditions=conditions),
                    "parameters": {
                        "code": code_value,
                        "code_hex": f"0x{code_value:08X}",
                        "ref_rva": code.get("ref_rva"),
                        "instruction": code.get("instruction"),
                        "ctl_code": code.get("ctl_code"),
                        "handler_rva": handler_rva,
                    },
                }
            )
        if len(all_codes) > len(plausible):
            notes.append(
                f"{len(all_codes) - len(plausible)} comparison immediate(s) did not "
                "look like CTL_CODE values (device type 0) and were not emitted as ioctl items"
            )

        # --- dispatch handler -------------------------------------
        if handler_rva is not None:
            conditions = ["DriverEntry writes MajorFunction[IRP_MJ_DEVICE_CONTROL]"]
            conditions.extend(
                f"device object exposed as {name}" for name in device_names[:4]
            )
            conditions.append("dispatch handler body was disassembled statically")
            items.append(
                {
                    "kind": "dispatch",
                    "name": "IRP_MJ_DEVICE_CONTROL",
                    "address_or_offset": f"rva=0x{int(handler_rva):X}",
                    "reachability": UNKNOWN_PRIVILEGE,
                    "reachability_detail": _reachability(access_conditions=conditions),
                    "parameters": {
                        "handler_rva": handler_rva,
                        "handler_va": handler_va,
                        "driver_entry_rva": facts.get("driver_entry_rva"),
                        "ioctl_code_count": len(plausible),
                    },
                }
            )

        # --- device names -----------------------------------------
        for name in device_names:
            items.append(
                {
                    "kind": "device",
                    "name": name,
                    "address_or_offset": (
                        f"rva=0x{int(device_refs[name]):X}"
                        if device_refs.get(name) is not None
                        else None
                    ),
                    "reachability": UNKNOWN_PRIVILEGE,
                    "reachability_detail": _reachability(
                        access_conditions=[
                            "device/symlink name found as a UTF-16LE literal",
                            "device ACL / symbolic-link ACL not analysed",
                        ],
                        interface_exposure=name,
                    ),
                    "parameters": {"source": "rdata_utf16le"},
                }
            )

        # --- security-relevant imports ----------------------------
        for imp in facts.get("imports_of_interest") or []:
            name = imp.get("name") or ""
            if not name:
                continue
            items.append(
                {
                    "kind": "import",
                    "name": name,
                    "address_or_offset": (
                        f"iat_rva=0x{int(imp['iat_rva']):X}"
                        if imp.get("iat_rva") is not None
                        else None
                    ),
                    "reachability": UNKNOWN_PRIVILEGE,
                    "reachability_detail": _reachability(
                        access_conditions=[
                            "imported primitive; call path and caller privileges not analysed"
                        ]
                    ),
                    "parameters": {"module": imp.get("module")},
                }
            )

        if not plausible and handler_rva is None:
            notes.append(
                "ioctl_extract found neither a device-control handler nor plausible "
                "IOCTL codes; no ioctl/dispatch items were emitted"
            )
    else:
        # Fallback: PE/strings facts only.  Still no privilege guesses.
        for name in pe.get("imports", []) or []:
            if not isinstance(name, str):
                continue
            if any(h.lower() in name.lower() for h in IOCTL_HINTS):
                items.append(
                    {
                        "kind": "import",
                        "name": name,
                        "address_or_offset": None,
                        "reachability": UNKNOWN_PRIVILEGE,
                        "reachability_detail": _reachability(
                            access_conditions=[
                                "import name matches an IOCTL-related token",
                                "no disassembly performed; handler/call path unknown",
                            ]
                        ),
                        "parameters": {"source": "import_name_heuristic"},
                    }
                )
        for export in pe.get("exports", []) or []:
            if not isinstance(export, dict):
                continue
            items.append(
                {
                    "kind": "export",
                    "name": _export_display_name(export),
                    "address_or_offset": (
                        f"rva=0x{int(export['rva']):X}"
                        if export.get("rva") is not None
                        else None
                    ),
                    "reachability": UNKNOWN_PRIVILEGE,
                    "reachability_detail": _reachability(
                        access_conditions=[
                            "export present; no call/reachability analysis performed"
                        ]
                    ),
                    "parameters": {"ordinal": export.get("ordinal")},
                }
            )
        string_list = (strings or {}).get("strings", []) or []
        for text in string_list:
            if not isinstance(text, str):
                continue
            if any(hint in text for hint in DEVICE_HINTS):
                items.append(
                    {
                        "kind": "device",
                        "name": text,
                        "address_or_offset": None,
                        "reachability": UNKNOWN_PRIVILEGE,
                        "reachability_detail": _reachability(
                            access_conditions=[
                                "device-like string found",
                                "device ACL / access checks not analysed",
                            ]
                        ),
                        "parameters": {"source": "static_strings"},
                    }
                )

    # De-duplicate by (kind, name, address) while preserving order.
    seen: set[tuple] = set()
    deduped: list[dict] = []
    for item in items:
        key = (item["kind"], item["name"], item.get("address_or_offset"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)

    facts_summary = None
    if facts:
        facts_summary = {
            "driver_entry_rva": facts.get("driver_entry_rva"),
            "device_control_handler_rva": facts.get("device_control_handler_rva"),
            "ioctl_code_count": len(facts.get("ioctl_codes") or []),
            "plausible_ioctl_code_count": len(
                [c for c in facts.get("ioctl_codes") or [] if c.get("plausible")]
            ),
            "device_names": list(facts.get("device_names") or []),
            "confidence": facts.get("confidence", "unknown"),
            "analysis_status": facts.get("analysis_status", "unknown"),
        }

    return {
        "items": deduped,
        "count": len(deduped),
        "basis": basis,
        "ioctl_facts": facts_summary,
        "notes": notes,
    }
