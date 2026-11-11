"""PE / binary header inspection backed by `pefile`.

The result is a plain, JSON-serialisable dict so it can be persisted by
the tool gateway and consumed by other tools (attack_surface_extract,
ioctl_extract).  Every field that cannot be determined from the file is
reported as ``None`` / an empty list -- never guessed.

Contract (backwards compatible with the previous hand-rolled parser):

  analyze_pe(path) -> {
    file_type, sha256, size, machine, subsystem, ...
    sections[], imports[], imports_by_module[], exports[], notes[]
  }

``imports`` is kept as a flat list of imported symbol names because the
recon agent (and older callers) consume it as strings.  The structured
view lives in ``imports_by_module``.  ``exports`` is structured and now
contains export ``name``/``ordinal``/``rva``/``va``.
"""

import hashlib
from pathlib import Path

import pefile

from ..registry import tool
from ...models.common import RiskLevel
from ...storage.artifact_store import FileSystemArtifactStore
from ...config import SETTINGS

MZ_SIG = b"MZ"

MACHINES = {
    0x014C: "i386",
    0x0162: "mips_r3000",
    0x0166: "mips_r4000",
    0x0168: "mips_r10000",
    0x0169: "mips_wce_v2",
    0x0184: "alpha",
    0x01A2: "sh3",
    0x01A3: "sh3_dsp",
    0x01A4: "sh3e",
    0x01A6: "sh4",
    0x01A8: "sh5",
    0x01C0: "arm",
    0x01C2: "thumb",
    0x01C4: "armv7",
    0x0200: "ia64",
    0x0266: "mips16",
    0x0284: "alpha64",
    0x0366: "mips_fpu",
    0x0466: "mips16_fpu",
    0x0520: "mips_wce_v4",
    0x0EBC: "ebc",
    0x8664: "x86_64",
    0x9041: "m32r",
    0xAA64: "arm64",
    0xC0EE: "cEE",
}

SUBSYSTEMS = {
    0: "unknown",
    1: "native",
    2: "windows_gui",
    3: "windows_cui",
    5: "os2_cui",
    7: "posix_cui",
    8: "native_windows",
    9: "windows_ce_gui",
    10: "efi_application",
    11: "efi_boot_service_driver",
    12: "efi_runtime_driver",
    13: "efi_rom",
    14: "xbox",
    16: "windows_boot_application",
}

DLL_CHARACTERISTIC_FLAGS = {
    0x0020: "high_entropy_va",
    0x0040: "dynamic_base",
    0x0080: "force_integrity",
    0x0100: "nx_compat",
    0x0200: "no_isolation",
    0x0400: "no_seh",
    0x0800: "no_bind",
    0x1000: "appcontainer",
    0x2000: "wdm_driver",
    0x4000: "guard_cf",
    0x8000: "terminal_server_aware",
}

FILE_CHARACTERISTIC_FLAGS = {
    0x0001: "relocs_stripped",
    0x0002: "executable_image",
    0x0004: "line_nums_stripped",
    0x0008: "local_syms_stripped",
    0x0010: "aggressive_ws_trim",
    0x0020: "large_address_aware",
    0x0100: "32bit_machine",
    0x0200: "debug_stripped",
    0x0400: "removable_run_from_swap",
    0x0800: "net_run_from_swap",
    0x1000: "system",
    0x2000: "dll",
    0x4000: "up_system_only",
}


def _read_file(path: Path) -> bytes:
    return Path(path).read_bytes()


def _decode_name(raw) -> str | None:
    if raw is None:
        return None
    if isinstance(raw, bytes):
        return raw.decode("ascii", errors="replace")
    return str(raw)


def _flags(value: int, table: dict[int, str]) -> list[str]:
    return [name for bit, name in table.items() if value & bit]


def _zero_result(sha: str, size: int, file_type: str, notes: list[str]) -> dict:
    return {
        "file_type": file_type,
        "sha256": sha,
        "size": size,
        "machine": None,
        "subsystem": None,
        "characteristics": None,
        "characteristics_flags": [],
        "dll_characteristics": None,
        "dll_characteristics_flags": [],
        "timestamp": None,
        "image_base": None,
        "entry_point_rva": None,
        "is_64bit": None,
        "sections": [],
        "imports": [],
        "imports_by_module": [],
        "exports": [],
        "export_names": [],
        "overlay": None,
        "source_path": None,
        "notes": notes,
    }


def analyze_pe_bytes(data: bytes, *, source_path: str | None = None) -> dict:
    """Parse *data* as a PE file.  Never raises on malformed input."""
    sha = hashlib.sha256(data).hexdigest()
    size = len(data)
    notes: list[str] = []

    result = _zero_result(sha, size, "unknown", notes)
    if not data.startswith(MZ_SIG):
        notes.append("not an MZ/PE file; only hash/size available")
        return result
    if len(data) < 0x40:
        result["file_type"] = "mz_short"
        notes.append("file too short for an MZ header")
        return result

    try:
        pe = pefile.PE(data=data, fast_load=False)
    except pefile.PEFormatError as exc:
        result["file_type"] = "pe_invalid"
        notes.append(f"pefile could not parse the PE: {exc}")
        return result
    except Exception as exc:  # noqa: BLE001 - parser robustness for untrusted input
        result["file_type"] = "pe_invalid"
        notes.append(f"unexpected PE parse failure: {type(exc).__name__}: {exc}")
        return result

    try:
        _fill_pe_fields(pe, data, result, notes)
    except Exception as exc:  # noqa: BLE001 - never crash on hostile input
        notes.append(
            f"partial PE parse failure: {type(exc).__name__}: {exc}; "
            "fields parsed before the failure are retained"
        )
    finally:
        pe.close()

    result["source_path"] = str(source_path) if source_path else None
    return result


def _fill_pe_fields(pe, data: bytes, result: dict, notes: list[str]) -> None:
    fh = pe.FILE_HEADER
    oh = pe.OPTIONAL_HEADER
    is_64 = oh.Magic == 0x20B
    if is_64:
        result["file_type"] = "pe32+"
    elif oh.Magic == 0x10B:
        result["file_type"] = "pe32"
    else:
        result["file_type"] = f"pe_unknown_magic_0x{oh.Magic:X}"
        notes.append(
            f"unexpected optional-header magic 0x{oh.Magic:X}; "
            "expected 0x10B (PE32) or 0x20B (PE32+)"
        )
    result["machine"] = MACHINES.get(fh.Machine, f"0x{fh.Machine:04X}")
    result["characteristics"] = fh.Characteristics
    result["characteristics_flags"] = _flags(fh.Characteristics, FILE_CHARACTERISTIC_FLAGS)
    result["dll_characteristics"] = oh.DllCharacteristics
    result["dll_characteristics_flags"] = _flags(oh.DllCharacteristics, DLL_CHARACTERISTIC_FLAGS)
    result["subsystem"] = SUBSYSTEMS.get(oh.Subsystem, f"unknown_0x{oh.Subsystem:X}")
    result["timestamp"] = fh.TimeDateStamp
    result["image_base"] = oh.ImageBase
    result["entry_point_rva"] = oh.AddressOfEntryPoint
    result["is_64bit"] = is_64

    sections = []
    for sec in pe.sections:
        name = _decode_name(sec.Name.rstrip(b"\x00")) or ""
        sections.append(
            {
                "name": name,
                "virtual_address": sec.VirtualAddress,
                "virtual_size": sec.Misc_VirtualSize,
                "raw_address": sec.PointerToRawData,
                "raw_size": sec.SizeOfRawData,
                "characteristics": sec.Characteristics,
                "entropy": round(float(sec.get_entropy()), 3),
            }
        )
    result["sections"] = sections

    # --- imports -----------------------------------------------------
    flat: list[str] = []
    by_module: list[dict] = []
    seen: set[str] = set()
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        module = _decode_name(entry.dll) or "unknown"
        funcs: list[dict] = []
        for imp in entry.imports:
            name = _decode_name(imp.name)
            ordinal = getattr(imp, "ordinal", None)
            display = name if name else f"ordinal_{ordinal}"
            iat_rva = None
            addr = getattr(imp, "address", None)
            if isinstance(addr, int) and addr:
                image_base = oh.ImageBase
                iat_rva = addr - image_base if addr >= image_base else addr
            funcs.append({"name": name, "ordinal": ordinal, "iat_rva": iat_rva})
            if display not in seen:
                seen.add(display)
                flat.append(display)
        by_module.append({"module": module, "functions": funcs})
    result["imports"] = flat
    result["imports_by_module"] = by_module
    if not by_module:
        notes.append("no import directory / no imports parsed")

    # --- exports -----------------------------------------------------
    exports: list[dict] = []
    export_names: list[str] = []
    export_dir = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if export_dir is not None:
        image_base = oh.ImageBase
        for sym in export_dir.symbols:
            name = _decode_name(sym.name)
            rva = int(sym.address)
            item = {
                "name": name,
                "ordinal": int(sym.ordinal),
                "rva": rva,
                "va": image_base + rva,
            }
            forwarder = getattr(sym, "forwarder", None)
            if forwarder:
                item["forwarder"] = _decode_name(forwarder)
            exports.append(item)
            if name:
                export_names.append(name)
    else:
        notes.append("no export directory present")
    result["exports"] = exports
    result["export_names"] = export_names

    # Overlay = bytes after the last section's raw data.
    try:
        last_end = max(
            (s["raw_address"] + s["raw_size"] for s in sections if s["raw_size"]),
            default=0,
        )
        result["overlay"] = max(0, len(data) - last_end)
    except Exception:  # noqa: BLE001 - overlay is informational only
        result["overlay"] = None

    warnings = list(getattr(pe, "get_warnings", lambda: [])())
    for warning in warnings[:8]:
        notes.append(f"pefile warning: {warning}")
    if len(warnings) > 8:
        notes.append(f"pefile reported {len(warnings) - 8} additional warnings")


@tool(
    "analyze_pe",
    description="Parse PE headers, sections, imports and exports (no execution).",
    risk_level=RiskLevel.LOW,
    requires_target=True,
    parameters_schema={"path": "absolute file path"},
)
def analyze_pe(path: str) -> dict:
    data = _read_file(Path(path))
    return analyze_pe_bytes(data, source_path=path)


@tool(
    "ingest_target",
    description="Hash a sample and register it in the artefact store.",
    risk_level=RiskLevel.LOW,
    requires_target=True,
    parameters_schema={"path": "absolute file path"},
)
def ingest_target(path: str) -> dict:
    p = Path(path)
    data = p.read_bytes()
    store = FileSystemArtifactStore(SETTINGS.artefact_root)
    sha = store.put(data, content_type="application/octet-stream")
    return {
        "sha256": sha,
        "size": len(data),
        "name": p.name,
    }
