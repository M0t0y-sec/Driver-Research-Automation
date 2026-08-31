"""Lightweight PE / binary header inspection.

We deliberately avoid the `pefile` dependency. The real Phase 2
implementation can swap the body while keeping the contract intact:

  analyze_pe(target_id, project_id) -> {
    file_type, machine, size, sha256, sections[], imports[], exports[], notes[]
  }
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path

from ..registry import tool
from ...models.common import RiskLevel
from ...storage.artifact_store import FileSystemArtifactStore
from ...config import SETTINGS

MZ_SIG = b"MZ"
PE_SIG = b"PE\x00\x00"

# Machine types we recognise (subset is fine)
MACHINES = {
    0x014C: "i386",
    0x0200: "ia64",
    0x8664: "x86_64",
    0x01C0: "arm",
    0xAA64: "arm64",
}


def _read_file(path: Path) -> bytes:
    return Path(path).read_bytes()


@tool(
    "analyze_pe",
    description="Parse PE headers, sections, imports, exports (no execution).",
    risk_level=RiskLevel.LOW,
    requires_target=True,
    parameters_schema={"path": "absolute file path"},
)
def analyze_pe(path: str) -> dict:
    data = _read_file(Path(path))
    sha = hashlib.sha256(data).hexdigest()
    notes: list[str] = []
    if not data.startswith(MZ_SIG):
        notes.append("not an MZ/PE file; emitting generic analysis only")
        return {
            "file_type": "unknown",
            "sha256": sha,
            "size": len(data),
            "machine": None,
            "sections": [],
            "imports": [],
            "exports": [],
            "notes": notes,
        }
    # DOS header: e_lfanew at offset 0x3C
    if len(data) < 0x40:
        notes.append("file too short for MZ header")
        return {"file_type": "mz_short", "sha256": sha, "size": len(data), "notes": notes}
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew : e_lfanew + 4] != PE_SIG:
        notes.append("MZ present but no PE signature")
        return {"file_type": "mz_no_pe", "sha256": sha, "size": len(data), "notes": notes}
    # COFF header at e_lfanew + 4
    coff = e_lfanew + 4
    if len(data) < coff + 20:
        return {"file_type": "pe_short", "sha256": sha, "size": len(data), "notes": notes}
    machine, _num_sections, _ts, _sym_table, _n_sym, opt_size, characteristics = struct.unpack_from(
        "<HHIIIHH", data, coff
    )
    opt_hdr = coff + 20
    magic = struct.unpack_from("<H", data, opt_hdr)[0] if opt_size >= 2 else 0
    file_type = "pe32+" if magic == 0x20B else "pe32"
    sections: list[dict] = []
    sec_off = opt_hdr + opt_size
    for _ in range(_num_sections):
        if sec_off + 40 > len(data):
            break
        name_bytes = data[sec_off : sec_off + 8].rstrip(b"\x00")
        vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", data, sec_off + 8)
        sections.append(
            {
                "name": name_bytes.decode("ascii", errors="replace"),
                "virtual_size": vsize,
                "virtual_address": vaddr,
                "raw_size": rsize,
                "raw_address": raddr,
            }
        )
        sec_off += 40
    # Very rough import/export scrape (enough for an attack surface hint)
    imports = _scrape_imports(data, sections, opt_hdr, opt_size, magic, file_type)
    exports = _scrape_exports(data, sections)
    return {
        "file_type": file_type,
        "sha256": sha,
        "size": len(data),
        "machine": MACHINES.get(machine, f"0x{machine:04X}"),
        "characteristics": characteristics,
        "sections": sections,
        "imports": imports,
        "exports": exports,
        "notes": notes,
    }


def _scrape_imports(data, sections, opt_hdr, opt_size, magic, file_type) -> list[str]:
    """Heuristic import scrape. Not authoritative; flagged accordingly."""
    if magic == 0x20B:
        # PE32+: import table RVA at opt_hdr+24 (data directory entry 1)
        import_rva_off = opt_hdr + 24 * 8 + 8
    else:
        import_rva_off = opt_hdr + 24 * 4 + 8
    if import_rva_off + 4 > len(data):
        return []
    import_rva = struct.unpack_from("<I", data, import_rva_off)[0]
    if import_rva == 0:
        return []
    # Convert RVA -> file offset by walking sections
    for sec in sections:
        if sec["virtual_address"] <= import_rva < sec["virtual_address"] + sec["virtual_size"]:
            file_off = sec["raw_address"] + (import_rva - sec["virtual_address"])
            break
    else:
        return []
    names: list[str] = []
    # Walk IMAGE_IMPORT_DESCRIPTORs (20 bytes each), terminated by all-zero.
    for _ in range(64):
        chunk = data[file_off : file_off + 20]
        if len(chunk) < 20 or chunk == b"\x00" * 20:
            break
        _orig_first_thunk, _ts, _fwd_chain, name_rva, _first_thunk = struct.unpack_from(
            "<IIIII", chunk
        )
        # name_rva is RVA to the DLL name (null-terminated ASCII)
        for sec in sections:
            if sec["virtual_address"] <= name_rva < sec["virtual_address"] + sec["virtual_size"]:
                off = sec["raw_address"] + (name_rva - sec["virtual_address"])
                end = data.find(b"\x00", off)
                if end == -1:
                    break
                names.append(data[off:end].decode("ascii", errors="replace"))
                break
        file_off += 20
    return names


def _scrape_exports(data, sections) -> list[str]:
    """Heuristic export scrape. Same caveats as imports."""
    if not sections:
        return []
    # Use the export directory's RVA: data directory entry 0.
    # For PE32 it's at offset 96 from opt_hdr start; PE32+ at 112.
    # We don't have the opt_hdr here; use the heuristic of finding
    # common strings ("DriverEntry", "IoCreateDevice") in the .text/.rdata
    # section to seed entries. This is *not* a real export table parse.
    candidates = []
    seeds = [b"DriverEntry", b"DriverUnload", b"AddDevice", b"IoCreateDevice", b"IoCreateSymbolicLink"]
    for sec in sections:
        if not sec["name"].lower().startswith(("text", "rdata", "data")):
            continue
        start = sec["raw_address"]
        end = start + sec["raw_size"]
        if start >= len(data) or end > len(data):
            continue
        body = data[start:end]
        for seed in seeds:
            if seed in body:
                candidates.append(seed.decode("ascii"))
    return sorted(set(candidates))


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
