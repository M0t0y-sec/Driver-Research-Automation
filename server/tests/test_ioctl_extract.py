"""Tests for the pefile/capstone static-analysis core.

Synthetic PE images are assembled in-process so the tests are hermetic
and cover x64/x86, exported and non-exported DriverEntry, an IOCTL
dispatch handler, a jump-table switch, and a driver with no IOCTL
surface at all.
"""

import struct

import pytest

from dra.tools.tools.ioctl_extract import ioctl_extract
from dra.tools.tools.analyze_pe import analyze_pe_bytes
from dra.tools.tools.attack_surface_extract import attack_surface_extract

TEXT_RVA = 0x1000
RDATA_RVA = 0x2000
X64_BASE = 0x140000000
X86_BASE = 0x10000000
HANDLER_RVA_X64 = 0x1019
HANDLER_RVA_X86 = 0x1011


# ---------------------------------------------------------------------------
# Minimal PE builder
# ---------------------------------------------------------------------------

def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _build_pe(
    *,
    machine: int,
    is_64: bool,
    image_base: int,
    entry_rva: int,
    code: bytes,
    rdata: bytes,
    data_dirs: dict[int, tuple[int, int]],
) -> bytes:
    opt_size = 0xF0 if is_64 else 0xE0
    num_sections = 2
    headers_end = 0x44 + 20 + opt_size + num_sections * 40
    text_raw = _align(headers_end, 0x200)
    text_raw_size = _align(len(code), 0x200)
    rdata_raw = text_raw + text_raw_size
    rdata_raw_size = _align(len(rdata), 0x200)
    size_image = _align(RDATA_RVA + len(rdata), 0x1000)

    headers = bytearray(text_raw)
    headers[0:2] = b"MZ"
    struct.pack_into("<I", headers, 0x3C, 0x40)
    headers[0x40:0x44] = b"PE\x00\x00"
    characteristics = 0x0022 if is_64 else 0x0102
    struct.pack_into(
        "<HHIIIHH",
        headers,
        0x44,
        machine,
        num_sections,
        0,
        0,
        0,
        opt_size,
        characteristics,
    )

    opt = 0x58
    if is_64:
        struct.pack_into("<H", headers, opt, 0x20B)
        headers[opt + 2] = 1
        struct.pack_into("<I", headers, opt + 0x04, len(code))
        struct.pack_into("<I", headers, opt + 0x08, len(rdata))
        struct.pack_into("<I", headers, opt + 0x10, entry_rva)
        struct.pack_into("<I", headers, opt + 0x14, TEXT_RVA)
        struct.pack_into("<Q", headers, opt + 0x18, image_base)
        struct.pack_into("<I", headers, opt + 0x20, 0x1000)
        struct.pack_into("<I", headers, opt + 0x24, 0x200)
        struct.pack_into("<HHHH", headers, opt + 0x28, 6, 0, 6, 0)
        struct.pack_into("<I", headers, opt + 0x34, 0)
        struct.pack_into("<I", headers, opt + 0x38, size_image)
        struct.pack_into("<I", headers, opt + 0x3C, text_raw)
        struct.pack_into("<H", headers, opt + 0x44, 1)  # native subsystem
        struct.pack_into("<H", headers, opt + 0x46, 0x160)
        struct.pack_into(
            "<QQQQ", headers, opt + 0x48, 0x100000, 0x1000, 0x100000, 0x1000
        )
        struct.pack_into("<I", headers, opt + 0x68, 0)
        struct.pack_into("<I", headers, opt + 0x6C, 16)
        dd = opt + 0x70
    else:
        struct.pack_into("<H", headers, opt, 0x10B)
        headers[opt + 2] = 1
        struct.pack_into("<I", headers, opt + 0x04, len(code))
        struct.pack_into("<I", headers, opt + 0x08, len(rdata))
        struct.pack_into("<I", headers, opt + 0x10, entry_rva)
        struct.pack_into("<I", headers, opt + 0x14, TEXT_RVA)
        struct.pack_into("<I", headers, opt + 0x18, RDATA_RVA)  # BaseOfData
        struct.pack_into("<I", headers, opt + 0x1C, image_base)
        struct.pack_into("<I", headers, opt + 0x20, 0x1000)
        struct.pack_into("<I", headers, opt + 0x24, 0x200)
        struct.pack_into("<HHHH", headers, opt + 0x28, 6, 0, 6, 0)
        struct.pack_into("<I", headers, opt + 0x34, 0)
        struct.pack_into("<I", headers, opt + 0x38, size_image)
        struct.pack_into("<I", headers, opt + 0x3C, text_raw)
        struct.pack_into("<H", headers, opt + 0x44, 1)
        struct.pack_into("<H", headers, opt + 0x46, 0x140)
        struct.pack_into(
            "<IIII", headers, opt + 0x48, 0x100000, 0x1000, 0x100000, 0x1000
        )
        struct.pack_into("<I", headers, opt + 0x58, 0)
        struct.pack_into("<I", headers, opt + 0x5C, 16)
        dd = opt + 0x60

    for index, (rva, size) in data_dirs.items():
        struct.pack_into("<II", headers, dd + index * 8, rva, size)

    sec_off = 0x58 + opt_size
    struct.pack_into(
        "<8sIIIIIIHHI",
        headers,
        sec_off,
        b".text",
        len(code),
        TEXT_RVA,
        text_raw_size,
        text_raw,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    sec_off += 40
    struct.pack_into(
        "<8sIIIIIIHHI",
        headers,
        sec_off,
        b".rdata",
        len(rdata),
        RDATA_RVA,
        rdata_raw_size,
        rdata_raw,
        0,
        0,
        0,
        0,
        0x40000040,
    )

    body = bytes(headers)
    body += bytes(code) + b"\x00" * (text_raw_size - len(code))
    body += bytes(rdata) + b"\x00" * (rdata_raw_size - len(rdata))
    return body


def _rdata_with_export(
    entry_rva: int,
    *,
    with_imports: bool = False,
    device_names: tuple[str, ...] = (),
) -> tuple[bytes, dict[int, tuple[int, int]]]:
    """Build .rdata with an export directory for `DriverEntry`."""
    buf = bytearray(40)  # IMAGE_EXPORT_DIRECTORY (patched below)

    def alloc(data: bytes) -> int:
        offset = len(buf)
        buf.extend(data)
        return offset

    funcs_off = alloc(struct.pack("<I", entry_rva))
    names_off = alloc(b"\x00" * 4)
    ords_off = alloc(struct.pack("<H", 0))
    dll_off = alloc(b"testdrv.sys\x00")
    name_off = alloc(b"DriverEntry\x00")
    struct.pack_into("<I", buf, names_off, RDATA_RVA + name_off)
    struct.pack_into(
        "<IIHHIIIIIII",
        buf,
        0,
        0,
        0,
        0,
        0,
        RDATA_RVA + dll_off,
        1,
        1,
        1,
        RDATA_RVA + funcs_off,
        RDATA_RVA + names_off,
        RDATA_RVA + ords_off,
    )

    for text in device_names:
        alloc((text + "\x00").encode("utf-16-le"))

    dirs: dict[int, tuple[int, int]] = {0: (RDATA_RVA, 40)}
    if with_imports:
        desc_off = len(buf)
        buf.extend(b"\x00" * 40)  # descriptor + null descriptor
        int_off = len(buf)
        buf.extend(b"\x00" * 16)
        iat_off = len(buf)
        buf.extend(b"\x00" * 16)
        mod_off = alloc(b"ntoskrnl.exe\x00")
        hint_off = alloc(struct.pack("<H", 0) + b"IoCreateDevice\x00")
        struct.pack_into("<Q", buf, int_off, RDATA_RVA + hint_off)
        struct.pack_into("<Q", buf, iat_off, RDATA_RVA + hint_off)
        struct.pack_into(
            "<IIIII",
            buf,
            desc_off,
            RDATA_RVA + int_off,
            0,
            0,
            RDATA_RVA + mod_off,
            RDATA_RVA + iat_off,
        )
        # IAT address printed by pefile is a VA.
        import_va = X64_BASE + RDATA_RVA + iat_off
        del import_va  # pefile computes it from ImageBase; kept for clarity
        dirs[1] = (RDATA_RVA + desc_off, 40)

    return bytes(buf), dirs


def _x64_entry(handler_rva: int | None) -> bytes:
    if handler_rva is None:
        return bytes.fromhex("31c0c3")  # xor eax, eax; ret

    code = bytearray()
    disp = handler_rva - (TEXT_RVA + 7)
    code += b"\x48\x8d\x05" + struct.pack("<i", disp)  # lea rax, [rip+disp]
    code += b"\x48\x89\x81\xe0\x00\x00\x00"  # mov [rcx+0xE0], rax
    code += b"\x31\xc0"  # xor eax, eax
    code += b"\xc3"  # ret
    assert len(code) == 0x11
    code += b"\x90" * (handler_rva - TEXT_RVA - len(code))
    return bytes(code)


def _x64_lea_composition_entry(handler_rva: int) -> bytes:
    """DriverEntry that writes the slot via lea reg,[rcx+0x70] first."""
    code = bytearray()
    disp = handler_rva - (TEXT_RVA + 7)
    code += b"\x48\x8d\x05" + struct.pack("<i", disp)  # lea rax, [rip+disp]
    code += b"\x4c\x8d\x81\x70\x00\x00\x00"  # lea r8, [rcx+0x70]
    code += b"\x49\x89\x40\x70"  # mov [r8+0x70], rax
    code += b"\x31\xc0"  # xor eax,eax
    code += b"\xc3"  # ret
    assert len(code) == 0x15
    code += b"\x90" * (handler_rva - TEXT_RVA - len(code))
    return bytes(code)


def _x64_compare_handler(codes: tuple[int, ...]) -> bytes:
    body = bytearray()
    for code in codes:
        body += b"\x81\xf9" + struct.pack("<I", code)  # cmp ecx, imm32
    body += b"\xc3"  # ret
    return bytes(body)


def _x64_switch_handler(case_count: int = 5) -> bytes:
    """sub ecx, base; cmp ecx, N; ja default; table dispatch."""
    buf = bytearray()
    base = 0x222000
    buf += b"\x81\xe9" + struct.pack("<I", base)  # sub ecx, 0x222000
    buf += b"\x83\xf9" + struct.pack("<B", case_count - 1)  # cmp ecx, N
    ja_pos = len(buf)
    buf += b"\x77\x00"  # ja default (rel8 patched)
    lea_pos = len(buf)
    buf += b"\x48\x8d\x15\x00\x00\x00\x00"  # lea rdx, [rip+table]
    buf += b"\x48\x63\x04\x8a"  # movsxd rax, dword ptr [rdx+rcx*4]
    buf += b"\x48\x03\xc2"  # add rax, rdx
    buf += b"\xff\xe0"  # jmp rax

    case_offsets = []
    for index in range(case_count):
        case_offsets.append(len(buf))
        buf += b"\xb8" + struct.pack("<I", 0x100 + index) + b"\xc3"
    default_off = len(buf)
    buf += b"\x31\xc0\xc3"  # xor eax, eax; ret
    while len(buf) % 4:
        buf += b"\x90"
    table_off = len(buf)
    for offset in case_offsets:
        buf += struct.pack("<i", offset - table_off)

    struct.pack_into("<b", buf, ja_pos + 1, default_off - (ja_pos + 2))
    struct.pack_into("<i", buf, lea_pos + 3, table_off - (lea_pos + 7))
    return bytes(buf)


def _x64_dispatch_table_handler(codes: tuple[int, ...] = (0x222001, 0x222002, 0x222003)) -> bytes:
    """Data-driven dispatch: bounds-check then compare against a dword table."""
    buf = bytearray()
    buf += b"\x41\x89\xc9"  # mov r9d, ecx (IOCTL code)
    buf += b"\x89\xc8"  # mov eax, ecx
    buf += b"\xc1\xe8\x02"  # shr eax, 2
    buf += b"\x25\xff\x03\x00\x00"  # and eax, 0x3ff
    buf += b"\x83\xf8" + struct.pack("<B", len(codes) - 1)  # cmp eax, N
    jae_pos = len(buf)
    buf += b"\x73\x00"  # jae default (patched)
    lea_pos = len(buf)
    buf += b"\x48\x8d\x15\x00\x00\x00\x00"  # lea rdx, [rip+table]
    buf += b"\x44\x39\x8c\x82\x00\x00\x00\x00"  # cmp [rdx+rax*4], r9d
    jne_pos = len(buf)
    buf += b"\x75\x00"  # jne default (patched)
    buf += b"\xb8\x01\x00\x00\x00"  # mov eax, 1
    buf += b"\xc3"  # ret
    default_off = len(buf)
    buf += b"\x31\xc0\xc3"  # xor eax,eax; ret
    while len(buf) % 4:
        buf += b"\x90"
    table_off = len(buf)
    for code in codes:
        buf += struct.pack("<I", code)
    struct.pack_into("<b", buf, jae_pos + 1, default_off - (jae_pos + 2))
    struct.pack_into("<b", buf, jne_pos + 1, default_off - (jne_pos + 2))
    struct.pack_into("<i", buf, lea_pos + 3, table_off - (lea_pos + 7))
    return bytes(buf)


def _x64_forwarding_handler(codes: tuple[int, ...] = (0x222004, 0x222008)) -> bytes:
    """Handler that immediately forwards to a local IOCTL processor."""
    sub_off = 0x20
    buf = bytearray()
    call_pos = len(buf)
    buf += b"\xe8\x00\x00\x00\x00"  # call sub (patched)
    buf += b"\xc3"  # ret
    buf += b"\x90" * (sub_off - len(buf))
    struct.pack_into("<i", buf, call_pos + 1, len(buf) - (call_pos + 5))
    for code in codes:
        buf += b"\x81\xf9" + struct.pack("<I", code)  # cmp ecx, imm32
    buf += b"\xc3"
    return bytes(buf)


def _x86_entry(handler_rva: int | None) -> bytes:
    code = bytearray()
    code += b"\x8b\x4c\x24\x04"  # mov ecx, [esp+4] (DriverObject)
    if handler_rva is None:
        code += b"\x33\xc0\xc2\x08\x00"  # xor eax,eax; ret 8
        return bytes(code)

    code += b"\xb8" + struct.pack("<I", X86_BASE + handler_rva)  # mov eax, handler
    code += b"\x89\x41\x70"  # mov [ecx+0x70], eax
    code += b"\x33\xc0"  # xor eax, eax
    code += b"\xc2\x08\x00"  # ret 8
    assert len(code) == 0x11
    code += b"\x90" * (handler_rva - TEXT_RVA - len(code))
    code += b"\x3d" + struct.pack("<I", 0x222004)  # cmp eax, imm32
    code += b"\xc2\x08\x00"  # ret 8
    return bytes(code)


def _write(tmp_path, name: str, blob: bytes):
    path = tmp_path / name
    path.write_bytes(blob)
    return path


def _x64_driver(
    entry_rva: int,
    handler: bytes | None,
    *,
    with_imports: bool = False,
    device_names: tuple[str, ...] = (),
    entry_code: bytes | None = None,
) -> bytes:
    rdata, dirs = _rdata_with_export(
        entry_rva, with_imports=with_imports, device_names=device_names
    )
    code = _x64_entry(HANDLER_RVA_X64 if handler is not None else None)
    if entry_code is not None:
        code = entry_code
    if handler is not None:
        code += handler
    return _build_pe(
        machine=0x8664,
        is_64=True,
        image_base=X64_BASE,
        entry_rva=entry_rva,
        code=code,
        rdata=rdata,
        data_dirs=dirs,
    )


# ---------------------------------------------------------------------------
# analyze_pe
# ---------------------------------------------------------------------------

def test_analyze_pe_parses_real_structures(tmp_path):
    blob = _x64_driver(
        TEXT_RVA,
        _x64_compare_handler((0x222004,)),
        with_imports=True,
        device_names=("\\Device\\TestDrv",),
    )
    result = analyze_pe_bytes(blob)

    assert result["file_type"] == "pe32+"
    assert result["machine"] == "x86_64"
    assert result["subsystem"] == "native"
    assert result["is_64bit"] is True
    assert result["image_base"] == X64_BASE
    assert result["entry_point_rva"] == TEXT_RVA
    assert [s["name"] for s in result["sections"]] == [".text", ".rdata"]

    export = next(e for e in result["exports"] if e["name"] == "DriverEntry")
    assert export["rva"] == TEXT_RVA
    assert export["va"] == X64_BASE + TEXT_RVA

    assert "IoCreateDevice" in result["imports"]
    module = result["imports_by_module"][0]
    assert module["module"] == "ntoskrnl.exe"
    assert module["functions"][0]["name"] == "IoCreateDevice"
    assert module["functions"][0]["iat_rva"] is not None
    assert result["dll_characteristics_flags"]
    assert result["source_path"] is None


def test_analyze_pe_rejects_non_pe():
    result = analyze_pe_bytes(b"this is not a PE file")
    assert result["file_type"] == "unknown"
    assert result["sections"] == []
    assert result["exports"] == []
    assert any("not an MZ/PE" in note for note in result["notes"])


def test_analyze_pe_survives_truncated_pe():
    blob = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x40) + b"PE\x00\x00" + b"\x00" * 100
    result = analyze_pe_bytes(blob)
    assert result["file_type"] in ("pe_invalid", "pe_unknown_magic_0x0")
    assert result["notes"]


# ---------------------------------------------------------------------------
# ioctl_extract
# ---------------------------------------------------------------------------

def test_x64_exported_driverentry_and_ioctl_codes(tmp_path):
    codes = (0x00222004, 0x00222008)
    blob = _x64_driver(
        TEXT_RVA,
        _x64_compare_handler(codes),
        with_imports=True,
        device_names=("\\Device\\TestDrv", "\\DosDevices\\TestDrv"),
    )
    path = _write(tmp_path, "x64_export.sys", blob)
    result = ioctl_extract(str(path))

    assert result["file_type"] == "pe32+"
    assert result["driver_entry_rva"] == TEXT_RVA
    assert result["driver_entry_source"] == "export"
    assert result["major_function_offset"] == 0xE0
    assert result["device_control_handler_rva"] == HANDLER_RVA_X64
    assert result["device_control_handler_va"] == X64_BASE + HANDLER_RVA_X64

    found = {item["code"] for item in result["ioctl_codes"]}
    assert {0x00222004, 0x00222008} <= found
    for item in result["ioctl_codes"]:
        assert item["plausible"] is True
        assert item["ref_va"] >= X64_BASE + HANDLER_RVA_X64
        assert item["ref_rva"] >= HANDLER_RVA_X64
        assert item["ctl_code"]["device_type"] == 0x22

    assert "\\Device\\TestDrv" in result["device_names"]
    assert "\\DosDevices\\TestDrv" in result["device_names"]
    assert any(i["name"] == "IoCreateDevice" for i in result["imports_of_interest"])
    assert result["confidence"] == "high"
    assert result["analysis_status"] == "ok"
    assert result["handler_search"]["major_function_writes"]


def test_major_function_store_via_lea_composition(tmp_path):
    handler = _x64_compare_handler((0x222010,))
    blob = _x64_driver(
        TEXT_RVA,
        handler,
        entry_code=_x64_lea_composition_entry(HANDLER_RVA_X64),
    )
    path = _write(tmp_path, "lea_compose.sys", blob)
    result = ioctl_extract(str(path))

    assert result["device_control_handler_rva"] == HANDLER_RVA_X64
    write = next(
        w
        for w in result["handler_search"]["major_function_writes"]
        if w["is_device_control"]
    )
    assert write["offset"] == 0xE0
    assert write["base_provenance"] is True
    assert write["instruction"].startswith("mov")
    assert write["store_rva"] == TEXT_RVA + 0x0E
    assert any(item["code"] == 0x222010 for item in result["ioctl_codes"])


def test_x86_entrypoint_only_driver(tmp_path):
    code = _x86_entry(HANDLER_RVA_X86)
    rdata = ("\\Device\\X86Drv\x00").encode("utf-16-le")
    blob = _build_pe(
        machine=0x14C,
        is_64=False,
        image_base=X86_BASE,
        entry_rva=TEXT_RVA,
        code=code,
        rdata=rdata,
        data_dirs={},
    )
    path = _write(tmp_path, "x86_entry.sys", blob)
    result = ioctl_extract(str(path))

    assert result["file_type"] == "pe32"
    assert result["is_64bit"] is False
    assert result["driver_entry_rva"] == TEXT_RVA
    assert result["driver_entry_source"] == "entry_point"
    assert result["major_function_offset"] == 0x70  # 0x38 + 0x0E * 4
    assert result["device_control_handler_rva"] == HANDLER_RVA_X86
    assert any(item["code"] == 0x222004 for item in result["ioctl_codes"])
    assert "\\Device\\X86Drv" in result["device_names"]
    assert result["confidence"] == "medium"


def test_driver_without_ioctl_dispatch_has_explicit_evidence(tmp_path):
    blob = _x64_driver(TEXT_RVA, None)
    path = _write(tmp_path, "no_ioctl.sys", blob)
    result = ioctl_extract(str(path))

    assert result["driver_entry_rva"] == TEXT_RVA
    assert result["driver_entry_source"] == "export"
    assert result["device_control_handler_rva"] is None
    assert result["ioctl_codes"] == []
    assert result["jump_tables"] == []
    assert result["analysis_status"] == "no_device_control_handler"
    assert result["confidence"] == "low"
    assert result["handler_search"]["major_function_writes"] == []
    assert any("no write to MajorFunction[IRP_MJ_DEVICE_CONTROL]" in n for n in result["notes"])
    assert any("absence of static evidence" in n for n in result["notes"])


def test_jump_table_switch_is_identified(tmp_path):
    handler = _x64_switch_handler(case_count=5)
    blob = _x64_driver(TEXT_RVA, handler)
    path = _write(tmp_path, "switch.sys", blob)
    result = ioctl_extract(str(path))

    assert result["device_control_handler_rva"] == HANDLER_RVA_X64
    assert len(result["jump_tables"]) == 1
    table = result["jump_tables"][0]
    assert table["entry_count"] == 5
    assert table["large_switch"] is True
    assert table["mode"] == "relative"
    assert [case["value"] for case in table["cases"]] == [
        0x222000,
        0x222001,
        0x222002,
        0x222003,
        0x222004,
    ]
    assert all(case["target_rva"] for case in table["cases"])
    # The sub ecx, 0x222000 base is itself a comparable immediate.
    assert any(item["code"] == 0x222000 for item in result["ioctl_codes"])


def test_data_driven_dispatch_table_is_enumerated(tmp_path):
    handler = _x64_dispatch_table_handler()
    blob = _x64_driver(TEXT_RVA, handler)
    path = _write(tmp_path, "table_dispatch.sys", blob)
    result = ioctl_extract(str(path))

    assert result["device_control_handler_rva"] == HANDLER_RVA_X64
    assert len(result["dispatch_tables"]) == 1
    table = result["dispatch_tables"][0]
    assert table["entry_count"] == 3
    assert table["compared_register"] == "r9d"
    assert table["index_register"] == "rax"
    assert {entry["value"] for entry in table["entries"]} == {
        0x222001,
        0x222002,
        0x222003,
    }
    found = {item["code"] for item in result["ioctl_codes"]}
    assert {0x222001, 0x222002, 0x222003} <= found
    assert all("dispatch_table" in item["sources"] for item in result["ioctl_codes"])
    assert result["confidence"] == "high"


def test_dispatch_callee_comparisons_are_followed(tmp_path):
    handler = _x64_forwarding_handler()
    blob = _x64_driver(TEXT_RVA, handler)
    path = _write(tmp_path, "forwarded.sys", blob)
    result = ioctl_extract(str(path))

    assert result["device_control_handler_rva"] == HANDLER_RVA_X64
    found = {item["code"] for item in result["ioctl_codes"]}
    assert {0x222004, 0x222008} <= found
    callees = result["handler_analysis"]["callees_analyzed"]
    assert len(callees) == 1
    assert callees[0]["rva"] == HANDLER_RVA_X64 + 0x20
    assert callees[0]["plausible_code_count"] == 2


def test_ioctl_extract_on_non_pe(tmp_path):
    path = _write(tmp_path, "not_pe.bin", b"garbage")
    result = ioctl_extract(str(path))
    assert result["driver_entry_rva"] is None
    assert result["device_control_handler_rva"] is None
    assert result["ioctl_codes"] == []
    assert result["device_names"] == []
    assert result["confidence"] == "unknown"
    assert result["analysis_status"] == "not_pe"


def test_pe_without_entrypoint_reports_evidence(tmp_path):
    # Same shape as the stub samples shipped under artifacts/.
    blob = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x40) + b"PE\x00\x00" + b"\x00" * 100
    path = _write(tmp_path, "stub.sys", blob)
    result = ioctl_extract(str(path))

    assert result["driver_entry_rva"] is None
    assert result["device_control_handler_rva"] is None
    assert result["ioctl_codes"] == []
    assert result["analysis_status"] == "unsupported_format"
    assert result["confidence"] == "low"
    assert any("unsupported optional-header magic" in note for note in result["notes"])


# ---------------------------------------------------------------------------
# attack_surface_extract
# ---------------------------------------------------------------------------

def test_attack_surface_uses_ioctl_facts_and_never_guesses_privilege(tmp_path):
    blob = _x64_driver(
        TEXT_RVA,
        _x64_compare_handler((0x00222004,)),
        device_names=("\\Device\\TestDrv",),
    )
    path = _write(tmp_path, "surface.sys", blob)
    facts = ioctl_extract(str(path))
    pe = analyze_pe_bytes(blob)

    result = attack_surface_extract(pe=pe, strings={"strings": []}, ioctl=facts)

    assert result["basis"] == "ioctl_extract"
    kinds = {item["kind"] for item in result["items"]}
    assert "ioctl" in kinds
    assert "device" in kinds
    assert "dispatch" in kinds
    ioctl_item = next(item for item in result["items"] if item["kind"] == "ioctl")
    assert ioctl_item["parameters"]["code"] == 0x222004
    assert ioctl_item["address_or_offset"].startswith("ref_va=")

    for item in result["items"]:
        assert item["reachability"] == "unknown"
        assert item["reachability_detail"]["required_privilege"] == "unknown"
        assert item["reachability_detail"]["attack_actor"] == "unknown"
    assert "unprivileged_user" not in repr(result)


def test_attack_surface_runs_ioctl_extract_from_pe_source_path(tmp_path):
    blob = _x64_driver(
        TEXT_RVA,
        _x64_compare_handler((0x00222004,)),
        device_names=("\\Device\\AutoRun",),
    )
    path = _write(tmp_path, "auto.sys", blob)
    pe = analyze_pe_bytes(blob)
    assert pe["source_path"] is None
    pe["source_path"] = str(path)  # what analyze_pe(path) produces

    result = attack_surface_extract(pe=pe, strings={"strings": []})

    assert result["basis"] == "ioctl_extract"
    assert any(item["kind"] == "ioctl" for item in result["items"])
    assert all(item["reachability"] == "unknown" for item in result["items"])


def test_attack_surface_falls_back_without_disassembly():
    result = attack_surface_extract(
        pe={
            "imports": ["IoCreateDevice"],
            "exports": [{"name": "DriverEntry", "ordinal": 1, "rva": 0x1000}],
        },
        strings={"strings": ["\\Device\\Fallback"]},
    )
    assert result["basis"] == "none"
    assert result["count"] >= 2
    for item in result["items"]:
        assert item["reachability"] == "unknown"
    kinds = {item["kind"] for item in result["items"]}
    assert {"import", "export", "device"} <= kinds
    assert any("no ioctl_extract facts" in note for note in result["notes"])
