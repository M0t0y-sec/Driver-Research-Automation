"""Static IOCTL / dispatch extraction for Windows kernel drivers.

This tool answers three concrete questions about a PE driver using only
static evidence:

  1. Where is ``DriverEntry``?  (export table first, then the PE entry
     point, verified against DriverObject usage where possible)
  2. Where does ``DriverEntry`` install
     ``MajorFunction[IRP_MJ_DEVICE_CONTROL]``?  (x64 DRIVER_OBJECT has the
     MajorFunction array at 0x70, so the slot is 0x70 + 0x0E*8 = 0xE0;
     x86 has the array at 0x38, so the slot is 0x38 + 0x0E*4 = 0x70)
  3. What IOCTL codes does that dispatch handler compare against?

Everything is heuristic and derived from the file.  Fields that cannot
be established are ``None`` / ``[]`` with an explicit note -- nothing is
invented.  The result is JSON-serialisable.

Output shape::

    {
      "driver_entry_rva": int | None,
      "device_control_handler_rva": int | None,
      "ioctl_codes": [{"code": int, "ref_va": int, ...}],
      "device_names": ["\\Device\\..."],
      "imports_of_interest": [{"module": ..., "name": ...}],
      "confidence": "high" | "medium" | "low" | "unknown",
      "notes": [...],
      ...
    }
"""

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

import pefile
from capstone import CS_AC_WRITE, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP

from ..registry import tool
from ...models.common import RiskLevel
from .analyze_pe import MACHINES

IRP_MJ_DEVICE_CONTROL = 0x0E

# DRIVER_OBJECT layout (Windows, stable ABI).
MAJOR_FUNCTION_OFFSET_X64 = 0x70
MAJOR_FUNCTION_OFFSET_X86 = 0x38
POINTER_SIZE_X64 = 8
POINTER_SIZE_X86 = 4
DRIVER_UNLOAD_OFFSET_X64 = 0x68
DRIVER_UNLOAD_OFFSET_X86 = 0x34
MAJOR_FUNCTION_COUNT = 28  # IRP_MJ_MAXIMUM_FUNCTION + 1

# Imports that matter for driver attack-surface assessment.  Names are
# compared case-insensitively.
INTERESTING_IMPORTS = {
    "iocreatedevice",
    "iocreatedevicesecure",
    "iocreatesymboliclink",
    "iodeletedevice",
    "iodeletesymboliclink",
    "iofcompleterequest",
    "iocompleterequest",
    "iofcalldriver",
    "iocalldriver",
    "iogetcurrentprocess",
    "iogetrequestorprocess",
    "iogetrequestorprocessid",
    "iogetrelateddevice",
    "iogetattacheddevice",
    "iogetdevicepointer",
    "probeforread",
    "probeforwrite",
    "mapprobeandlockpages",
    "mmprobeandlockpages",
    "mmmaplockedpagesspecifycache",
    "mmmaplockedpages",
    "mmunmaplockedpages",
    "mmgetsystemaddressformdlsafe",
    "mmgetmdlvirtualaddress",
    "mmcopyvirtualmemory",
    "mmgetphysicaladdress",
    "mmlockpagesspecifycache",
    "mmunlockpages",
    "rtlcopymemory",
    "rtlmovememory",
    "rtlzeromemory",
    "memcpy",
    "memmove",
    "memset",
    "obreferenceobjectbyhandle",
    "obopenobjectbypointer",
    "obreferenceobjectbypointer",
    "zwopenprocess",
    "zwterminateprocess",
    "zwreadvirtualmemory",
    "zwwritevirtualmemory",
    "zwqueryinformationprocess",
    "zwsetinformationprocess",
    "zwcreatedirectoryobject",
    "zwopendirectoryobject",
    "pslookupprocessbyprocessid",
    "psgetcurrentprocessid",
    "kestackattachprocess",
    "keunstackdetachprocess",
    "seaccesscheck",
    "sesingleprivilegecheck",
    "iowmiopenblock",
    "iowmiwriteevent",
}

UTF16_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")
DRIVER_ENTRY_EXPORT = re.compile(r"^_?driverentry(@\d+)?$", re.IGNORECASE)

# x64 register aliases -> canonical 64-bit name.  A write to any alias
# clobbers the canonical register (conservative for provenance tracking).
_X64_ALIASES = {
    "eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
    "esi": "rsi", "edi": "rdi", "ebp": "rbp", "esp": "rsp",
    "ax": "rax", "bx": "rbx", "cx": "rcx", "dx": "rdx",
    "si": "rsi", "di": "rdi", "bp": "rbp", "sp": "rsp",
    "al": "rax", "bl": "rbx", "cl": "rcx", "dl": "rdx",
    "sil": "rsi", "dil": "rdi", "bpl": "rbp", "spl": "rsp",
    "ah": "rax", "bh": "rbx", "ch": "rcx", "dh": "rdx",
}
for _n in range(8, 16):
    _X64_ALIASES[f"r{_n}d"] = f"r{_n}"
    _X64_ALIASES[f"r{_n}w"] = f"r{_n}"
    _X64_ALIASES[f"r{_n}b"] = f"r{_n}"

_X86_ALIASES = {
    "ax": "eax", "bx": "ebx", "cx": "ecx", "dx": "edx",
    "si": "esi", "di": "edi", "bp": "ebp", "sp": "esp",
    "al": "eax", "bl": "ebx", "cl": "ecx", "dl": "edx",
    "ah": "eax", "bh": "ebx", "ch": "ecx", "dh": "edx",
}

UNKNOWN = ("unknown",)
CALLER_SAVED_X64 = {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"}
CALLER_SAVED_X86 = {"eax", "ecx", "edx"}


def _canon(name: str, is_64: bool) -> str:
    if is_64:
        return _X64_ALIASES.get(name, name)
    return _X86_ALIASES.get(name, name)


def _is_driver_object(value: tuple) -> bool:
    return bool(value) and value[0] == "do"


@dataclass
class _State:
    """Abstract register/stack state for one basic block."""

    env: dict[str, tuple] = field(default_factory=dict)
    sp: int = 0
    slots: dict[int, tuple] = field(default_factory=dict)
    frame_base: int | None = None
    last_push: tuple | None = None
    push_count: int = 0

    def copy(self) -> "_State":
        return _State(
            env=dict(self.env),
            sp=self.sp,
            slots=dict(self.slots),
            frame_base=self.frame_base,
            last_push=self.last_push,
            push_count=self.push_count,
        )


class _PeView:
    """Thin PE accessor used by both the entry-point scan and handler CFG."""

    def __init__(self, pe: pefile.PE, data: bytes, path: str) -> None:
        self.pe = pe
        self.data = data
        self.path = path
        self.image_base: int = pe.OPTIONAL_HEADER.ImageBase
        self.size_image: int = pe.OPTIONAL_HEADER.SizeOfImage
        self.is_64: bool = pe.OPTIONAL_HEADER.Magic == 0x20B
        self.major_function_base = (
            MAJOR_FUNCTION_OFFSET_X64 if self.is_64 else MAJOR_FUNCTION_OFFSET_X86
        )
        self.pointer_size = POINTER_SIZE_X64 if self.is_64 else POINTER_SIZE_X86
        self.device_control_offset = (
            self.major_function_base + IRP_MJ_DEVICE_CONTROL * self.pointer_size
        )
        self.driver_unload_offset = (
            DRIVER_UNLOAD_OFFSET_X64 if self.is_64 else DRIVER_UNLOAD_OFFSET_X86
        )
        self.md = Cs(CS_ARCH_X86, CS_MODE_64 if self.is_64 else CS_MODE_32)
        self.md.detail = True

    # -- address / byte helpers ----------------------------------------

    def rva_to_va(self, rva: int) -> int:
        return self.image_base + rva

    def va_to_rva(self, va: int) -> int:
        return va - self.image_base

    def section_for_rva(self, rva: int):
        for sec in self.pe.sections:
            va = sec.VirtualAddress
            size = max(sec.Misc_VirtualSize, sec.SizeOfRawData)
            if va <= rva < va + size:
                return sec
        # Headers are mapped but contain no executable code.
        return None

    def read_rva(self, rva: int, size: int) -> bytes:
        try:
            offset = self.pe.get_offset_from_rva(rva)
        except Exception:  # noqa: BLE001 - unmapped RVA
            return b""
        if offset is None or offset < 0 or offset >= len(self.data):
            return b""
        return self.data[offset : offset + size]

    def is_executable(self, rva: int) -> bool:
        sec = self.section_for_rva(rva)
        if sec is None:
            return False
        return bool(sec.Characteristics & 0x20000000)  # IMAGE_SCN_MEM_EXECUTE

    def section_bytes(self, sec) -> bytes:
        start = sec.PointerToRawData
        end = start + sec.SizeOfRawData
        if start >= len(self.data):
            return b""
        return self.data[start:end]

    def disasm_one(self, rva: int):
        code = self.read_rva(rva, 16)
        if not code:
            return None
        try:
            for insn in self.md.disasm(code, self.rva_to_va(rva), count=1):
                return insn
        except Exception:  # noqa: BLE001 - capstone is strict about bad bytes
            return None
        return None

    def read_pointer(self, va: int) -> int | None:
        size = 8 if self.is_64 else 4
        raw = self.read_rva(self.va_to_rva(va), size)
        if len(raw) != size:
            return None
        return int.from_bytes(raw, "little")


# ---------------------------------------------------------------------------
# DriverEntry resolution
# ---------------------------------------------------------------------------

def _find_driver_entry(view: _PeView) -> tuple[int | None, str | None, list[str]]:
    notes: list[str] = []
    export_name = None
    export_dir = getattr(view.pe, "DIRECTORY_ENTRY_EXPORT", None)
    if export_dir is not None:
        for sym in export_dir.symbols:
            raw = sym.name
            if raw is None:
                continue
            name = raw.decode("ascii", errors="replace") if isinstance(raw, bytes) else str(raw)
            if DRIVER_ENTRY_EXPORT.match(name):
                rva = int(sym.address)
                if view.is_executable(rva):
                    return rva, "export", notes + [f"DriverEntry export found: {name}"]
                notes.append(
                    f"export {name} points at RVA 0x{rva:X}, which is not executable; ignoring"
                )
                export_name = name
    if export_name:
        notes.append(f"DriverEntry export {export_name} was unusable; falling back to entry point")
    entry = int(view.pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    if entry == 0:
        return None, None, notes + ["AddressOfEntryPoint is 0; no driver entry candidate"]
    if not view.is_executable(entry):
        return None, None, notes + [
            f"AddressOfEntryPoint RVA 0x{entry:X} is not in an executable section"
        ]
    return entry, "entry_point", notes + [
        f"no usable DriverEntry export; using AddressOfEntryPoint RVA 0x{entry:X}"
    ]


# ---------------------------------------------------------------------------
# DriverEntry scan: find the MajorFunction[IRP_MJ_DEVICE_CONTROL] store
# ---------------------------------------------------------------------------

def _mem_slot_key(insn, mem, state: _State, is_64: bool) -> int | None:
    """Return the symbolic stack slot key for [rsp/rbp + disp], else None."""
    if mem.base == 0:
        return None
    base = _canon(insn.reg_name(mem.base), is_64)
    if base in ("rsp", "esp"):
        return state.sp + mem.disp
    if base in ("rbp", "ebp") and state.frame_base is not None:
        return state.frame_base + mem.disp
    return None


def _mem_value(insn, mem, state: _State, view: _PeView) -> tuple:
    """Resolve a memory operand to an abstract value."""
    is_64 = view.is_64
    if mem.base == X86_REG_RIP:
        va = insn.address + insn.size + mem.disp
        ptr = view.read_pointer(va)
        if ptr is not None and view.image_base <= ptr < view.image_base + view.size_image:
            return ("addr", ptr)
        return ("mem", va)
    if mem.base == 0:
        # x86 absolute displacement.
        va = mem.disp
        ptr = view.read_pointer(va)
        if ptr is not None and view.image_base <= ptr < view.image_base + view.size_image:
            return ("addr", ptr)
        return ("mem", va)
    base_name = _canon(insn.reg_name(mem.base), is_64)
    slot_key = _mem_slot_key(insn, mem, state, is_64)
    if slot_key is not None:
        return state.slots.get(slot_key, UNKNOWN)
    base_val = state.env.get(base_name)
    if base_val is not None:
        if base_val[0] == "do":
            return ("do_field", base_val[1] + mem.disp)
        if base_val[0] == "addr":
            va = base_val[1] + mem.disp
            ptr = view.read_pointer(va)
            if ptr is not None and view.image_base <= ptr < view.image_base + view.size_image:
                return ("addr", ptr)
            return ("mem", va)
    return ("mem", None)


def _resolve_handler_va(value: tuple, view: _PeView) -> tuple[int | None, str]:
    """Resolve an abstract store value to a code VA."""
    if not value:
        return None, "unknown_value"
    kind = value[0]
    if kind == "addr":
        va = value[1]
        if view.is_executable(view.va_to_rva(va)):
            return va, "register"
        return None, "address_not_executable"
    if kind == "imm":
        va = value[1]
        # x64 stores of function pointers use sign-extended imm32, but a
        # real image VA fits in 32 bits of sign extension only in rare
        # tiny-image cases; check the raw value first.
        for candidate in (va, va & 0xFFFFFFFF, va & 0xFFFFFFFFFFFFFFFF):
            if view.image_base <= candidate < view.image_base + view.size_image:
                if view.is_executable(view.va_to_rva(candidate)):
                    return candidate, "immediate"
        return None, "immediate_outside_image"
    if kind == "mem":
        return None, "memory_load"
    return None, "unknown_value"


def _invalidate_written(insn, state: _State, is_64: bool, keep: set[str]) -> None:
    """Drop provenance for registers written by *insn* (except *keep*)."""
    written: set[str] = set()
    for op in insn.operands:
        if op.type == X86_OP_REG and (op.access & CS_AC_WRITE):
            written.add(_canon(insn.reg_name(op.reg), is_64))
    try:
        _, implicit = insn.regs_access()
        for reg_id in implicit:
            written.add(_canon(insn.reg_name(reg_id), is_64))
    except Exception:  # noqa: BLE001 - defensive against capstone quirks
        pass
    for name in written:
        if name in keep:
            continue
        if name in state.env:
            state.env[name] = UNKNOWN


def _process_instruction(
    view: _PeView,
    insn,
    state: _State,
) -> dict:
    """Update abstract state for one instruction.

    Returns a dict with optional keys:
      ``store``: candidate store info for MajorFunction writes
      ``call_target_va`` / ``call_arg0`` / ``call_env``: call metadata for
      callee following
    """
    is_64 = view.is_64
    mn = insn.mnemonic
    ops = insn.operands
    keep: set[str] = set()
    out: dict = {}

    # --- stack pointer adjustments / push / pop -----------------------
    if mn == "push" and len(ops) == 1:
        value = UNKNOWN
        op = ops[0]
        if op.type == X86_OP_REG:
            value = state.env.get(_canon(insn.reg_name(op.reg), is_64), UNKNOWN)
        elif op.type == X86_OP_IMM:
            value = ("imm", op.imm)
        state.sp -= view.pointer_size
        state.slots[state.sp] = value
        state.last_push = value
        state.push_count += 1
        return out
    if mn == "pop" and len(ops) == 1:
        value = state.slots.get(state.sp, UNKNOWN)
        state.sp += view.pointer_size
        op = ops[0]
        if op.type == X86_OP_REG:
            state.env[_canon(insn.reg_name(op.reg), is_64)] = value
            keep.add(_canon(insn.reg_name(op.reg), is_64))
        state.last_push = None
        return out
    if mn in ("add", "sub") and len(ops) == 2:
        dst, src = ops
        if dst.type == X86_OP_REG and src.type == X86_OP_IMM:
            name = _canon(insn.reg_name(dst.reg), is_64)
            if name in ("rsp", "esp"):
                delta = src.imm if mn == "add" else -src.imm
                state.sp += delta
                return out
            old = state.env.get(name)
            if old and old[0] == "imm":
                state.env[name] = ("imm", old[1] + (src.imm if mn == "add" else -src.imm))
                keep.add(name)
                _invalidate_written(insn, state, is_64, keep)
                return out
    if mn in ("inc", "dec") and len(ops) == 1 and ops[0].type == X86_OP_REG:
        name = _canon(insn.reg_name(ops[0].reg), is_64)
        old = state.env.get(name)
        if old and old[0] == "imm":
            state.env[name] = ("imm", old[1] + (1 if mn == "inc" else -1))
            keep.add(name)
            _invalidate_written(insn, state, is_64, keep)
            return out

    # --- call metadata (capture before clobbering) --------------------
    if mn == "call":
        target = None
        if len(ops) == 1 and ops[0].type == X86_OP_IMM:
            target = ops[0].imm
        out["call_target_va"] = target
        if is_64:
            out["call_arg0"] = state.env.get("rcx", UNKNOWN)
            out["call_env"] = {
                "rcx": state.env.get("rcx", UNKNOWN),
                "rdx": state.env.get("rdx", UNKNOWN),
                "r8": state.env.get("r8", UNKNOWN),
                "r9": state.env.get("r9", UNKNOWN),
            }
        else:
            out["call_arg0"] = state.last_push if state.last_push is not None else UNKNOWN
            out["call_env"] = {}
        # Caller-saved registers are clobbered; x86 stdcall args are
        # popped by the callee.
        for name in CALLER_SAVED_X64 if is_64 else CALLER_SAVED_X86:
            state.env[name] = UNKNOWN
        for name in ("rax",) if is_64 else ("eax",):
            state.env[name] = UNKNOWN
        if not is_64 and state.push_count:
            state.sp += state.push_count * view.pointer_size
        state.last_push = None
        state.push_count = 0
        return out

    # --- mov ----------------------------------------------------------
    if mn in ("mov", "movabs") and len(ops) == 2:
        dst, src = ops
        if dst.type == X86_OP_REG:
            dname = _canon(insn.reg_name(dst.reg), is_64)
            if src.type == X86_OP_REG:
                sname = _canon(insn.reg_name(src.reg), is_64)
                if dname in ("rbp", "ebp") and sname in ("rsp", "esp"):
                    # mov rbp, rsp / mov ebp, esp starts a frame.
                    state.frame_base = state.sp
                    state.env[dname] = UNKNOWN
                else:
                    state.env[dname] = state.env.get(sname, UNKNOWN)
            elif src.type == X86_OP_IMM:
                state.env[dname] = ("imm", src.imm)
            elif src.type == X86_OP_MEM:
                state.env[dname] = _mem_value(insn, src.mem, state, view)
            keep.add(dname)
        elif dst.type == X86_OP_MEM:
            value = UNKNOWN
            if src.type == X86_OP_REG:
                value = state.env.get(_canon(insn.reg_name(src.reg), is_64), UNKNOWN)
            elif src.type == X86_OP_IMM:
                value = ("imm", src.imm)
            slot_key = _mem_slot_key(insn, dst.mem, state, is_64)
            if slot_key is not None:
                state.slots[slot_key] = value
            else:
                addr_kind, offset = _store_target(insn, dst.mem, state, view)
                if addr_kind == "driver_object" and offset is not None:
                    in_major = (
                        view.major_function_base
                        <= offset
                        < view.major_function_base
                        + MAJOR_FUNCTION_COUNT * view.pointer_size
                    )
                    is_device_control = offset == view.device_control_offset
                    if in_major:
                        resolved_va, how = _resolve_handler_va(value, view)
                        out["store"] = {
                            "store_va": insn.address,
                            "store_rva": view.va_to_rva(insn.address),
                            "offset": offset,
                            "is_device_control": is_device_control,
                            "base_provenance": True,
                            "base_register": _canon(
                                insn.reg_name(dst.mem.base), is_64
                            ) if dst.mem.base else None,
                            "resolved_va": resolved_va,
                            "resolved_rva": view.va_to_rva(resolved_va) if resolved_va is not None else None,
                            "resolution": how,
                            "instruction": f"{mn} {insn.op_str}",
                        }
                    elif offset == view.driver_unload_offset:
                        resolved_va, how = _resolve_handler_va(value, view)
                        out["store"] = {
                            "store_va": insn.address,
                            "store_rva": view.va_to_rva(insn.address),
                            "offset": offset,
                            "is_device_control": False,
                            "is_driver_unload": True,
                            "base_provenance": True,
                            "base_register": _canon(
                                insn.reg_name(dst.mem.base), is_64
                            ) if dst.mem.base else None,
                            "resolved_va": resolved_va,
                            "resolved_rva": view.va_to_rva(resolved_va) if resolved_va is not None else None,
                            "resolution": how,
                            "instruction": f"{mn} {insn.op_str}",
                        }
                elif (
                    offset is None
                    and dst.mem.index == 0
                    and dst.mem.base not in (0, X86_REG_RIP)
                    and dst.mem.disp == view.device_control_offset
                ):
                    # Base provenance unknown (e.g. spilled/reloaded through
                    # an untracked slot), but the displacement is exactly the
                    # IRP_MJ_DEVICE_CONTROL slot.  Keep it as a lower
                    # confidence candidate.
                    resolved_va, how = _resolve_handler_va(value, view)
                    out["store"] = {
                        "store_va": insn.address,
                        "store_rva": view.va_to_rva(insn.address),
                        "offset": dst.mem.disp,
                        "is_device_control": True,
                        "base_provenance": False,
                        "base_register": _canon(insn.reg_name(dst.mem.base), is_64)
                        if dst.mem.base else None,
                        "resolved_va": resolved_va,
                        "resolved_rva": view.va_to_rva(resolved_va) if resolved_va is not None else None,
                        "resolution": how,
                        "instruction": f"{mn} {insn.op_str}",
                    }
            keep.clear()

    # --- lea ----------------------------------------------------------
    if mn == "lea" and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_MEM:
        dname = _canon(insn.reg_name(ops[0].reg), is_64)
        mem = ops[1].mem
        if mem.index != 0:
            # Indexed LEA is an array access, not a scalar DriverObject field.
            state.env[dname] = UNKNOWN
        elif mem.base == X86_REG_RIP:
            state.env[dname] = ("addr", insn.address + insn.size + mem.disp)
        elif mem.base == 0:
            state.env[dname] = ("addr", mem.disp)
        else:
            base_name = _canon(insn.reg_name(mem.base), is_64)
            if base_name == "rsp" or (base_name in ("rbp", "ebp") and state.frame_base is not None):
                state.env[dname] = UNKNOWN
            else:
                base_val = state.env.get(base_name, UNKNOWN)
                if _is_driver_object(base_val):
                    state.env[dname] = ("do", base_val[1] + mem.disp)
                elif base_val[0] == "addr":
                    state.env[dname] = ("addr", base_val[1] + mem.disp)
                else:
                    state.env[dname] = UNKNOWN
        keep.add(dname)

    # --- xor reg, reg -> zero -----------------------------------------
    if mn == "xor" and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG:
        a = _canon(insn.reg_name(ops[0].reg), is_64)
        b = _canon(insn.reg_name(ops[1].reg), is_64)
        if a == b:
            state.env[a] = ("imm", 0)
            keep.add(a)

    _invalidate_written(insn, state, is_64, keep)
    return out


def _store_target(insn, mem, state: _State, view: _PeView) -> tuple[str, int | None]:
    """Classify a store destination for MajorFunction detection."""
    if mem.index != 0:
        return "indexed", None
    slot_key = _mem_slot_key(insn, mem, state, view.is_64)
    if slot_key is not None:
        return "stack", None
    if mem.base == 0 or mem.base == X86_REG_RIP:
        return "absolute", None
    base_name = _canon(insn.reg_name(mem.base), view.is_64)
    base_val = state.env.get(base_name)
    if base_val is not None and base_val[0] == "do":
        return "driver_object", base_val[1] + mem.disp
    return "unknown", None


def _scan_for_major_store(
    view: _PeView,
    entry_rva: int,
    *,
    max_depth: int = 2,
    max_instructions: int = 8000,
) -> dict:
    """Scan DriverEntry and directly-called init functions for writes."""
    is_64 = view.is_64
    functions: list[tuple[int, _State, int]] = []
    initial = _State(env={"rcx": ("do", 0)} if is_64 else {})
    if not is_64:
        initial.slots[4] = ("do", 0)  # [esp+4] = DriverObject (stdcall)
    functions.append((entry_rva, initial, 0))

    visited_funcs: set[tuple[int, int]] = set()
    written_blocks: set[tuple[int, int]] = set()
    stores: list[dict] = []
    driver_object_refs = 0
    total_instructions = 0
    followed: list[dict] = []

    while functions and total_instructions < max_instructions:
        func_rva, state0, depth = functions.pop(0)
        if (func_rva, depth) in visited_funcs:
            continue
        visited_funcs.add((func_rva, depth))
        work: list[tuple[int, _State]] = [(func_rva, state0)]
        block_count = 0
        while work and total_instructions < max_instructions and block_count < 400:
            block_rva, state = work.pop()
            if (block_rva, depth) in written_blocks:
                continue
            written_blocks.add((block_rva, depth))
            block_count += 1
            if not view.is_executable(block_rva):
                continue
            pc = block_rva
            instr_in_block = 0
            while (
                total_instructions < max_instructions
                and instr_in_block < 256
            ):
                insn = view.disasm_one(pc)
                if insn is None:
                    break
                total_instructions += 1
                instr_in_block += 1
                next_rva = pc + insn.size

                info = _process_instruction(view, insn, state)
                if "store" in info:
                    info["store"]["function_rva"] = func_rva
                    stores.append(info["store"])
                if info.get("call_target_va") is not None and depth < max_depth:
                    target_va = info["call_target_va"]
                    target_rva = view.va_to_rva(target_va)
                    if view.is_executable(target_rva):
                        arg0 = info.get("call_arg0", UNKNOWN)
                        if _is_driver_object(arg0) and len(followed) < 32:
                            callee = _State()
                            if is_64:
                                callee.env.update(info.get("call_env", {}))
                            else:
                                callee.slots[4] = arg0
                            functions.append((target_rva, callee, depth + 1))
                            followed.append(
                                {
                                    "call_site_rva": view.va_to_rva(insn.address),
                                    "target_rva": target_rva,
                                    "depth": depth + 1,
                                }
                            )

                mn = insn.mnemonic
                if mn.startswith("j") and mn != "jmp":
                    if insn.operands and insn.operands[0].type == X86_OP_IMM:
                        target_rva = view.va_to_rva(insn.operands[0].imm)
                        if view.is_executable(target_rva):
                            work.append((target_rva, state.copy()))
                    pc = next_rva
                    continue
                if mn == "jmp":
                    if insn.operands and insn.operands[0].type == X86_OP_IMM:
                        target_rva = view.va_to_rva(insn.operands[0].imm)
                        if view.is_executable(target_rva):
                            work.append((target_rva, state.copy()))
                    break
                if mn in ("ret", "retf", "iret", "iretq", "int3", "ud2", "hlt"):
                    break
                pc = next_rva

    # The same store can be reached through several block entry points;
    # report each physical store once.
    unique_stores: dict[tuple, dict] = {}
    for store in stores:
        key = (store["store_rva"], store["offset"], store["is_device_control"])
        unique_stores.setdefault(key, store)
    stores = list(unique_stores.values())

    return {
        "stores": stores,
        "driver_object_refs": sum(1 for s in stores if s.get("base_provenance")),
        "instructions_scanned": total_instructions,
        "calls_followed": followed,
    }


# ---------------------------------------------------------------------------
# Dispatch-handler analysis: comparisons + jump tables
# ---------------------------------------------------------------------------

def _ctl_decode(code: int) -> dict:
    return {
        "device_type": (code >> 16) & 0xFFFF,
        "access": (code >> 14) & 0x3,
        "function": (code >> 2) & 0xFFF,
        "method": code & 0x3,
    }


def _plausible_ctl_code(code: int) -> bool:
    """Heuristic: a CTL_CODE normally has a non-zero device type."""
    if code in (0, 0xFFFFFFFF):
        return False
    return (code >> 16) != 0


def _find_lea_value(prior_insns: list, reg_name: str) -> int | None:
    for prev in reversed(prior_insns[-20:]):
        if prev.mnemonic == "lea" and len(prev.operands) == 2:
            dst, src = prev.operands
            if (
                dst.type == X86_OP_REG
                and prev.reg_name(dst.reg) == reg_name
                and src.type == X86_OP_MEM
            ):
                if src.mem.base == X86_REG_RIP:
                    return prev.address + prev.size + src.mem.disp
                if src.mem.base == 0:
                    return src.mem.disp
                return None
        if prev.mnemonic in ("mov", "movabs") and len(prev.operands) == 2:
            dst, src = prev.operands
            if dst.type == X86_OP_REG and prev.reg_name(dst.reg) == reg_name:
                if src.type == X86_OP_IMM:
                    return src.imm
                return None
        for op in prev.operands:
            if (
                op.type == X86_OP_REG
                and prev.reg_name(op.reg) == reg_name
                and (op.access & CS_AC_WRITE)
            ):
                return None
    return None


def _find_switch_bounds(prior_insns: list) -> tuple[int | None, str | None]:
    """Find ``cmp index, N; ja default`` before a switch jump.

    Returns (max_index, index_register) or (None, None).
    """
    for i in range(len(prior_insns) - 1, max(-1, len(prior_insns) - 24), -1):
        insn = prior_insns[i]
        if (
            insn.mnemonic in ("cmp",)
            and len(insn.operands) == 2
            and insn.operands[0].type == X86_OP_REG
            and insn.operands[1].type == X86_OP_IMM
        ):
            for nxt in prior_insns[i + 1 : i + 4]:
                if nxt.mnemonic in ("ja", "jae", "jg", "jge"):
                    return insn.operands[1].imm & 0xFFFFFFFF, insn.reg_name(
                        insn.operands[0].reg
                    )
    return None, None


def _find_sub_base(
    prior_insns: list, index_reg: str | None, is_64: bool
) -> int | None:
    for insn in reversed(prior_insns[-24:]):
        if (
            insn.mnemonic == "sub"
            and len(insn.operands) == 2
            and insn.operands[0].type == X86_OP_REG
            and insn.operands[1].type == X86_OP_IMM
        ):
            name = _canon(insn.reg_name(insn.operands[0].reg), is_64)
            if name in ("rsp", "esp"):
                continue
            if index_reg is not None and name != _canon(index_reg, is_64):
                continue
            return insn.operands[1].imm & 0xFFFFFFFF
    return None


def _extract_table_dispatch_codes(view: _PeView, insn, prior_insns: list) -> dict | None:
    """Recognize data-driven IOCTL dispatch:
    ``cmp dword ptr [table + index*4 + disp], code_reg`` with a preceding
    bounds check.  The table holds the accepted IOCTL codes verbatim.

    Example (afd.sys)::

        mov  r9d, [rbx+0x18]              ; IOCTL code
        mov  eax, r9d
        shr  eax, 2
        and  eax, 0x3ff
        cmp  eax, 0x4a                   ; bounds
        jae  default
        lea  rdx, [rip-table]
        cmp  dword ptr [rdx+rax*4+0x7c1a0], r9d
        jne  default
    """
    if len(insn.operands) != 2:
        return None
    left, right = insn.operands
    if left.type == X86_OP_MEM and right.type == X86_OP_REG:
        mem_op, reg_op = left, right
    elif left.type == X86_OP_REG and right.type == X86_OP_MEM:
        mem_op, reg_op = right, left
    else:
        return None
    if mem_op.size < 4:
        return None  # the table stores dword IOCTL codes
    mem = mem_op.mem
    if mem.index == 0 or mem.scale != 4:
        return None  # dword IOCTL-code table

    bound, _bound_reg = _find_switch_bounds(prior_insns)
    if bound is None or bound <= 0 or bound > 4096:
        return None
    count = bound + 1

    if mem.base == X86_REG_RIP:
        table_va = insn.address + insn.size + mem.disp
    elif mem.base == 0:
        table_va = mem.disp
    else:
        base_va = _find_lea_value(prior_insns, insn.reg_name(mem.base))
        if base_va is None:
            return None
        table_va = base_va + mem.disp
    table_rva = view.va_to_rva(table_va) if table_va >= view.image_base else table_va
    if table_rva < 0 or table_rva >= view.size_image:
        return None

    entries: list[dict] = []
    for index in range(count):
        raw = view.read_rva(table_rva + index * 4, 4)
        if len(raw) != 4:
            break
        value = int.from_bytes(raw, "little")
        if value == 0:
            continue
        entries.append(
            {
                "value": value,
                "table_entry_rva": table_rva + index * 4,
                "index": index,
            }
        )
    if not entries:
        return None
    plausible = [entry for entry in entries if _plausible_ctl_code(entry["value"])]
    # Require the table to be dominated by CTL_CODE-shaped values; this
    # rejects random dword arrays that merely look like bounds checks.
    if len(plausible) < max(3, (len(entries) * 3) // 4):
        return None

    return {
        "compare_va": insn.address,
        "compare_rva": view.va_to_rva(insn.address),
        "table_va": table_va,
        "table_rva": table_rva,
        "entry_count": len(entries),
        "index_scale": mem.scale,
        "index_register": insn.reg_name(mem.index),
        "compared_register": insn.reg_name(reg_op.reg),
        "entries": entries,
    }


def _read_jump_entries(
    view: _PeView,
    table_rva: int,
    scale: int,
    limit: int,
    mode: str,
) -> list[tuple[int, int | None]]:
    """Read up to *limit* jump-table entries.

    Returns [(case_index, target_rva_or_None), ...].
    """
    entries: list[tuple[int, int | None]] = []
    for i in range(limit):
        raw = view.read_rva(table_rva + i * scale, scale)
        if len(raw) != scale:
            break
        value = int.from_bytes(raw, "little", signed=(scale == 4))
        unsigned = value & ((1 << (scale * 8)) - 1)
        target_rva: int | None = None
        if mode == "relative":
            if scale != 4:
                break
            candidate = table_rva + value  # signed dword offset from table base
            if view.is_executable(candidate):
                target_rva = candidate
        else:  # absolute
            if view.image_base <= unsigned < view.image_base + view.size_image:
                cand = view.va_to_rva(unsigned)
                if view.is_executable(cand):
                    target_rva = cand
        entries.append((i, target_rva))
        if target_rva is None and limit > 64:
            # Unknown entry count: stop at the first clearly invalid entry.
            break
    return entries


def _resolve_jump_table(view: _PeView, insn, prior_insns: list) -> dict | None:
    """Best-effort resolution of an indirect jump used for a switch."""
    if not insn.operands:
        return None
    op = insn.operands[0]
    table_va: int | None = None
    scale = 8 if view.is_64 else 4
    relative = False
    index_reg: str | None = None
    table_reg_name: str | None = None
    base_reg_name: str | None = None

    if op.type == X86_OP_REG:
        jump_reg = insn.reg_name(op.reg)
        # Pattern: lea base, [rip+table]; movsxd idx, [base+idx*4];
        #          add idx, base; jmp idx
        for prev in reversed(prior_insns[-16:]):
            if prev.mnemonic == "add" and len(prev.operands) == 2:
                dst, src = prev.operands
                if (
                    dst.type == X86_OP_REG
                    and prev.reg_name(dst.reg) == jump_reg
                    and src.type == X86_OP_REG
                ):
                    base_reg_name = prev.reg_name(src.reg)
                    table_va = _find_lea_value(prior_insns, base_reg_name)
                    relative = True
                    break
            if prev.mnemonic == "lea" and len(prev.operands) == 2:
                dst, src = prev.operands
                if (
                    dst.type == X86_OP_REG
                    and prev.reg_name(dst.reg) == jump_reg
                    and src.type == X86_OP_MEM
                    and src.mem.index != 0
                ):
                    base_reg_name = (
                        prev.reg_name(src.mem.base) if src.mem.base else None
                    )
                    if src.mem.base == X86_REG_RIP:
                        table_va = prev.address + prev.size + src.mem.disp
                    elif base_reg_name:
                        table_va = _find_lea_value(prior_insns, base_reg_name)
                    scale = src.mem.scale or scale
                    index_reg = prev.reg_name(src.mem.index)
                    break
        for prev in reversed(prior_insns[-20:]):
            if (
                prev.mnemonic in ("movsxd", "movslq", "mov")
                and len(prev.operands) == 2
                and prev.operands[0].type == X86_OP_REG
                and prev.operands[1].type == X86_OP_MEM
                and prev.operands[1].mem.index != 0
            ):
                mem = prev.operands[1].mem
                index_reg = prev.reg_name(mem.index)
                scale = mem.scale or scale
                if table_va is None:
                    if mem.base == X86_REG_RIP:
                        table_va = prev.address + prev.size + mem.disp
                    elif mem.base:
                        table_va = _find_lea_value(prior_insns, prev.reg_name(mem.base))
                break
    elif op.type == X86_OP_MEM:
        mem = op.mem
        scale = mem.scale or scale
        if mem.index:
            index_reg = insn.reg_name(mem.index)
        if mem.base == X86_REG_RIP:
            table_va = insn.address + insn.size + mem.disp
        elif mem.base == 0:
            table_va = mem.disp  # x86 absolute VA
        elif mem.base:
            base_reg_name = insn.reg_name(mem.base)
            table_va = _find_lea_value(prior_insns, base_reg_name)
        relative = False
    else:
        return None

    if table_va is None:
        return None
    table_rva = view.va_to_rva(table_va) if table_va >= view.image_base else table_va
    if table_rva < 0 or table_rva >= view.size_image:
        return None

    bound, bound_reg = _find_switch_bounds(prior_insns)
    case_base = _find_sub_base(prior_insns, index_reg, view.is_64)
    if case_base is None:
        case_base = 0
    if bound is not None:
        count = bound + 1
        if count <= 0 or count > 4096:
            count = None
    else:
        count = None

    # Pick relative vs absolute by how many entries resolve.
    best: list[tuple[int, int | None]] = []
    best_mode = "relative" if relative else "absolute"
    modes = ["relative", "absolute"] if scale == 4 else ["absolute"]
    for mode in modes:
        limit = count if count is not None else 256
        entries = _read_jump_entries(view, table_rva, scale, limit, mode)
        valid = sum(1 for _, t in entries if t is not None)
        if valid > sum(1 for _, t in best if t is not None):
            best = entries
            best_mode = mode
    if not best:
        return None
    valid = [(i, t) for i, t in best if t is not None]
    if not valid:
        return None

    cases = [
        {"value": (case_base + i) & 0xFFFFFFFF, "target_rva": t}
        for i, t in valid[:128]
    ]
    target_rvas = sorted({t for _, t in valid})
    return {
        "insn_va": insn.address,
        "insn_rva": view.va_to_rva(insn.address),
        "table_va": table_va,
        "table_rva": table_rva,
        "entry_size": scale,
        "entry_count": len(best),
        "mode": best_mode,
        "case_base": case_base,
        "large_switch": len(best) >= 5,
        "cases": cases,
        "target_rvas": target_rvas,
    }


def _analyze_region(view: _PeView, start_rva: int, max_instructions: int) -> dict:
    """Disassemble one function region and collect dispatch evidence."""
    work = [start_rva]
    visited_blocks: set[int] = set()
    instruction_count = 0
    block_count = 0
    comparisons: list[dict] = []
    jump_tables: list[dict] = []
    dispatch_tables: list[dict] = []
    seen_table_compares: set[int] = set()
    indirect_jumps = 0
    call_count = 0
    calls: list[dict] = []

    while work and instruction_count < max_instructions:
        block_rva = work.pop()
        if block_rva in visited_blocks:
            continue
        visited_blocks.add(block_rva)
        if not view.is_executable(block_rva):
            continue
        block_count += 1
        block_insns: list = []
        pc = block_rva
        instr_in_block = 0
        while instruction_count < max_instructions and instr_in_block < 512:
            insn = view.disasm_one(pc)
            if insn is None:
                break
            instruction_count += 1
            instr_in_block += 1
            block_insns.append(insn)
            mn = insn.mnemonic
            ops = insn.operands
            next_rva = pc + insn.size

            # 32-bit immediate comparisons are IOCTL candidates.
            if mn in ("cmp", "sub") and len(ops) == 2:
                dst, src = ops
                if (
                    dst.type == X86_OP_REG
                    and src.type == X86_OP_IMM
                    # Encoding width, not operand width: capstone reports
                    # a 32-bit operand for imm8-encoded cmp too.
                    and insn.encoding.imm_size == 4
                    and dst.size in (4, 8)
                    and ((dst.size == 4) or view.is_64)
                ):
                    reg_name = insn.reg_name(dst.reg)
                    if reg_name not in ("rsp", "esp", "rip"):
                        code = src.imm & 0xFFFFFFFF
                        comparisons.append(
                            {
                                "code": code,
                                "ref_va": insn.address,
                                "ref_rva": view.va_to_rva(insn.address),
                                "instruction": f"{mn} {insn.op_str}",
                                "mnemonic": mn,
                                "source": "immediate_compare",
                                "function_rva": start_rva,
                            }
                        )

            # Data-driven dispatch: the handler compares the IOCTL code
            # against a dword table after a bounds check.
            if mn == "cmp":
                table = _extract_table_dispatch_codes(view, insn, block_insns[:-1])
                if table is not None and table["compare_rva"] not in seen_table_compares:
                    seen_table_compares.add(table["compare_rva"])
                    dispatch_tables.append(table)
                    for entry in table["entries"]:
                        if not _plausible_ctl_code(entry["value"]):
                            continue
                        comparisons.append(
                            {
                                "code": entry["value"],
                                "ref_va": table["compare_va"],
                                "ref_rva": table["compare_rva"],
                                "instruction": (
                                    f"{insn.mnemonic} {insn.op_str} "
                                    f"(table[{entry['index']}] == 0x{entry['value']:08X})"
                                ),
                                "mnemonic": "cmp",
                                "source": "dispatch_table",
                                "table_entry_rva": entry["table_entry_rva"],
                                "function_rva": start_rva,
                            }
                        )

            if mn == "call":
                call_count += 1
                if ops and ops[0].type == X86_OP_IMM:
                    target_rva = view.va_to_rva(ops[0].imm)
                    if view.is_executable(target_rva):
                        calls.append(
                            {
                                "call_rva": view.va_to_rva(insn.address),
                                "target_rva": target_rva,
                            }
                        )
            if mn.startswith("j") and mn != "jmp":
                if ops and ops[0].type == X86_OP_IMM:
                    target_rva = view.va_to_rva(ops[0].imm)
                    if view.is_executable(target_rva):
                        work.append(target_rva)
                pc = next_rva
                continue
            if mn == "jmp":
                if ops and ops[0].type == X86_OP_IMM:
                    target_rva = view.va_to_rva(ops[0].imm)
                    if view.is_executable(target_rva):
                        work.append(target_rva)
                else:
                    indirect_jumps += 1
                    table = _resolve_jump_table(view, insn, block_insns[:-1])
                    if table is not None:
                        jump_tables.append(table)
                        for target_rva in table["target_rvas"]:
                            if target_rva not in visited_blocks:
                                work.append(target_rva)
                break
            if mn in ("ret", "retf", "iret", "iretq", "int3", "ud2", "hlt"):
                break
            pc = next_rva

    return {
        "start_rva": start_rva,
        "instructions": instruction_count,
        "blocks": block_count,
        "comparisons": len(comparisons),
        "call_count": call_count,
        "calls": calls,
        "indirect_jumps": indirect_jumps,
        "jump_tables": jump_tables,
        "dispatch_tables": dispatch_tables,
        "raw_comparisons": comparisons,
        "ioctl_codes": _merge_comparisons(comparisons),
    }


def _merge_comparisons(comparisons: list[dict]) -> list[dict]:
    """Deduplicate candidate immediates by value, keeping all refs."""
    by_code: dict[int, dict] = {}
    for comp in comparisons:
        entry = by_code.get(comp["code"])
        if entry is None:
            entry = {
                "code": comp["code"],
                "code_hex": f"0x{comp['code']:08X}",
                "ref_va": comp["ref_va"],
                "ref_rva": comp["ref_rva"],
                "instruction": comp["instruction"],
                "plausible": _plausible_ctl_code(comp["code"]),
                "ctl_code": _ctl_decode(comp["code"])
                if _plausible_ctl_code(comp["code"])
                else None,
                "refs": [],
                "sources": set(),
                "functions": set(),
            }
            by_code[comp["code"]] = entry
        ref = {
            "va": comp["ref_va"],
            "rva": comp["ref_rva"],
            "instruction": comp["instruction"],
            "source": comp.get("source", "immediate_compare"),
            "function_rva": comp.get("function_rva"),
        }
        if comp.get("table_entry_rva") is not None:
            ref["table_entry_rva"] = comp["table_entry_rva"]
        entry["refs"].append(ref)
        entry["sources"].add(ref["source"])
        if ref["function_rva"] is not None:
            entry["functions"].add(ref["function_rva"])
    ioctl_codes = []
    for code in sorted(by_code):
        entry = by_code[code]
        # Sets are not JSON-serialisable; normalise to sorted lists.
        entry["sources"] = sorted(entry["sources"])
        entry["functions"] = sorted(entry["functions"])
        ioctl_codes.append(entry)
    return ioctl_codes


def _analyze_handler(view: _PeView, handler_rva: int, max_instructions: int) -> dict:
    """Analyze the dispatch handler plus relevant direct callees.

    A registered IRP_MJ_DEVICE_CONTROL routine sometimes forwards to a
    local IOCTL processor (e.g. tcpip.sys).  A callee's comparisons are
    merged only when that callee itself contains at least two
    CTL_CODE-shaped immediates, which keeps generic helpers from
    polluting the candidate list.
    """
    root = _analyze_region(view, handler_rva, max_instructions)
    merged: list[dict] = list(root["raw_comparisons"])
    jump_tables = list(root["jump_tables"])
    dispatch_tables = list(root["dispatch_tables"])
    total_instructions = root["instructions"]
    total_blocks = root["blocks"]
    total_calls = root["call_count"]
    total_indirect = root["indirect_jumps"]
    callees: list[dict] = []

    queue: list[tuple[int, int]] = [(call["target_rva"], 1) for call in root["calls"]]
    seen = {handler_rva}
    budget = max(2000, max_instructions // 2)
    while queue and len(callees) < 8 and budget > 0:
        target_rva, depth = queue.pop(0)
        if target_rva in seen or depth > 2:
            continue
        seen.add(target_rva)
        sub = _analyze_region(view, target_rva, min(6000, budget))
        budget -= sub["instructions"]
        total_instructions += sub["instructions"]
        total_blocks += sub["blocks"]
        total_calls += sub["call_count"]
        total_indirect += sub["indirect_jumps"]
        if sub["instructions"] == 0:
            continue
        plausible = {
            comp["code"]
            for comp in sub["raw_comparisons"]
            if _plausible_ctl_code(comp["code"])
        }
        if len(plausible) < 2 and not sub["dispatch_tables"]:
            continue
        merged.extend(sub["raw_comparisons"])
        jump_tables.extend(sub["jump_tables"])
        dispatch_tables.extend(sub["dispatch_tables"])
        callees.append(
            {
                "rva": target_rva,
                "depth": depth,
                "instructions": sub["instructions"],
                "plausible_code_count": len(plausible),
                "dispatch_tables": len(sub["dispatch_tables"]),
            }
        )
        for call in sub["calls"]:
            queue.append((call["target_rva"], depth + 1))

    ioctl_codes = _merge_comparisons(merged)
    return {
        "handler_rva": handler_rva,
        "handler_va": view.rva_to_va(handler_rva),
        "instructions": total_instructions,
        "blocks": total_blocks,
        "comparisons": len(merged),
        "call_count": total_calls,
        "indirect_jumps": total_indirect,
        "jump_tables": jump_tables,
        "dispatch_tables": dispatch_tables,
        "ioctl_codes": ioctl_codes,
        "callees_analyzed": callees,
    }


# ---------------------------------------------------------------------------
# Strings / imports
# ---------------------------------------------------------------------------

def _extract_device_names(view: _PeView) -> tuple[list[str], list[dict]]:
    """Extract UTF-16LE ``\\Device\\`` / ``\\DosDevices\\`` strings."""
    names: list[str] = []
    refs: list[dict] = []
    seen: set[str] = set()
    sections = list(view.pe.sections)
    # Prefer .rdata, then other non-executable initialised sections.
    sections.sort(
        key=lambda s: (
            0 if b"rdata" in s.Name.lower() else 1,
            0 if not (s.Characteristics & 0x20000000) else 1,
        )
    )
    for sec in sections:
        if sec.Characteristics & 0x20000000:
            continue  # never expect UTF-16 literals in code
        body = view.section_bytes(sec)
        if not body:
            continue
        for match in UTF16_RUN.finditer(body):
            try:
                text = match.group(0).decode("utf-16-le")
            except UnicodeDecodeError:
                continue
            if "\\Device\\" not in text and "\\DosDevices\\" not in text:
                continue
            # An ASCII literal ending in "y\0" immediately before the
            # UTF-16 string can look like one extra WCHAR; trim anything
            # before the namespace prefix.
            starts = [
                index
                for index in (text.find("\\Device\\"), text.find("\\DosDevices\\"))
                if index >= 0
            ]
            if starts:
                text = text[min(starts) :]
            text = text.strip("\x00")
            if text in ("\\Device\\", "\\DosDevices\\"):
                continue
            if text in seen:
                continue
            seen.add(text)
            names.append(text)
            refs.append(
                {
                    "name": text,
                    "rva": sec.VirtualAddress + match.start(),
                    "section": sec.Name.rstrip(b"\x00").decode("ascii", errors="replace"),
                }
            )
    return names, refs


def _extract_imports_of_interest(view: _PeView) -> list[dict]:
    found: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for entry in getattr(view.pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        module = entry.dll.decode("ascii", errors="replace") if entry.dll else "unknown"
        for imp in entry.imports:
            if not imp.name:
                continue
            name = imp.name.decode("ascii", errors="replace")
            if name.lower() not in INTERESTING_IMPORTS:
                continue
            key = (module.lower(), name.lower())
            if key in seen:
                continue
            seen.add(key)
            iat_rva = None
            if isinstance(imp.address, int) and imp.address:
                iat_rva = (
                    imp.address - view.image_base
                    if imp.address >= view.image_base
                    else imp.address
                )
            found.append({"module": module, "name": name, "iat_rva": iat_rva})
    found.sort(key=lambda x: (x["module"].lower(), x["name"].lower()))
    return found


# ---------------------------------------------------------------------------
# Tool entry point
# ---------------------------------------------------------------------------

def _base_result(path: str, sha: str, size: int) -> dict:
    return {
        "path": path,
        "sha256": sha,
        "size": size,
        "file_type": "unknown",
        "machine": None,
        "is_64bit": None,
        "image_base": None,
        "entry_point_rva": None,
        "driver_entry_rva": None,
        "driver_entry_source": None,
        "driver_entry_evidence": [],
        "major_function_offset": None,
        "device_control_handler_rva": None,
        "device_control_handler_va": None,
        "device_control_handler_source": None,
        "handler_search": None,
        "handler_analysis": None,
        "jump_tables": [],
        "dispatch_tables": [],
        "ioctl_codes": [],
        "device_names": [],
        "device_name_refs": [],
        "imports_of_interest": [],
        "confidence": "unknown",
        "confidence_reasons": [],
        "notes": [],
        "analysis_status": "not_analyzed",
    }


@tool(
    "ioctl_extract",
    description=(
        "Statically locate DriverEntry and the IRP_MJ_DEVICE_CONTROL dispatch "
        "handler, then enumerate IOCTL-code comparisons and device names."
    ),
    risk_level=RiskLevel.LOW,
    requires_target=True,
    parameters_schema={
        "path": "absolute file path",
        "max_handler_instructions": "int (default 20000)",
    },
)
def ioctl_extract(path: str, max_handler_instructions: int = 20000) -> dict:
    p = Path(path)
    data = p.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    result = _base_result(str(p), sha, len(data))
    notes: list[str] = result["notes"]

    if not data.startswith(b"MZ"):
        notes.append("not an MZ/PE file; no driver structure can be extracted")
        result["analysis_status"] = "not_pe"
        return result

    try:
        pe = pefile.PE(data=data, fast_load=False)
    except pefile.PEFormatError as exc:
        notes.append(f"pefile could not parse the PE: {exc}")
        result["analysis_status"] = "parse_error"
        return result
    except Exception as exc:  # noqa: BLE001 - untrusted input robustness
        notes.append(f"unexpected PE parse failure: {type(exc).__name__}: {exc}")
        result["analysis_status"] = "parse_error"
        return result

    try:
        _run_analysis(pe, data, result, max_handler_instructions)
    finally:
        pe.close()
    return result


def _run_analysis(pe, data: bytes, result: dict, max_handler_instructions: int) -> None:
    notes: list[str] = result["notes"]
    magic = int(pe.OPTIONAL_HEADER.Magic)
    if magic not in (0x10B, 0x20B):
        result["file_type"] = f"pe_unknown_magic_0x{magic:X}"
        notes.append(
            f"unsupported optional-header magic 0x{magic:X}; expected 0x10B "
            "(PE32) or 0x20B (PE32+). This is not a valid PE32/PE32+ image, "
            "so no driver structure can be analysed."
        )
        result["analysis_status"] = "unsupported_format"
        result["confidence"] = "low"
        result["confidence_reasons"] = [
            f"optional-header magic 0x{magic:X} is neither PE32 nor PE32+"
        ]
        return
    view = _PeView(pe, data, result["path"])
    result["file_type"] = "pe32+" if view.is_64 else "pe32"
    result["machine"] = MACHINES.get(
        pe.FILE_HEADER.Machine, f"0x{pe.FILE_HEADER.Machine:04X}"
    )
    result["is_64bit"] = view.is_64
    result["image_base"] = view.image_base
    result["entry_point_rva"] = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    result["major_function_offset"] = view.device_control_offset
    notes.append(
        f"DRIVER_OBJECT.MajorFunction base=0x{view.major_function_base:X}, "
        f"pointer_size={view.pointer_size}, "
        f"MajorFunction[IRP_MJ_DEVICE_CONTROL] offset=0x{view.device_control_offset:X}"
    )

    result["imports_of_interest"] = _extract_imports_of_interest(view)
    if result["imports_of_interest"]:
        notes.append(
            "imports of interest: "
            + ", ".join(sorted({i['name'] for i in result['imports_of_interest']}))
        )
    else:
        notes.append("no imports from the security-interest list were found")

    names, refs = _extract_device_names(view)
    result["device_names"] = names
    result["device_name_refs"] = refs
    if names:
        notes.append(f"found {len(names)} UTF-16LE device/symlink name(s) in data sections")
    else:
        notes.append(
            "no UTF-16LE \\Device\\ or \\DosDevices\\ strings found in non-executable sections"
        )

    entry_rva, entry_source, entry_notes = _find_driver_entry(view)
    notes.extend(entry_notes)
    result["driver_entry_rva"] = entry_rva
    result["driver_entry_source"] = entry_source

    if entry_rva is None:
        result["analysis_status"] = "no_driver_entry"
        result["confidence"] = "low"
        result["confidence_reasons"] = ["no usable DriverEntry/entry point"]
        return

    scan = _scan_for_major_store(view, entry_rva)
    result["handler_search"] = {
        "instructions_scanned": scan["instructions_scanned"],
        "driver_object_store_count": len(scan["stores"]),
        "calls_followed": scan["calls_followed"],
        "major_function_writes": [
            {
                "store_rva": s["store_rva"],
                "offset": s["offset"],
                "is_device_control": s["is_device_control"],
                "is_driver_unload": s.get("is_driver_unload", False),
                "base_provenance": s["base_provenance"],
                "base_register": s["base_register"],
                "resolved_rva": s["resolved_rva"],
                "resolution": s["resolution"],
                "function_rva": s.get("function_rva"),
                "instruction": s["instruction"],
            }
            for s in scan["stores"]
        ],
    }

    dev_writes = [s for s in scan["stores"] if s["is_device_control"]]
    resolved = [s for s in dev_writes if s["resolved_rva"] is not None]
    chosen = None
    if resolved:
        chosen = sorted(resolved, key=lambda s: (not s["base_provenance"], s["store_rva"]))[0]
    elif dev_writes:
        chosen = dev_writes[0]

    evidence: list[str] = []
    if entry_source == "export":
        evidence.append("DriverEntry resolved from the export table")
    else:
        evidence.append("DriverEntry resolved from AddressOfEntryPoint (no export)")
    if scan["stores"]:
        evidence.append(
            f"{len(scan['stores'])} DRIVER_OBJECT store(s) observed "
            f"(MajorFunction/DriverUnload)"
        )
        callee_functions = sorted(
            {
                s["function_rva"]
                for s in scan["stores"]
                if s.get("function_rva") is not None
                and s["function_rva"] != entry_rva
            }
        )
        if callee_functions:
            evidence.append(
                "DriverObject-referencing init code also found in directly-called "
                "function(s): "
                + ", ".join(f"RVA 0x{rva:X}" for rva in callee_functions)
            )
    else:
        evidence.append("no DRIVER_OBJECT stores observed in DriverEntry scan")
    result["driver_entry_evidence"] = evidence

    if chosen is not None:
        result["device_control_handler_rva"] = chosen["resolved_rva"]
        result["device_control_handler_va"] = chosen["resolved_va"]
        result["device_control_handler_source"] = "driver_entry"
        if chosen["resolved_rva"] is None:
            notes.append(
                "a write to MajorFunction[IRP_MJ_DEVICE_CONTROL] was found at "
                f"RVA 0x{chosen['store_rva']:X} ({chosen['instruction']}), but the "
                f"stored handler value could not be resolved ({chosen['resolution']})"
            )
        else:
            prov = "with DriverObject provenance" if chosen["base_provenance"] else "without provenance"
            notes.append(
                "found MajorFunction[IRP_MJ_DEVICE_CONTROL] write at "
                f"RVA 0x{chosen['store_rva']:X} ({chosen['instruction']}) "
                f"{prov}; handler RVA 0x{chosen['resolved_rva']:X}"
            )
            if not chosen["base_provenance"]:
                notes.append(
                    "handler store base register provenance is unknown; treat the "
                    "handler RVA as a lower-confidence candidate"
                )
        if len(resolved) > 1:
            notes.append(
                "multiple resolved IRP_MJ_DEVICE_CONTROL stores: "
                + ", ".join(f"RVA 0x{s['resolved_rva']:X}" for s in resolved)
                + f"; using RVA 0x{chosen['resolved_rva']:X}"
                if chosen["resolved_rva"] is not None
                else "multiple IRP_MJ_DEVICE_CONTROL stores found"
            )
    else:
        notes.append(
            "no write to MajorFunction[IRP_MJ_DEVICE_CONTROL] "
            f"(offset 0x{view.device_control_offset:X}) was found in DriverEntry "
            "or its directly-followed callees; device_control_handler_rva is null"
        )
        written_slots = sorted(
            {
                s["offset"]
                for s in scan["stores"]
                if s.get("base_provenance")
                and view.major_function_base
                <= s["offset"]
                < view.major_function_base
                + MAJOR_FUNCTION_COUNT * view.pointer_size
            }
        )
        if written_slots:
            notes.append(
                "MajorFunction slots written: "
                + ", ".join(f"0x{offset:X}" for offset in written_slots)
                + f"; the IRP_MJ_DEVICE_CONTROL slot (0x{view.device_control_offset:X}) "
                "is not among them"
            )
        elif not scan["stores"]:
            notes.append(
                "no DriverObject-referencing initialisation code was observed at all; "
                "this is typical for KMDF/WDF drivers or when initialisation happens "
                "through indirect calls"
            )
        notes.append(
            "this is an absence of static evidence, not proof that the driver "
            "lacks an IOCTL interface (the assignment may happen in a helper "
            "outside the followed call depth or through computed code)"
        )
        result["analysis_status"] = "no_device_control_handler"
        result["confidence"] = "low"
        result["confidence_reasons"] = [
            "DriverEntry found but no IRP_MJ_DEVICE_CONTROL handler store observed"
        ]
        return

    handler_rva = result["device_control_handler_rva"]
    if handler_rva is None:
        result["analysis_status"] = "handler_unresolved"
        result["confidence"] = "low"
        result["confidence_reasons"] = ["handler store found but target unresolved"]
        return

    analysis = _analyze_handler(view, handler_rva, max_handler_instructions)
    result["handler_analysis"] = {
        "instructions": analysis["instructions"],
        "blocks": analysis["blocks"],
        "comparisons": analysis["comparisons"],
        "call_count": analysis["call_count"],
        "indirect_jumps": analysis["indirect_jumps"],
        "jump_tables": len(analysis["jump_tables"]),
        "dispatch_tables": len(analysis["dispatch_tables"]),
        "callees_analyzed": analysis.get("callees_analyzed", []),
    }
    result["jump_tables"] = analysis["jump_tables"]
    result["dispatch_tables"] = analysis["dispatch_tables"]
    result["ioctl_codes"] = analysis["ioctl_codes"]

    if analysis["instructions"] == 0:
        notes.append(
            f"handler RVA 0x{handler_rva:X} could not be disassembled "
            "(not executable or outside mapped code)"
        )
        result["analysis_status"] = "handler_not_disassembled"
        result["confidence"] = "low"
        result["confidence_reasons"] = ["dispatch handler could not be disassembled"]
        return

    plausible = [c for c in analysis["ioctl_codes"] if c["plausible"]]
    if analysis["jump_tables"]:
        for jt in analysis["jump_tables"]:
            notes.append(
                "jump table at RVA 0x%X (%d entries, %s mode%s)"
                % (
                    jt["table_rva"],
                    jt["entry_count"],
                    jt["mode"],
                    ", large switch" if jt["large_switch"] else "",
                )
            )
    if analysis["dispatch_tables"]:
        for dt in analysis["dispatch_tables"]:
            sample = [entry["value"] for entry in dt["entries"]][:5]
            notes.append(
                "data-driven IOCTL dispatch table at RVA 0x%X: %d accepted "
                "code(s) checked at RVA 0x%X (first: %s)"
                % (
                    dt["table_rva"],
                    dt["entry_count"],
                    dt["compare_rva"],
                    ", ".join(f"0x{v:08X}" for v in sample),
                )
            )
    for callee in analysis.get("callees_analyzed", []):
        notes.append(
            "followed dispatch callee RVA 0x%X (%d instructions, %d plausible "
            "code(s), %d dispatch table(s))"
            % (
                callee["rva"],
                callee["instructions"],
                callee["plausible_code_count"],
                callee["dispatch_tables"],
            )
        )
    if plausible:
        notes.append(
            f"handler contains {analysis['comparisons']} 32-bit immediate "
            f"comparison(s); {len(plausible)} distinct value(s) look like CTL_CODEs"
        )
    elif analysis["comparisons"]:
        notes.append(
            f"handler contains {analysis['comparisons']} 32-bit immediate "
            "comparison(s), but none look like CTL_CODE values (device type 0)"
        )
    else:
        notes.append("handler contains no 32-bit immediate comparisons")
    notes.append(
        "IOCTL codes are static candidates taken from cmp/sub immediates in the "
        "dispatch handler; they are not proof of a reachable or vulnerable IOCTL"
    )

    result["analysis_status"] = "ok" if plausible else "no_plausible_ioctl_codes"
    reasons: list[str] = []
    if entry_source == "export":
        reasons.append("DriverEntry from export table")
    else:
        reasons.append("DriverEntry from PE entry point (no export)")
    if chosen["base_provenance"]:
        reasons.append("handler store has DriverObject provenance")
    else:
        reasons.append("handler store lacks DriverObject provenance")
    if plausible:
        reasons.append(f"{len(plausible)} plausible CTL_CODE candidate(s)")
        result["confidence"] = "high" if entry_source == "export" else "medium"
    else:
        reasons.append("no plausible CTL_CODE candidates in handler")
        result["confidence"] = "low"
    result["confidence_reasons"] = reasons
