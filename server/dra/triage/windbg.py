"""Parser for recorded WinDbg ``!analyze -v`` output.

The platform does not run a kernel debugger in Phase 0/1.  Instead the lab
records the textual output of ``!analyze -v`` and hands it to triage.  This
module is the only place that understands that text.

Design rules, in order of importance:

* **Never invent a value.**  A field that is absent from the text is
  ``None`` here and is listed in :attr:`WinDbgAnalysis.missing_fields`.
  Downstream code turns those into the literal string ``"unknown"``; it
  must not fill gaps with a plausible-looking guess.
* **Tolerate real output.**  WinDbg prints addresses with a backtick
  separator (``fffff805`12345678``), prints source annotations as
  ``[c:\\src\\foo.c @ 42]``, emits ``WARNING:`` lines in the middle of a
  stack, and omits whole sections depending on symbols and bugcheck.
* **Keep provenance.**  Frames are preserved in order; the "faulting
  frame" is the first frame that is not part of the bugcheck machinery
  (``KeBugCheckEx`` / ``KiPageFault`` / ...), which is what a human
  triager reads as the crash site.

The parser does not interpret the bugcheck; classification lives in
:mod:`dra.triage.classify`.
"""

import re
from dataclasses import dataclass, field

UNKNOWN = "unknown"

# ---------------------------------------------------------------------------
# Stack frames
# ---------------------------------------------------------------------------

_SYMBOL_RE = re.compile(
    r"(?P<module>[A-Za-z0-9_.\-]+)!"
    r"(?P<symbol>[A-Za-z_~?][A-Za-z0-9_@?$<>\\]*)"
    r"(?:\+(?P<offset>0x[0-9a-fA-F]+))?"
)
_MODULE_OFFSET_RE = re.compile(
    r"(?P<module>[A-Za-z0-9_.\-]+)\+(?P<offset>0x[0-9a-fA-F]+)"
)
_SOURCE_RE = re.compile(r"\[(?P<file>[^\[\]]+?)\s+@\s+(?P<line>\d+)\]")
_FRAME_ADDRESS_RE = re.compile(
    r"^\s*(?:[0-9a-fA-F]{2,4}\s+)?(?:0x)?(?P<address>[0-9a-fA-F]{8,16})\b"
)

# The bugcheck machinery sits *above* the faulting frame.  Skipping it is
# not a guess: these routines are the ones that report a fault, never the
# code that caused it.
_BUGCHECK_MECHANISM = frozenset(
    {
        "kebugcheckex",
        "kebugcheck2",
        "kibugcheckdispatch",
        "kipagefault",
        "kifastfaildispatch",
        "kiraisesecuritycheckfailure",
        "kiexceptiondispatch",
        "kidispatchexception",
        "kisystemfatalexception",
        "kihandlexception",
        "kisecuritycheckfailure",
        "kifatalexception",
    }
)


@dataclass(frozen=True)
class StackFrame:
    """One frame from ``STACK_TEXT``.

    ``module`` / ``symbol`` / ``offset`` are the vendor-facing identity
    (``mydriver!Func+0x1a``).  Any of them may be ``None`` when WinDbg
    could not resolve symbols; callers must surface that as ``unknown``
    rather than substituting another frame.
    """

    index: int
    raw: str
    address: str | None = None
    module: str | None = None
    symbol: str | None = None
    offset: int | None = None
    source_file: str | None = None
    source_line: int | None = None

    @property
    def qualified(self) -> str | None:
        if self.module and self.symbol:
            base = f"{self.module}!{self.symbol}"
            if self.offset is not None:
                return f"{base}+0x{self.offset:x}"
            return base
        if self.module and self.offset is not None:
            return f"{self.module}+0x{self.offset:x}"
        if self.module:
            return self.module
        return None

    @property
    def location(self) -> str:
        return self.qualified or UNKNOWN

    @property
    def is_resolved(self) -> bool:
        return self.module is not None

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "raw": self.raw,
            "address": self.address,
            "module": self.module,
            "symbol": self.symbol,
            "offset": self.offset,
            "source_file": self.source_file,
            "source_line": self.source_line,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "StackFrame":
        return cls(
            index=int(data.get("index", 0)),
            raw=str(data.get("raw", "")),
            address=data.get("address"),
            module=data.get("module"),
            symbol=data.get("symbol"),
            offset=data.get("offset"),
            source_file=data.get("source_file"),
            source_line=data.get("source_line"),
        )


def _parse_frame(line: str, index: int) -> StackFrame | None:
    """Parse one ``STACK_TEXT`` line, or return ``None`` if it is not one."""
    text = line.strip()
    if not text:
        return None

    module: str | None = None
    symbol: str | None = None
    offset: int | None = None

    m = _SYMBOL_RE.search(text)
    if m:
        module = m.group("module")
        symbol = m.group("symbol")
        raw_offset = m.group("offset")
        offset = int(raw_offset, 16) if raw_offset else None
    else:
        m = _MODULE_OFFSET_RE.search(text)
        if m:
            module = m.group("module")
            offset = int(m.group("offset"), 16)

    addr_m = _FRAME_ADDRESS_RE.match(text)
    address = addr_m.group("address") if addr_m else None

    if module is None and symbol is None and address is None:
        return None

    src = _SOURCE_RE.search(text)
    return StackFrame(
        index=index,
        raw=text[:500],
        address=address,
        module=module,
        symbol=symbol,
        offset=offset,
        source_file=src.group("file").strip() if src else None,
        source_line=int(src.group("line")) if src else None,
    )


# ---------------------------------------------------------------------------
# Top-level fields
# ---------------------------------------------------------------------------

_KV_RE = re.compile(r"^([A-Z][A-Z0-9_]{2,40}):\s*(.*)$")
_ARG_RE = re.compile(r"^Arg([1-4]):\s*([0-9a-fA-F]+)\b", re.IGNORECASE)
_BUGCHECK_NAME_RE = re.compile(
    r"^([A-Z][A-Z0-9_]{3,})\s*\(([0-9a-fA-F]{1,8})\)\s*$"
)
_BUGCHECK_LINE_RE = re.compile(
    r"^BugCheck\s+([0-9a-fA-F]+),\s*\{([^}]*)\}", re.IGNORECASE
)

_REGISTER_NAMES = frozenset(
    {
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip",
        "eflags", "rflags", "efl",
    }
)
_REGISTER_RE = re.compile(
    r"\b(?P<name>[a-zA-Z][a-zA-Z0-9]{1,3})\s*=\s*(?P<value>[0-9a-fA-F]{4,16})\b"
)

# Mitigations are only reported when the recorded text actually shows
# them.  An empty list means "not visible", never "not enabled".
_MITIGATION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "Driver Verifier",
        re.compile(
            r"(?i)(?:\bdriver verifier\b|\bverifier!|\bverifier\.sys\b"
            r"|\bverifier enabled\b|DRIVER_VERIFIER_DETECTED_VIOLATION)"
        ),
    ),
    (
        "CFG",
        re.compile(
            r"(?i)(?:\bcontrol flow guard\b|\bguard_icall\b"
            r"|\bGUARD_ICALL_CHECK_FAILURE\b|\b__guard_check_icall\b"
            r"|\bCFG\s*(?:enabled|disabled|on|off)\b)"
        ),
    ),
    (
        "HVCI",
        re.compile(
            r"(?i)(?:\bHVCI\b|\bhypervisor[- ]enforced code integrity\b"
            r"|\bhypervisor code integrity\b)"
        ),
    ),
    (
        "DEP/NX",
        re.compile(
            r"(?i)(?:\bDEP\s*(?:enabled|disabled|on|off)\b"
            r"|\bNX\s*(?:enabled|disabled|on|off)\b"
            r"|\bdata execution prevention\b|\bno[- ]execute\b"
            r"|\bexecute disable\b)"
        ),
    ),
    ("SMEP", re.compile(r"(?i)\bSMEP\b")),
    ("SMAP", re.compile(r"(?i)\bSMAP\b")),
    (
        "KASLR",
        re.compile(r"(?i)\bKASLR\b|\bkernel ASLR\b"),
    ),
)

#: Fields a vendor triage report is expected to answer.  Missing ones are
#: recorded explicitly rather than guessed; downstream code uses this list
#: when no analysis text exists at all.
CORE_FIELDS: tuple[str, ...] = (
    "bugcheck_code",
    "bugcheck_name",
    "bugcheck_arguments",
    "process_name",
    "image_name",
    "module_name",
    "faulting_module",
    "stack_text",
    "symbol_name",
    "failure_bucket_id",
    "registers",
)


def _parse_leading_hex(value: str) -> int | None:
    """Parse the hex number at the start of a field value.

    WinDbg writes values as ``0000000000000000, memory referenced`` or
    ``fffff805`12345678``.  Only the leading token is considered so that
    prose such as "not available" can never be read as hex.
    """
    cleaned = value.replace("`", "").strip()
    m = re.match(r"^(?:0x)?([0-9a-fA-F]{1,16})\b", cleaned)
    return int(m.group(1), 16) if m else None


_PLACEHOLDER_VALUES = frozenset(
    {"", "-", "?", "??", "n/a", "na", "unknown", "<unknown>", "none", "null"}
)


def _clean_str(value: str | None) -> str | None:
    """Treat WinDbg's explicit unknown markers as absent fields."""
    if value is None:
        return None
    text = str(value).strip()
    if text.lower() in _PLACEHOLDER_VALUES:
        return None
    return text


def _module_token(value: str) -> str | None:
    """Extract the module name from ``FAULTING_MODULE``.

    Formats seen in the wild::

        FAULTING_MODULE: fffff80512345678 mydriver
        FAULTING_MODULE: 00000000 mydriver
        FAULTING_MODULE: mydriver
    """
    for token in re.split(r"[\s,]+", value.replace("`", "").strip()):
        if not token:
            continue
        if re.fullmatch(r"(?:0x)?[0-9a-fA-F]{4,16}", token):
            continue
        if re.fullmatch(r"[A-Za-z0-9_.\-]+", token):
            return token
    return None


@dataclass(frozen=True)
class WinDbgAnalysis:
    """Structured view of one ``!analyze -v`` output."""

    raw: str = ""
    bugcheck_code: int | None = None
    bugcheck_name: str | None = None
    bugcheck_arguments: tuple[int | None, int | None, int | None, int | None] = (
        None,
        None,
        None,
        None,
    )
    process_name: str | None = None
    image_name: str | None = None
    module_name: str | None = None
    faulting_module: str | None = None
    stack: tuple[StackFrame, ...] = ()
    symbol_name: str | None = None
    failure_bucket_id: str | None = None
    failure_id_hash: str | None = None
    read_address: int | None = None
    write_address: int | None = None
    execute_address: int | None = None
    pool_address: int | None = None
    exception_code: int | None = None
    exception_address: int | None = None
    probably_invalid_acquire: str | None = None
    probably_invalid_release: str | None = None
    registers: dict[str, int] = field(default_factory=dict)
    driver_verifier: bool = False
    verifier_details: tuple[str, ...] = ()
    mitigations: tuple[str, ...] = ()
    missing_fields: tuple[str, ...] = ()
    parse_warnings: tuple[str, ...] = ()

    # -- derived views -------------------------------------------------

    @property
    def bugcheck_label(self) -> str:
        name = self.bugcheck_name or UNKNOWN
        code = (
            f"0x{self.bugcheck_code:X}"
            if self.bugcheck_code is not None
            else UNKNOWN
        )
        return f"{name} ({code})"

    @property
    def has_bugcheck(self) -> bool:
        return self.bugcheck_code is not None or self.bugcheck_name is not None

    @property
    def faulting_frame(self) -> StackFrame | None:
        """First frame that is not bugcheck machinery.

        If an unresolved frame occurs before any known non-machinery
        frame, the crash site is genuinely unknown and ``None`` is
        returned.  Returning a lower frame would misattribute the crash.
        """
        for frame in self.stack:
            if frame.module is None and frame.symbol is None:
                if frame.address is not None:
                    return None
                continue
            symbol = (frame.symbol or "").lower()
            if symbol in _BUGCHECK_MECHANISM:
                continue
            return frame
        return None

    @property
    def observed_mitigations(self) -> tuple[str, ...]:
        if self.mitigations:
            return self.mitigations
        text = self.raw or ""
        return tuple(name for name, pattern in _MITIGATION_PATTERNS if pattern.search(text))

    @property
    def is_parsed(self) -> bool:
        return self.has_bugcheck and bool(self.stack)

    # -- persistence ---------------------------------------------------

    def to_dict(self) -> dict:
        """JSON-safe representation.

        ``raw`` is intentionally omitted: the original text lives in the
        crash record / artifact store, and persisting it again would
        double the storage for every node.
        """
        return {
            "bugcheck_code": self.bugcheck_code,
            "bugcheck_name": self.bugcheck_name,
            "bugcheck_arguments": list(self.bugcheck_arguments),
            "process_name": self.process_name,
            "image_name": self.image_name,
            "module_name": self.module_name,
            "faulting_module": self.faulting_module,
            "stack": [frame.to_dict() for frame in self.stack],
            "symbol_name": self.symbol_name,
            "failure_bucket_id": self.failure_bucket_id,
            "failure_id_hash": self.failure_id_hash,
            "read_address": self.read_address,
            "write_address": self.write_address,
            "execute_address": self.execute_address,
            "pool_address": self.pool_address,
            "exception_code": self.exception_code,
            "exception_address": self.exception_address,
            "probably_invalid_acquire": self.probably_invalid_acquire,
            "probably_invalid_release": self.probably_invalid_release,
            "registers": dict(self.registers),
            "driver_verifier": self.driver_verifier,
            "verifier_details": list(self.verifier_details),
            "mitigations": list(self.mitigations),
            "missing_fields": list(self.missing_fields),
            "parse_warnings": list(self.parse_warnings),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "WinDbgAnalysis":
        args = list(data.get("bugcheck_arguments") or [])
        args += [None] * (4 - len(args))
        return cls(
            raw="",
            bugcheck_code=_as_int(data.get("bugcheck_code")),
            bugcheck_name=data.get("bugcheck_name"),
            bugcheck_arguments=(args[0], args[1], args[2], args[3]),
            process_name=data.get("process_name"),
            image_name=data.get("image_name"),
            module_name=data.get("module_name"),
            faulting_module=data.get("faulting_module"),
            stack=tuple(
                StackFrame.from_dict(item) for item in (data.get("stack") or [])
            ),
            symbol_name=data.get("symbol_name"),
            failure_bucket_id=data.get("failure_bucket_id"),
            failure_id_hash=data.get("failure_id_hash"),
            read_address=_as_int(data.get("read_address")),
            write_address=_as_int(data.get("write_address")),
            execute_address=_as_int(data.get("execute_address")),
            pool_address=_as_int(data.get("pool_address")),
            exception_code=_as_int(data.get("exception_code")),
            exception_address=_as_int(data.get("exception_address")),
            probably_invalid_acquire=data.get("probably_invalid_acquire"),
            probably_invalid_release=data.get("probably_invalid_release"),
            registers={
                str(k): int(v)
                for k, v in (data.get("registers") or {}).items()
                if _as_int(v) is not None
            },
            driver_verifier=bool(data.get("driver_verifier")),
            verifier_details=tuple(data.get("verifier_details") or ()),
            mitigations=tuple(data.get("mitigations") or ()),
            missing_fields=tuple(data.get("missing_fields") or ()),
            parse_warnings=tuple(data.get("parse_warnings") or ()),
        )


def _as_int(value) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_windbg_analysis(text: str | None) -> WinDbgAnalysis:
    """Parse ``!analyze -v`` output.

    The function is total: any text produces a :class:`WinDbgAnalysis`.
    When the text is not analysis output, every field stays ``None`` and
    :attr:`WinDbgAnalysis.missing_fields` says so.
    """
    raw = text or ""
    normalized = raw.replace("`", "").replace("\r\n", "\n").replace("\r", "\n")
    lines = normalized.split("\n")

    kv: dict[str, str] = {}
    args_by_index: dict[int, int] = {}
    p_by_index: dict[int, int] = {}
    frames: list[StackFrame] = []
    warnings: list[str] = []
    verifier_details: list[str] = []
    registers: dict[str, int] = {}

    bugcheck_name: str | None = None
    bugcheck_code_from_name: int | None = None
    bugcheck_code_from_line: int | None = None
    line_arguments: list[int] = []

    in_stack = False

    for line in lines:
        stripped = line.strip()
        if not stripped:
            if in_stack:
                in_stack = False
            continue

        if in_stack:
            header = _KV_RE.match(stripped)
            if header and not stripped.lower().startswith(("warning:", "error:")):
                in_stack = False
                # fall through: the line is a section header
            else:
                if stripped.lower().startswith(("warning:", "error:")) or stripped.startswith("***"):
                    warnings.append(stripped)
                    continue
                frame = _parse_frame(stripped, len(frames))
                if frame is not None:
                    frames.append(frame)
                continue

        # -- argument block -------------------------------------------------
        arg_m = _ARG_RE.match(stripped)
        if arg_m:
            args_by_index[int(arg_m.group(1)) - 1] = int(arg_m.group(2), 16)
            continue

        # -- bugcheck header line ------------------------------------------
        name_m = _BUGCHECK_NAME_RE.match(stripped)
        if name_m and bugcheck_name is None:
            bugcheck_name = name_m.group(1)
            bugcheck_code_from_name = int(name_m.group(2), 16)
            continue
        line_m = _BUGCHECK_LINE_RE.match(stripped)
        if line_m and bugcheck_name is None:
            bugcheck_code_from_line = int(line_m.group(1), 16)
            for part in line_m.group(2).split(","):
                value = _parse_leading_hex(part)
                if value is not None:
                    line_arguments.append(value)
            continue

        # -- top-level key/value -------------------------------------------
        kv_m = _KV_RE.match(stripped)
        if kv_m:
            key, value = kv_m.group(1), kv_m.group(2).strip()
            if key == "STACK_TEXT":
                in_stack = True
                if value:
                    frame = _parse_frame(value, len(frames))
                    if frame is not None:
                        frames.append(frame)
                continue
            if key.startswith("BUGCHECK_P") and key[10:].isdigit():
                index = int(key[10:]) - 1
                if 0 <= index < 4:
                    parsed = _parse_leading_hex(value)
                    if parsed is not None:
                        p_by_index[index] = parsed
            if key not in kv or not kv[key]:
                kv[key] = value
            if "verifier" in stripped.lower() and len(verifier_details) < 10:
                verifier_details.append(stripped[:300])
            continue

        # -- registers (CONTEXT / TRAP_FRAME) ------------------------------
        for reg_m in _REGISTER_RE.finditer(stripped):
            name = reg_m.group("name").lower()
            if name in _REGISTER_NAMES:
                registers.setdefault(name, int(reg_m.group("value"), 16))

    # Bugcheck code: explicit code wins, then the name line, then the
    # legacy "BugCheck A, {...}" form.
    code: int | None = None
    raw_code = kv.get("BUGCHECK_CODE", "")
    if raw_code:
        code = _parse_leading_hex(raw_code)
    if code is None:
        code = bugcheck_code_from_name
    if code is None:
        code = bugcheck_code_from_line

    arguments: list[int | None] = [None, None, None, None]
    for i in range(4):
        if i in p_by_index:
            arguments[i] = p_by_index[i]
        elif i in args_by_index:
            arguments[i] = args_by_index[i]
        elif i < len(line_arguments):
            arguments[i] = line_arguments[i]

    image_name = _clean_str(kv.get("IMAGE_NAME"))
    module_name = _clean_str(kv.get("MODULE_NAME"))
    faulting_module = _clean_str(_module_token(kv.get("FAULTING_MODULE", "")))

    process_name = _clean_str(kv.get("PROCESS_NAME"))
    symbol_name = _clean_str(kv.get("SYMBOL_NAME"))
    # FAILURE_BUCKET_ID is the canonical field; DEFAULT_BUCKET_ID is the
    # older name and carries the same kind of hint when the former is
    # absent.  This is a field fallback, not an inferred value.
    failure_bucket_id = _clean_str(kv.get("FAILURE_BUCKET_ID")) or _clean_str(
        kv.get("DEFAULT_BUCKET_ID")
    )
    failure_id_hash = _clean_str(kv.get("FAILURE_ID_HASH"))

    read_address = _parse_leading_hex(kv.get("READ_ADDRESS", "")) if kv.get("READ_ADDRESS") else None
    write_address = _parse_leading_hex(kv.get("WRITE_ADDRESS", "")) if kv.get("WRITE_ADDRESS") else None
    execute_address = (
        _parse_leading_hex(kv.get("EXECUTE_ADDRESS", "")) if kv.get("EXECUTE_ADDRESS") else None
    )
    pool_address = _parse_leading_hex(kv.get("POOL_ADDRESS", "")) if kv.get("POOL_ADDRESS") else None
    exception_code = (
        _parse_leading_hex(kv.get("EXCEPTION_CODE", "")) if kv.get("EXCEPTION_CODE") else None
    )
    exception_address = (
        _parse_leading_hex(kv.get("EXCEPTION_ADDRESS", "")) if kv.get("EXCEPTION_ADDRESS") else None
    )

    driver_verifier = bool(
        (bugcheck_name and "VERIFIER" in bugcheck_name.upper())
        or any(
            _MITIGATION_PATTERNS[0][1].search(item) for item in verifier_details
        )
        or any((frame.module or "").lower() == "verifier" for frame in frames)
    )

    analysis = WinDbgAnalysis(
        raw=raw,
        bugcheck_code=code,
        bugcheck_name=bugcheck_name,
        bugcheck_arguments=(arguments[0], arguments[1], arguments[2], arguments[3]),
        process_name=process_name,
        image_name=image_name,
        module_name=module_name,
        faulting_module=faulting_module,
        stack=tuple(frames),
        symbol_name=symbol_name,
        failure_bucket_id=failure_bucket_id,
        failure_id_hash=failure_id_hash,
        read_address=read_address,
        write_address=write_address,
        execute_address=execute_address,
        pool_address=pool_address,
        exception_code=exception_code,
        exception_address=exception_address,
        probably_invalid_acquire=_clean_str(kv.get("PROBABLY_INVALID_ACQUIRE")),
        probably_invalid_release=_clean_str(kv.get("PROBABLY_INVALID_RELEASE")),
        registers=registers,
        driver_verifier=driver_verifier,
        verifier_details=tuple(verifier_details),
        mitigations=tuple(
            name for name, pattern in _MITIGATION_PATTERNS if pattern.search(normalized)
        ),
        parse_warnings=tuple(warnings),
    )

    missing: list[str] = []
    if analysis.bugcheck_code is None:
        missing.append("bugcheck_code")
    if analysis.bugcheck_name is None:
        missing.append("bugcheck_name")
    if all(arg is None for arg in analysis.bugcheck_arguments):
        missing.append("bugcheck_arguments")
    if not analysis.process_name:
        missing.append("process_name")
    if not analysis.image_name:
        missing.append("image_name")
    if not analysis.module_name:
        missing.append("module_name")
    if not analysis.faulting_module:
        missing.append("faulting_module")
    if not analysis.stack:
        missing.append("stack_text")
    if not analysis.symbol_name:
        missing.append("symbol_name")
    if not analysis.failure_bucket_id:
        missing.append("failure_bucket_id")
    if not analysis.registers:
        missing.append("registers")

    return WinDbgAnalysis(
        **{**analysis.__dict__, "missing_fields": tuple(missing)}
    )
