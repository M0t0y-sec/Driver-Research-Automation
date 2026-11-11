"""Deterministic defect classification from a parsed WinDbg analysis.

The vendor question is not "did it crash?" but "is the defect ours?".
This module answers three things from facts in the dump:

1. **What kind of defect** the bugcheck is consistent with
   (``null_deref``, ``pool_corruption``, ``use_after_free``, ...).
2. **Where the fault happened** (module!function+offset, or ``unknown``).
3. **Who owns the faulting component** - the target driver, a third-party
   driver, an OS routine, or the environment.

Attribution is deliberately conservative:

* The faulting frame decides ownership.  If it is the target driver, the
  defect is the target's.
* If it is a third-party driver, the result is ``third_party_driver`` even
  when the target driver appears lower in the call chain.  Vendors reject
  "our driver crashed because we called someone else's code" without
  evidence that the input violated that module's contract.
* If it is an OS routine, the closest non-OS caller decides: an OS free
  routine corrupting a pool block that the target driver passed in is
  attributed to the target, with ``medium`` confidence and an explicit
  reason.
* If the stack is missing or unresolved above the first non-machinery
  frame, attribution is ``unknown`` - never guessed.

Categories are descriptions of the *observed* failure, not proof of the
underlying defect.  ``BAD_POOL_HEADER`` proves pool metadata was already
corrupt when it was touched; the write that corrupted it is usually not
in the crash stack.  The reasons tuple records that limitation so a
human (and the downstream report) sees it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .windbg import UNKNOWN, StackFrame, WinDbgAnalysis

#: Categories that describe a memory-safety defect.  Used by impact and
#: exploitability to decide whether the crash is merely a DoS or could
#: support memory corruption.
MEMORY_CORRUPTION_CATEGORIES = frozenset(
    {
        "out_of_bound",
        "pool_corruption",
        "use_after_free",
        "integer_overflow",
        "stack_overflow",
        "control_flow",
        "format_string",
        "invalid_memory_access",
    }
)

#: Null-page threshold.  x64 canonical user space starts at 0x10000 in
#: practice; anything below is the null page.
_NULL_PAGE_LIMIT = 0x10000
_SENTINEL_VALUES = {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF, 0xDEADBEEF, 0xBAD0B0B0}

# Bugchecks that describe the machine/environment rather than a specific
# driver's memory handling.
_ENVIRONMENT_BUGCHECKS = {
    0x124: "WHEA_UNCORRECTABLE_ERROR - hardware-reported machine check",
    0x101: "CLOCK_WATCHDOG_TIMEOUT - a processor stopped responding",
    0x7A: "KERNEL_DATA_INPAGE_ERROR - storage or memory failure",
}

_EXCEPTION_BUGCHECKS = {0x1E, 0x3B, 0x7E, 0x8E}

# Modules shipped with Windows.  This is intentionally an explicit list
# plus a few unambiguous prefixes: treating every non-listed module as
# third-party is the safe default, and a false "third-party" label is
# better than blaming the target driver for someone else's code.
_OS_MODULES = frozenset(
    {
        "nt", "ntoskrnl", "ntkrnlmp", "ntkrnlpa", "ntkrpamp", "hal", "kd",
        "win32k", "win32kbase", "win32kfull", "win32kcore", "win32kbasefull",
        "dxgkrnl", "dxgmms1", "dxgmms2", "dxcore", "tcpip", "ndis", "ndiswan",
        "fltmgr", "storport", "classpnp", "volmgr", "volmgrx", "volsnap",
        "partmgr", "fvevol", "mountmgr", "ci", "cng", "ksecdd", "msrpc",
        "afd", "netio", "http", "srv", "srvnet", "rdbss", "mup", "npfs",
        "msfs", "fastfat", "ntfs", "usbport", "usbhub", "usbccgp", "usbehci",
        "usbxhci", "hidclass", "hidusb", "kbdclass", "mouclass", "acpi",
        "pci", "pcw", "wdf01000", "wdfldr", "wdfkd", "clfs", "watchdog",
        "spaceport", "stornvme", "storahci", "disk", "cdrom", "ks", "portcls",
        "wdmaud", "ksthunk", "beep", "rdpdr", "termdd", "vmbus", "hv",
        "hvservice", "msquic", "bam", "npcap", "pacer", "wfplwfs", "tcpip6",
        "netbt", "smb", "mrxsmb", "mrxsmb20", "srv2", "dfsc", "luafv",
        "bindflt", "wcifs", "cldflt", "iorate", "fileinfo", "wimmount",
        "ntfs3", "refs", "refsv1", "csc", "umbus", "umpass", "uefi",
        "bootvid", "vdrvroot", "pdc", "pdc.sys", "cng.sys", "dxgkrnl.sys",
    }
)
_OS_PREFIXES = (
    "nt",
    "hal",
    "win32k",
    "wdf",
    "dxg",
    "ndis",
    "tcpip",
    "fltmgr",
    "storport",
    "classpnp",
    "volmgr",
    "partmgr",
    "fvevol",
    "mountmgr",
    "ksecdd",
    "msrpc",
    "usbport",
    "usbhub",
    "usbccgp",
    "usbehci",
    "usbxhci",
    "hidclass",
    "hidusb",
    "kbdclass",
    "mouclass",
    "stornvme",
    "storahci",
    "spaceport",
    "vmbus",
    "clfs",
)


def is_os_module(module: str | None) -> bool:
    """True when the module name belongs to the Windows kernel/OS set."""
    if not module:
        return False
    name = module.strip().lower()
    if name.endswith(".sys"):
        name = name[:-4]
    if name in _OS_MODULES:
        return True
    return name.startswith(_OS_PREFIXES)


@dataclass(frozen=True)
class DefectClassification:
    """Result of classifying one crash analysis."""

    category: str
    attribution: str
    confidence: str
    #: Frame where the fault actually fired (e.g. ``nt!ExFreePoolWithTag``).
    faulting_frame: StackFrame | None
    faulting_module: str | None
    faulting_function: str
    #: Frame whose code owns the defect.  For an OS routine called with
    #: bad state by the target driver this is the target caller, which is
    #: the function a vendor would fix.
    responsible_frame: StackFrame | None
    #: Location of :attr:`responsible_frame` (``mydriver!Cleanup+0x4a``).
    instruction_region: str
    trigger_condition: str
    third_party_modules: tuple[str, ...] = ()
    #: Every stack frame that belongs to the target driver, in stack order.
    target_frames: tuple[StackFrame, ...] = ()
    reasons: tuple[str, ...] = ()
    unknown_fields: tuple[str, ...] = ()

    @property
    def faulting_location(self) -> str:
        return self.instruction_region or UNKNOWN

    @property
    def first_target_frame(self) -> StackFrame | None:
        """First frame inside the target driver, or ``None``."""
        return self.target_frames[0] if self.target_frames else None

    @property
    def root_cause_function(self) -> str:
        """``module!symbol`` without the offset, for the RootCause.function field."""
        frame = self.responsible_frame
        if frame is None:
            return self.instruction_region or UNKNOWN
        if frame.module and frame.symbol:
            return f"{frame.module}!{frame.symbol}"
        if frame.module:
            return frame.module
        return self.instruction_region or UNKNOWN


# ---------------------------------------------------------------------------
# Category
# ---------------------------------------------------------------------------


def _category_rank(value: str) -> int:
    return {"low": 0, "medium": 1, "high": 2}.get(value, 0)


def _lower_confidence(*values: str) -> str:
    return min(values, key=_category_rank, default="low")


def _faulting_address(analysis: WinDbgAnalysis) -> int | None:
    code = analysis.bugcheck_code
    args = analysis.bugcheck_arguments
    if code in (0xA, 0xD1):
        return args[0] if args[0] is not None else analysis.read_address
    if code == 0x50:
        return args[0] if args[0] is not None else (
            analysis.write_address if analysis.write_address is not None else analysis.read_address
        )
    if code == 0xFC:
        return analysis.execute_address
    if code in _EXCEPTION_BUGCHECKS:
        return args[1] if args[1] is not None else analysis.exception_address
    return None


def _operation(analysis: WinDbgAnalysis) -> str | None:
    """Read / write / execute, when the bugcheck arguments say so."""
    code = analysis.bugcheck_code
    args = analysis.bugcheck_arguments
    if code == 0xA:
        # Arg3 bit 0: 0 = read, 1 = write.
        if args[2] is not None:
            return "write" if (args[2] & 1) else "read"
    if code == 0x50:
        # Arg2: 0 = read, 1 = write.
        if args[1] is not None:
            return "write" if (args[1] & 1) else "read"
    if analysis.write_address is not None and analysis.read_address is None:
        return "write"
    if analysis.read_address is not None and analysis.write_address is None:
        return "read"
    return None


def _exception_category(code: int | None, address: int | None) -> tuple[str, str, list[str]]:
    if code is None:
        return "unknown", "low", ["exception bugcheck without an exception code"]
    if code == 0xC0000005:
        if address is not None and address < _NULL_PAGE_LIMIT:
            return "null_deref", "high", [
                f"access violation at 0x{address:X} (null page)"
            ]
        return "invalid_memory_access", "medium", [
            f"access violation at 0x{address:X}" if address is not None
            else "access violation with no faulting address recorded"
        ]
    if code == 0xC0000094:
        return "logic", "high", ["integer divide-by-zero exception (0xC0000094)"]
    if code == 0xC0000095:
        return "integer_overflow", "high", ["integer overflow exception (0xC0000095)"]
    if code == 0xC00000FD:
        return "stack_overflow", "high", ["stack overflow exception (0xC00000FD)"]
    if code == 0xC0000409:
        return "stack_overflow", "medium", [
            "STATUS_STACK_BUFFER_OVERRUN fast-fail (0xC0000409); "
            "a stack cookie or fail-fast check fired"
        ]
    if code == 0xC000001D:
        return "control_flow", "medium", ["illegal instruction exception (0xC000001D)"]
    if code == 0xC0000374:
        return "out_of_bound", "high", ["heap corruption detected (0xC0000374)"]
    if code == 0x80000003:
        return "logic", "medium", ["breakpoint / assertion (0x80000003)"]
    return "unknown", "low", [f"unmapped exception code 0x{code:X}"]


def _category_from_failure_bucket(
    analysis: WinDbgAnalysis,
) -> tuple[str, str, list[str]] | None:
    bucket = (analysis.failure_bucket_id or "").upper()
    if not bucket:
        return None
    if "STACK" in bucket and "OVERFLOW" in bucket:
        return "stack_overflow", "medium", [f"failure bucket {bucket} indicates stack overflow"]
    if "POOL" in bucket and ("CORRUPT" in bucket or "BAD" in bucket):
        return "pool_corruption", "medium", [f"failure bucket {bucket} indicates pool corruption"]
    if "MEMORY_CORRUPTION" in bucket:
        return "out_of_bound", "medium", [
            f"failure bucket {bucket} indicates memory corruption"
        ]
    if "GUARD" in bucket or "FAIL_FAST" in bucket or "CFG" in bucket:
        return "control_flow", "medium", [
            f"failure bucket {bucket} indicates a control-flow integrity check"
        ]
    if bucket.startswith("AV_") or "PAGE_FAULT" in bucket:
        return "invalid_memory_access", "low", [
            f"failure bucket {bucket} is an access-violation bucket"
        ]
    return None


def categorize(analysis: WinDbgAnalysis) -> tuple[str, str, list[str]]:
    """Map bugcheck + arguments + stack hints to a defect category.

    Returns ``(category, confidence, reasons)``.  ``unknown`` is a valid
    answer and is used whenever the dump does not establish a category.
    """
    code = analysis.bugcheck_code
    name = (analysis.bugcheck_name or "").upper()
    args = analysis.bugcheck_arguments

    if not analysis.has_bugcheck and not analysis.stack:
        return "unknown", "low", ["no bugcheck code/name and no stack in the analysis"]

    # A lock acquire/release validation failure is a synchronization
    # defect signal that is independent of the bugcheck family.  Driver
    # Verifier reports the bad lock state in these fields.
    if analysis.probably_invalid_acquire or analysis.probably_invalid_release:
        return "race", "medium", [
            "PROBABLY_INVALID_ACQUIRE/RELEASE recorded: the driver's lock "
            "acquisition/release ordering is invalid, which is a "
            "synchronization defect (deadlock / lock misuse), not memory "
            "corruption"
        ]

    # -- direct bugcheck families --------------------------------------
    if code == 0xA or code == 0xD1:
        address = _faulting_address(analysis)
        if address is None:
            return "invalid_memory_access", "low", [
                f"{name or 'IRQL bugcheck'} without a recorded referenced address"
            ]
        if address < _NULL_PAGE_LIMIT:
            return "null_deref", "high", [
                f"referenced address 0x{address:X} lies in the null page"
            ]
        if address in _SENTINEL_VALUES:
            return "invalid_memory_access", "medium", [
                f"referenced address 0x{address:X} is a sentinel/invalid pointer"
            ]
        return "invalid_memory_access", "medium", [
            f"referenced address 0x{address:X} is not a valid kernel address"
        ]

    if code == 0x50:
        address = _faulting_address(analysis)
        if address is None:
            return "invalid_memory_access", "low", [
                "PAGE_FAULT_IN_NONPAGED_AREA without a recorded address"
            ]
        if address < _NULL_PAGE_LIMIT:
            return "null_deref", "high", [
                f"nonpaged-pool access at 0x{address:X} (null page)"
            ]
        return "invalid_memory_access", "medium", [
            f"nonpaged-pool access at 0x{address:X}; the address is not mapped"
        ]

    if code == 0x19:
        return "pool_corruption", "high", [
            "BAD_POOL_HEADER: pool metadata was already corrupt when it was "
            "touched; the write that corrupted it happened earlier and is "
            "usually not on this stack"
        ]

    if code == 0xC2:
        subcode = args[0]
        if subcode == 0x07:
            return "use_after_free", "high", [
                "BAD_POOL_CALLER subcode 0x07: attempt to free pool that was already freed"
            ]
        if subcode == 0x06:
            return "invalid_memory_access", "medium", [
                "BAD_POOL_CALLER subcode 0x06: attempt to free an invalid pool address"
            ]
        return "unknown", "low", [
            "BAD_POOL_CALLER subcode "
            + (f"0x{subcode:X}" if subcode is not None else UNKNOWN)
            + " is not mapped to a defect category; inspect the pool state"
        ]

    if code == 0xC1:
        return "out_of_bound", "high", [
            "SPECIAL_POOL_DETECTED_MEMORY_CORRUPTION: a write outside the "
            "allocation was detected by special pool"
        ]
    if code == 0xC5:
        return "out_of_bound", "medium", [
            "DRIVER_CORRUPTED_EXPOOL: executive pool memory was corrupted"
        ]
    if code == 0xC6:
        return "use_after_free", "high", [
            "DRIVER_CAUGHT_MODIFYING_FREED_POOL: a driver wrote to freed pool memory"
        ]
    if code == 0x139:
        subcode = args[3]
        if subcode == 0x03:
            return "out_of_bound", "medium", [
                "KERNEL_SECURITY_CHECK_FAILURE subcode 0x03: LIST_ENTRY corruption "
                "(typically an overflow or use-after-free of a linked structure)"
            ]
        return "out_of_bound", "low", [
            "KERNEL_SECURITY_CHECK_FAILURE: a kernel structure integrity check "
            "failed; memory corruption is indicated but the exact defect is not "
            "established by the bugcheck alone"
        ]
    if code == 0xFC:
        return "control_flow", "high", [
            "ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY: execution reached a "
            "non-executable page (corrupted function pointer or return address)"
        ]
    if code == 0x7F:
        trap = args[0]
        if trap == 0x08:
            return "stack_overflow", "high", [
                "UNEXPECTED_KERNEL_MODE_TRAP trap 0x08: double fault, typically "
                "kernel stack exhaustion/overflow"
            ]
        return "invalid_memory_access", "low", [
            f"UNEXPECTED_KERNEL_MODE_TRAP trap {trap!r}; category not established"
        ]
    if code == 0x109:
        return "control_flow", "medium", [
            "CRITICAL_STRUCTURE_CORRUPTION: a critical kernel structure or code "
            "page was modified"
        ]
    if code in _EXCEPTION_BUGCHECKS:
        exception_code = args[0] if args[0] is not None else analysis.exception_code
        exception_address = args[1] if args[1] is not None else analysis.exception_address
        return _exception_category(exception_code, exception_address)

    if code in _ENVIRONMENT_BUGCHECKS:
        return "unknown", "medium", [_ENVIRONMENT_BUGCHECKS[code]]

    if code == 0x133:
        return "logic", "medium", [
            "DPC_WATCHDOG_VIOLATION: a DPC/ISR ran past its time budget; this is "
            "a hang/latency defect, not direct evidence of memory corruption"
        ]
    if code == 0x9F:
        return "logic", "medium", [
            "DRIVER_POWER_STATE_FAILURE: a driver failed a power transition"
        ]
    if code == 0x1A:
        return "out_of_bound", "low", [
            "MEMORY_MANAGEMENT: memory corruption or hardware failure; the dump "
            "does not distinguish them"
        ]
    if code == 0x4E:
        return "out_of_bound", "low", [
            "PFN_LIST_CORRUPT: page-frame metadata corruption; can be caused by a "
            "driver write or by failing hardware"
        ]
    if code == 0xEF:
        return "logic", "low", ["CRITICAL_PROCESS_DIED without a driver-specific cause"]

    # -- fall back to bucket hints, never to a guess -------------------
    bucket = _category_from_failure_bucket(analysis)
    if bucket is not None:
        category, confidence, reasons = bucket
        if analysis.bugcheck_code is not None or analysis.bugcheck_name:
            return category, confidence, reasons

    if analysis.bugcheck_code is not None or analysis.bugcheck_name is not None:
        label = analysis.bugcheck_label
        return "unknown", "low", [
            f"bugcheck {label} has no category mapping in this triage version"
        ]
    return "unknown", "low", ["no bugcheck code/name in the analysis"]


# ---------------------------------------------------------------------------
# Attribution
# ---------------------------------------------------------------------------


def _role(module: str | None, target_module: str | None) -> str:
    """'target' | 'os' | 'third_party' | 'unknown' for one module name."""
    if not module:
        return "unknown"
    name = module.lower()
    if name.endswith(".sys"):
        name = name[:-4]
    target = (target_module or "").lower()
    if target.endswith(".sys"):
        target = target[:-4]
    if target and name == target:
        return "target"
    if is_os_module(name):
        return "os"
    return "third_party"


def _collect_third_party(
    analysis: WinDbgAnalysis, target_module: str | None
) -> tuple[str, ...]:
    seen: list[str] = []
    for frame in analysis.stack:
        module = frame.module
        if not module:
            continue
        if _role(module, target_module) != "third_party":
            continue
        if module not in seen:
            seen.append(module)
    return tuple(seen)


def _attribute(
    analysis: WinDbgAnalysis, target_module: str | None
) -> tuple[str, str, list[str]]:
    """Return ``(attribution, confidence, reasons)``."""
    fault = analysis.faulting_frame
    third_party = _collect_third_party(analysis, target_module)
    environment = (
        analysis.bugcheck_code in _ENVIRONMENT_BUGCHECKS
        or "WHEA" in (analysis.bugcheck_name or "").upper()
        or "CLOCK_WATCHDOG" in (analysis.bugcheck_name or "").upper()
    )

    if target_module is None:
        if environment:
            return "environment", "medium", [
                "no target module was supplied; the bugcheck is hardware/environment class"
            ]
        return "unknown", "low", [
            "no target module was supplied, so ownership cannot be established"
        ]

    if fault is None:
        if environment:
            return "environment", "medium", [
                "no faulting frame; the bugcheck is hardware/environment class"
            ]
        if not analysis.stack:
            return "unknown", "low", [
                "no STACK_TEXT in the analysis; the faulting component is unknown"
            ]
        return "unknown", "low", [
            "the first non-machinery stack frame could not be resolved to a module; "
            "attribution would be a guess"
        ]

    role = _role(fault.module, target_module)
    fault_label = fault.location

    if role == "target":
        return "target_driver", "high", [
            f"faulting frame {fault_label} belongs to the target driver"
        ]

    if role == "third_party":
        reasons = [
            f"faulting frame {fault_label} belongs to third-party module "
            f"{fault.module}, not the target driver"
        ]
        target_frames = [f.location for f in analysis.stack if _role(f.module, target_module) == "target"]
        if target_frames:
            reasons.append(
                "target driver appears lower in the call chain at "
                + ", ".join(target_frames[:3])
                + "; that makes the target a caller, not the faulting component"
            )
        return "third_party_driver", "high", reasons

    if role == "os":
        # The fault is in an OS routine.  The nearest non-OS caller owns
        # the arguments.  An unresolved frame in between stops the walk:
        # the caller is then unknowable.
        for frame in analysis.stack[fault.index + 1:]:
            caller_role = _role(frame.module, target_module)
            if caller_role == "target":
                return "target_driver", "medium", [
                    f"faulting frame {fault_label} is an OS routine; the nearest "
                    f"non-OS caller {frame.location} is the target driver, so the "
                    "target supplied the state that the OS routine rejected"
                ]
            if caller_role == "third_party":
                return "third_party_driver", "medium", [
                    f"faulting frame {fault_label} is an OS routine; the nearest "
                    f"non-OS caller {frame.location} is third-party module "
                    f"{frame.module}, not the target driver"
                ]
            if caller_role == "unknown":
                return "unknown", "low", [
                    f"faulting frame {fault_label} is an OS routine; the caller "
                    "chain is unresolved, so ownership cannot be established"
                ]
        if environment:
            return "environment", "medium", [
                f"faulting frame {fault_label} is an OS routine and no target or "
                "third-party caller is visible; the bugcheck is hardware/environment class"
            ]
        return "os_component", "medium", [
            f"faulting frame {fault_label} is an OS routine with no target-driver "
            "or third-party caller visible in the stack"
        ]

    return "unknown", "low", [
        f"faulting frame {fault_label} has no resolvable module"
    ]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def _responsible_frame(
    analysis: WinDbgAnalysis,
    attribution: str,
    target_module: str | None,
) -> StackFrame | None:
    """Frame whose code owns the defect, given the attribution.

    When the fault fired inside an OS routine but the nearest non-OS
    caller is the target driver, the target caller is responsible: the
    OS routine rejected state the driver supplied.  Every other
    attribution keeps the actual faulting frame.
    """
    fault = analysis.faulting_frame
    if fault is None:
        return None
    if attribution != "target_driver":
        return fault
    if _role(fault.module, target_module) != "os":
        return fault
    for frame in analysis.stack[fault.index + 1:]:
        caller_role = _role(frame.module, target_module)
        if caller_role == "target":
            return frame
        if caller_role == "unknown":
            return fault
    return fault


def _trigger_condition(
    analysis: WinDbgAnalysis,
    category: str,
    attribution: str,
    responsible: StackFrame | None = None,
) -> str:
    if (
        not analysis.has_bugcheck
        and not analysis.stack
        and not analysis.failure_bucket_id
    ):
        return (
            "unknown (no parsable WinDbg !analyze -v output was available for "
            "this crash)"
        )

    parts: list[str] = []
    if analysis.has_bugcheck:
        parts.append(analysis.bugcheck_label)
    fault = analysis.faulting_frame
    if fault is not None:
        parts.append(f"faulting instruction {fault.location}")
    if responsible is not None and fault is not None and responsible.index != fault.index:
        parts.append(f"responsible frame {responsible.location}")

    address = _faulting_address(analysis)
    operation = _operation(analysis)
    if address is not None:
        parts.append(f"{operation or 'access'} of 0x{address:X}")

    if analysis.bugcheck_code in (0xA, 0xD1):
        irql = analysis.bugcheck_arguments[1]
        if irql is not None:
            parts.append(f"IRQL {irql}")

    parts.append(f"category {category}")
    if attribution == "third_party_driver":
        parts.append("faulting component is a third-party module, not the target")
    elif attribution == "os_component":
        parts.append("faulting component is an OS routine")
    elif attribution == "environment":
        parts.append("environment/hardware-class failure")
    elif attribution == "unknown":
        parts.append("defect ownership not established")

    return "; ".join(parts)


def classify_defect(
    analysis: WinDbgAnalysis,
    *,
    target_module: str | None = None,
) -> DefectClassification:
    """Classify one parsed analysis.

    ``target_module`` is the driver under research (filename without
    ``.sys``, case-insensitive).  Without it, attribution is ``unknown``
    except for hardware-class bugchecks: claiming ownership without a
    target would be a fabrication.
    """
    category, category_confidence, category_reasons = categorize(analysis)
    attribution, attribution_confidence, attribution_reasons = _attribute(
        analysis, target_module
    )

    fault = analysis.faulting_frame
    responsible = _responsible_frame(analysis, attribution, target_module)
    faulting_module = fault.module if fault is not None else None
    faulting_function = fault.location if fault is not None else UNKNOWN
    instruction_region = responsible.qualified if responsible is not None else None
    if instruction_region is None:
        instruction_region = UNKNOWN

    target_frames = tuple(
        frame
        for frame in analysis.stack
        if _role(frame.module, target_module) == "target"
    )

    reasons = list(category_reasons + attribution_reasons)
    if (
        responsible is not None
        and fault is not None
        and responsible.index != fault.index
    ):
        reasons.append(
            f"root cause location {responsible.location} is the target caller of "
            f"the faulting OS routine {fault.location}"
        )
    if target_frames and (
        responsible is None or target_frames[0].index != responsible.index
    ):
        reasons.append(
            "first target-driver frame in the stack: "
            + target_frames[0].location
        )

    return DefectClassification(
        category=category,
        attribution=attribution,
        confidence=_lower_confidence(category_confidence, attribution_confidence),
        faulting_frame=fault,
        faulting_module=faulting_module,
        faulting_function=faulting_function,
        responsible_frame=responsible,
        instruction_region=instruction_region,
        trigger_condition=_trigger_condition(
            analysis, category, attribution, responsible
        ),
        third_party_modules=_collect_third_party(analysis, target_module),
        target_frames=target_frames,
        reasons=tuple(reasons),
        unknown_fields=analysis.missing_fields,
    )


def crash_classification(classification: DefectClassification) -> str:
    """Map a defect classification onto ``Crash.classification``.

    Third-party / environment ownership overrides the category so a
    consumer that only reads ``Crash.classification`` cannot mistake a
    third-party fault for a target-driver defect.
    """
    if classification.attribution == "third_party_driver":
        return "third_party"
    if classification.attribution == "os_component":
        return "os_component"
    if classification.attribution == "environment":
        return "env_anomaly"
    if classification.attribution == "unknown":
        return "unknown"

    category = classification.category
    if category in {
        "null_deref",
        "use_after_free",
        "out_of_bound",
        "pool_corruption",
        "race",
        "input_validation",
        "integer_overflow",
        "stack_overflow",
        "control_flow",
        "invalid_memory_access",
        "uninit_memory",
        "logic",
    }:
        return category
    return "unknown"


def target_module_from_path(path: str | None) -> str | None:
    """Driver module name from a target path (``...\\mydriver.sys`` -> ``mydriver``)."""
    if not path:
        return None
    name = re.split(r"[\\/]", str(path))[-1].strip()
    if not name:
        return None
    if name.lower().endswith(".sys"):
        name = name[:-4]
    return name or None
