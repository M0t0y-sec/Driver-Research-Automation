"""Crash triage tests.

The samples are hand-written but follow the real ``!analyze -v`` output
shape: the ``NAME (code)`` header, ``Arguments:`` block, ``BUGCHECK_Pn``
key/values, ``PROCESS_NAME`` / ``MODULE_NAME`` / ``IMAGE_NAME``,
``STACK_TEXT`` frames with module+offset+source annotation, ``CONTEXT``
register dumps, and a ``FAILURE_BUCKET_ID``.

What these tests protect:

* field extraction from real-format text (including WinDbg's backtick
  address separator and inline ``WARNING:`` lines);
* correct classification of the four common crash families;
* third-party faults are never attributed to the target driver;
* missing fields are surfaced as ``unknown``/missing, never fabricated;
* the four graph nodes write Crash, RootCause, SecurityImpact,
  ExploitabilityAssessment and Evidence records.
"""

import asyncio
import shutil

import pytest

from dra.agents._ops import build_ops
from dra.agents.triage import (
    exploitability_node,
    impact_node,
    root_cause_node,
    triage_node,
)
from dra.agents.validation import validation_node
from dra.config import SETTINGS
from dra.evidence.strength import evidence_proves_defect, is_real_location
from dra.models.common import EvidenceStrength, IDPrefix, new_id
from dra.models.crash import Crash
from dra.models.hypothesis import Hypothesis
from dra.storage.filesystem import HypothesisStore
from dra.triage import (
    assess_controllability,
    assess_exploitability,
    assess_impact,
    classify_defect,
    crash_classification,
    parse_windbg_analysis,
)
from dra.triage.windbg import CORE_FIELDS


@pytest.fixture
def fresh_env(tmp_path):
    SETTINGS.__dict__["data_dir"] = tmp_path / "data"
    SETTINGS.__dict__["artifacts_dir"] = tmp_path / "artefacts"
    SETTINGS.__dict__["audit_log_path"] = tmp_path / "audit.log.jsonl"
    SETTINGS.data_dir.mkdir(parents=True, exist_ok=True)
    SETTINGS.artifacts_dir.mkdir(parents=True, exist_ok=True)
    yield tmp_path
    shutil.rmtree(tmp_path, ignore_errors=True)


# ---------------------------------------------------------------------------
# Real-format samples
# ---------------------------------------------------------------------------

ANALYZE_A_NULL_DEREF = r"""
*******************************************************************************
*                                                                             *
*                        Bugcheck Analysis                                    *
*                                                                             *
*******************************************************************************

IRQL_NOT_LESS_OR_EQUAL (a)
An attempt was made to access a pageable (or completely invalid) address at an
interrupt request level (IRQL) that is too high.  This is usually
caused by drivers using improper addresses.
If a kernel debugger is available get the stack backtrace.
Arguments:
Arg1: 0000000000000000, memory referenced
Arg2: 0000000000000002, IRQL
Arg3: 0000000000000000, bitfield :
	bit 0 : value 0 = read operation, 1 = write operation
	bit 3 : value 0 = not an execute operation, 1 = execute operation (only on chips which support this level of status)
Arg4: fffff805`12345678, address which referenced memory

Debugging Details:
------------------

KEY_VALUES_STRING: 1

    Key  : Analysis.CPU.mSec
    Value: 1234

BUGCHECK_CODE:  a

BUGCHECK_P1: 0

BUGCHECK_P2: 2

BUGCHECK_P3: 0

BUGCHECK_P4: fffff80512345678

FAULTING_THREAD:  ffffe00012345678

PROCESS_NAME:  poc.exe

READ_ADDRESS:  0000000000000000

CUSTOMER_CRASH_COUNT:  1

DEFAULT_BUCKET_ID:  AV_0_mydriver!Func

CONTEXT:  fffff80512345678 -- (.cxr 0xfffff80512345678)
rax=0000000000000000 rbx=0000000000000001 rcx=0000000000000000
rdx=0000000000000000 rsi=fffff80512345678 rdi=0000000000000000
rip=fffff80512345678 rsp=fffff80511111111 rbp=fffff80511111112
 r8=0000000000000000  r9=0000000000000000 r10=0000000000000000
r11=0000000000000000 r12=0000000000000000 r13=0000000000000000
r14=0000000000000000 r15=0000000000000000
iopl=0         nv up ei pl zr na po nc
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246

STACK_TEXT:
fffff805`11111111 fffff805`22222222 nt!KeBugCheckEx
fffff805`11111112 fffff805`22222223 nt!KiBugCheckDispatch+0x69
fffff805`11111113 fffff805`22222224 nt!KiPageFault+0x46b
WARNING: Frame IP not in any known module. Following frames may be wrong.
fffff805`11111114 fffff805`22222225 mydriver!Func+0x1a [c:\src\mydriver\func.c @ 42]
fffff805`11111115 fffff805`22222226 nt!IofCallDriver+0x1d
fffff805`11111116 fffff805`22222227 mydriver!Dispatch+0x55

SYMBOL_NAME:  mydriver!Func+1a

MODULE_NAME: mydriver

IMAGE_NAME:  mydriver.sys

FAULTING_MODULE: fffff80512345678 mydriver

IMAGE_VERSION:  1.0.0.0

STACK_COMMAND:  .cxr; .ecxr ; kb

FAILURE_BUCKET_ID:  AV_0_mydriver!Func

OS_VERSION:  10.0.19041.1

BUILDLAB_STR:  vb_release

OSPLATFORM_TYPE:  x64

OSNAME:  Windows 10

Followup:     MachineOwner
---------
"""

ANALYZE_19_POOL_HEADER = r"""
BAD_POOL_HEADER (19)
The pool is already corrupt at the time of the current request.
This may or may not be due to the caller.
Arguments:
Arg1: 0000000000000020, The pool entry we were looking for within the page.
Arg2: fffff80512345678, The next pool entry.
Arg3: fffff80512345679
Arg4: fffff8051234567a

BUGCHECK_CODE:  19

BUGCHECK_P1: 20

BUGCHECK_P2: fffff80512345678

BUGCHECK_P3: fffff80512345679

BUGCHECK_P4: fffff8051234567a

PROCESS_NAME:  poc.exe

POOL_ADDRESS: fffff80512345678

STACK_TEXT:
fffff805`11111111 fffff805`22222222 nt!KeBugCheckEx
fffff805`11111112 fffff805`22222223 nt!ExFreePoolWithTag+0x123
fffff805`11111113 fffff805`22222224 mydriver!Cleanup+0x4a [c:\src\mydriver\cleanup.c @ 88]
fffff805`11111114 fffff805`22222225 nt!IofCallDriver+0x1d
fffff805`11111115 fffff805`22222226 mydriver!DispatchIoctl+0x77

SYMBOL_NAME:  nt!ExFreePoolWithTag+123

MODULE_NAME:  nt

IMAGE_NAME:  ntkrnlmp.exe

FAILURE_BUCKET_ID:  BAD_POOL_HEADER_mydriver!Cleanup
"""

ANALYZE_C2_BAD_POOL_CALLER = r"""
BAD_POOL_CALLER (c2)
A kernel-mode program must not make a request to the memory manager
that is invalid for the current IRQL level or for the current state.
Arguments:
Arg1: 0000000000000007, Attempt to free pool which was already freed
Arg2: 0000000000000010, Pool tag value
Arg3: fffff80512345678, Memory contents of the pool block
Arg4: fffff8051234567a, Address of the block of pool being freed

BUGCHECK_CODE:  c2

BUGCHECK_P1: 7

BUGCHECK_P2: 10

BUGCHECK_P3: fffff80512345678

BUGCHECK_P4: fffff8051234567a

PROCESS_NAME:  poc.exe

STACK_TEXT:
fffff805`11111111 fffff805`22222222 nt!KeBugCheckEx
fffff805`11111112 fffff805`22222223 nt!ExFreePoolWithTag+0x123
fffff805`11111113 fffff805`22222224 mydriver!Cleanup+0x4a
fffff805`11111114 fffff805`22222225 nt!IofCallDriver+0x1d

SYMBOL_NAME:  nt!ExFreePoolWithTag+123

MODULE_NAME:  nt

IMAGE_NAME:  ntkrnlmp.exe

FAILURE_BUCKET_ID:  0xC2_mydriver!Cleanup
"""

ANALYZE_50_CONTROLLED_WRITE = r"""
PAGE_FAULT_IN_NONPAGED_AREA (50)
Invalid system memory was referenced.  This cannot be protected by try-except.
Typically the address is just plain bad or it is pointing at freed memory.
Arguments:
Arg1: 4141414141414141, memory referenced.
Arg2: 0000000000000001, value 0 = read operation, 1 = write operation.
Arg3: fffff805`12345678, If non-zero, the instruction address which referenced the bad memory
	address.
Arg4: 0000000000000002, (reserved)

BUGCHECK_CODE:  50

BUGCHECK_P1: 4141414141414141

BUGCHECK_P2: 1

BUGCHECK_P3: fffff80512345678

BUGCHECK_P4: 2

PROCESS_NAME:  poc.exe

READ_ADDRESS:  0000000000000000

WRITE_ADDRESS:  4141414141414141

CONTEXT:  fffff80512345678 -- (.cxr 0xfffff80512345678)
rax=4141414141414141 rbx=0000000000000000 rcx=4141414141414141
rdx=0000000000000010 rsi=fffff80512345678 rdi=fffff80512345679
rip=fffff80512345678 rsp=fffff80511111111 rbp=fffff80511111112
r11=0000000000000000 r12=0000000000000000 r13=0000000000000000
iopl=0         nv up ei pl zr na po nc
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246

STACK_TEXT:
fffff805`11111111 fffff805`22222222 nt!KeBugCheckEx
fffff805`11111112 fffff805`22222223 nt!KiPageFault+0x46b
fffff805`11111113 fffff805`22222224 mydriver!CopyData+0x33 [c:\src\mydriver\copy.c @ 17]
fffff805`11111114 fffff805`22222225 mydriver!DispatchIoctl+0x77

SYMBOL_NAME:  mydriver!CopyData+33

MODULE_NAME: mydriver

IMAGE_NAME:  mydriver.sys

FAILURE_BUCKET_ID:  AV_4141414141414141_mydriver!CopyData
"""

ANALYZE_50_THIRD_PARTY = r"""
PAGE_FAULT_IN_NONPAGED_AREA (50)
Invalid system memory was referenced.  This cannot be protected by try-except.
Arguments:
Arg1: 0000000000000000, memory referenced.
Arg2: 0000000000000000, value 0 = read operation, 1 = write operation.
Arg3: fffff805`12345678, If non-zero, the instruction address which referenced the bad memory
	address.
Arg4: 0000000000000002, (reserved)

BUGCHECK_CODE:  50

BUGCHECK_P1: 0

BUGCHECK_P2: 0

BUGCHECK_P3: fffff80512345678

BUGCHECK_P4: 2

PROCESS_NAME:  poc.exe

STACK_TEXT:
fffff805`11111111 fffff805`22222222 nt!KeBugCheckEx
fffff805`11111112 fffff805`22222223 nt!KiPageFault+0x46b
fffff805`11111113 fffff805`22222224 otherdrv!BadWrite+0x42
fffff805`11111114 fffff805`22222225 mydriver!DispatchIoctl+0x77
fffff805`11111115 fffff805`22222226 nt!IofCallDriver+0x1d

SYMBOL_NAME:  otherdrv!BadWrite+42

MODULE_NAME: otherdrv

IMAGE_NAME:  otherdrv.sys

FAILURE_BUCKET_ID:  AV_0_otherdrv!BadWrite
"""

ANALYZE_C4_VERIFIER = r"""
DRIVER_VERIFIER_DETECTED_VIOLATION (c4)
A device driver has been detected doing something illegal.
Arguments:
Arg1: 00000000000000e2, A driver has not checked the return value of a memory allocation.
Arg2: fffff80512345678
Arg3: fffff80512345679
Arg4: fffff8051234567a

BUGCHECK_CODE:  c4

BUGCHECK_P1: e2

BUGCHECK_P2: fffff80512345678

BUGCHECK_P3: fffff80512345679

BUGCHECK_P4: fffff8051234567a

PROCESS_NAME:  poc.exe

HVCI: enabled

PROBABLY_INVALID_ACQUIRE: fffff80512345678

PROBABLY_INVALID_RELEASE: fffff80512345679

STACK_TEXT:
fffff805`11111111 fffff805`22222222 nt!KeBugCheckEx
fffff805`11111112 fffff805`22222223 nt!VerifierBugCheckIfAppropriate+0x42
fffff805`11111113 fffff805`22222224 mydriver!Func+0x10

SYMBOL_NAME:  mydriver!Func+10

MODULE_NAME: mydriver

IMAGE_NAME:  mydriver.sys

FAILURE_BUCKET_ID:  0xC4_mydriver!Func
"""

ANALYZE_3B_INTEGER_OVERFLOW = r"""
SYSTEM_SERVICE_EXCEPTION (3b)
An exception occurred while executing a system service.
Arguments:
Arg1: 00000000c0000095, The exception code that was not handled
Arg2: 0000000000000000, The address that the exception occurred at
Arg3: fffff80512345678, Exception record address
Arg4: fffff80512345679, Context record address

BUGCHECK_CODE:  3b

BUGCHECK_P1: c0000095

BUGCHECK_P2: 0

BUGCHECK_P3: fffff80512345678

BUGCHECK_P4: fffff80512345679

PROCESS_NAME:  poc.exe

STACK_TEXT:
fffff805`11111111 fffff805`22222222 nt!KeBugCheckEx
fffff805`11111112 fffff805`22222223 nt!KiExceptionDispatch+0x42
fffff805`11111113 fffff805`22222224 mydriver!ScaleLength+0x10
fffff805`11111114 fffff805`22222225 mydriver!DispatchIoctl+0x77

SYMBOL_NAME:  mydriver!ScaleLength+10

MODULE_NAME: mydriver

IMAGE_NAME:  mydriver.sys

FAILURE_BUCKET_ID:  0x3B_c0000095_mydriver!ScaleLength
"""

ANALYZE_ONLY_BUGCHECK = r"""
BAD_POOL_HEADER (19)
The pool is already corrupt at the time of the current request.
BUGCHECK_CODE:  19
BUGCHECK_P1: 20
PROCESS_NAME:  System
"""

ANALYZE_GARBAGE = "No debug information available for this dump.\n"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _crash(
    *,
    project_id: str = "PRJ-1",
    research_id: str | None = "RES-1",
    text: str | None = None,
    analysis_ref: str | None = None,
    hypothesis_id: str | None = None,
    **kwargs,
) -> Crash:
    return Crash(
        id=new_id(IDPrefix.CRASH),
        project_id=project_id,
        execution_id="EXE-1",
        research_id=research_id,
        hypothesis_id=hypothesis_id,
        analysis_text=text,
        analysis_ref=analysis_ref,
        summary="recorded crash",
        **kwargs,
    )


def _hypothesis(*, actor: str = "unprivileged_local_user") -> Hypothesis:
    return Hypothesis(
        id=new_id(IDPrefix.HYPOTHESIS),
        project_id="PRJ-1",
        target_id="TGT-1",
        category="memory_safety",
        description="IOCTL handler copies a user-controlled buffer without a bounds check",
        falsification="sending a buffer larger than the pool allocation must not corrupt the pool",
        related_attack_actor=actor,  # type: ignore[arg-type]
    )


def _state(crash_ids: list[str], *, hypothesis_ids: list[str] | None = None) -> dict:
    return {
        "project_id": "PRJ-1",
        "research_id": "RES-1",
        "target_id": "TGT-1",
        "target_path": r"C:\drivers\mydriver.sys",
        "crash_ids": list(crash_ids),
        "hypothesis_ids": list(hypothesis_ids or []),
        "selected_hypothesis_ids": list(hypothesis_ids or []),
        "evidence_ids": [],
        "root_cause_ids": [],
        "impact_ids": [],
        "exploitability_ids": [],
        "crash_analysis_notes": [],
    }


def _run_nodes(ops, state: dict) -> dict:
    for node in (triage_node, root_cause_node, impact_node, exploitability_node):
        update = asyncio.run(node(state, ops))
        state.update(update)
    return state


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def test_parse_irql_not_less_or_equal_extracts_fields_and_frames():
    parsed = parse_windbg_analysis(ANALYZE_A_NULL_DEREF)

    assert parsed.bugcheck_code == 0xA
    assert parsed.bugcheck_name == "IRQL_NOT_LESS_OR_EQUAL"
    assert parsed.bugcheck_arguments == (0, 2, 0, 0xFFFFF80512345678)
    assert parsed.process_name == "poc.exe"
    assert parsed.module_name == "mydriver"
    assert parsed.image_name == "mydriver.sys"
    assert parsed.faulting_module == "mydriver"
    assert parsed.symbol_name == "mydriver!Func+1a"
    assert parsed.failure_bucket_id == "AV_0_mydriver!Func"

    # Stack: backtick-separated addresses are normalised, the WARNING line
    # is kept out of the frames, and the source annotation is preserved.
    assert len(parsed.stack) == 6
    assert parsed.stack[3].module == "mydriver"
    assert parsed.stack[3].symbol == "Func"
    assert parsed.stack[3].offset == 0x1A
    assert parsed.stack[3].source_line == 42
    assert parsed.stack[3].source_file.lower().endswith("func.c")
    assert parsed.stack[3].location == "mydriver!Func+0x1a"

    # The first non-bugcheck-machinery frame is the fault site.
    assert parsed.faulting_frame is not None
    assert parsed.faulting_frame.location == "mydriver!Func+0x1a"
    assert parsed.registers["rcx"] == 0
    assert parsed.registers["rip"] == 0xFFFFF80512345678
    assert any("Frame IP not in any known module" in w for w in parsed.parse_warnings)

    # Present fields are not reported missing.
    assert "bugcheck_code" not in parsed.missing_fields
    assert "bugcheck_name" not in parsed.missing_fields
    assert "stack_text" not in parsed.missing_fields
    assert "registers" not in parsed.missing_fields


def test_missing_fields_are_explicit_unknown_not_fabricated():
    parsed = parse_windbg_analysis(ANALYZE_GARBAGE)
    assert parsed.bugcheck_code is None
    assert parsed.bugcheck_name is None
    assert parsed.bugcheck_arguments == (None, None, None, None)
    assert parsed.stack == ()
    assert parsed.faulting_frame is None
    for field in CORE_FIELDS:
        assert field in parsed.missing_fields

    classification = classify_defect(parsed, target_module="mydriver")
    assert classification.category == "unknown"
    assert classification.attribution == "unknown"
    assert classification.faulting_function == "unknown"
    assert classification.instruction_region == "unknown"
    assert classification.confidence == "low"
    assert classification.trigger_condition.startswith("unknown")


def test_explicit_unknown_placeholders_are_not_treated_as_module_names():
    text = r"""
BUGCHECK_CODE:  50
BUGCHECK_P1: 0
PROCESS_NAME:  <unknown>
MODULE_NAME: <unknown>
IMAGE_NAME:  <unknown>
FAULTING_MODULE: <unknown>
STACK_TEXT:
fffff805`11111111 fffff805`22222222 nt!KeBugCheckEx
fffff805`11111112 fffff805`22222223 nt!KiPageFault+0x46b
fffff805`11111113 fffff805`22222224 0xfffff805`33333333
"""
    parsed = parse_windbg_analysis(text)
    assert parsed.process_name is None
    assert parsed.module_name is None
    assert parsed.image_name is None
    assert parsed.faulting_module is None
    assert "module_name" in parsed.missing_fields
    assert "image_name" in parsed.missing_fields

    classification = classify_defect(parsed, target_module="mydriver")
    # "<unknown>" must never become a third-party module name.
    assert classification.attribution == "unknown"
    assert classification.third_party_modules == ()


def test_unresolved_frame_above_faulting_frame_is_not_guessed():
    text = r"""
BUGCHECK_CODE:  50
BUGCHECK_P1: 0
BUGCHECK_P2: 0
STACK_TEXT:
fffff805`11111111 fffff805`22222222 nt!KeBugCheckEx
fffff805`11111112 fffff805`22222223 nt!KiPageFault+0x46b
fffff805`11111113 fffff805`22222224 0xfffff805`33333333
fffff805`11111114 fffff805`22222225 mydriver!Func+0x1a
"""
    parsed = parse_windbg_analysis(text)
    # The unresolved frame precedes any known non-machinery frame, so the
    # crash site is genuinely unknown; returning mydriver!Func would be a
    # misattribution.
    assert parsed.faulting_frame is None
    classification = classify_defect(parsed, target_module="mydriver")
    assert classification.attribution == "unknown"
    assert classification.instruction_region == "unknown"


# ---------------------------------------------------------------------------
# Classification: four typical families
# ---------------------------------------------------------------------------


def test_0a_null_deref_is_classified_and_attributed_to_target():
    parsed = parse_windbg_analysis(ANALYZE_A_NULL_DEREF)
    classification = classify_defect(parsed, target_module="mydriver")

    assert classification.category == "null_deref"
    assert classification.attribution == "target_driver"
    assert classification.confidence == "high"
    assert classification.faulting_function == "mydriver!Func+0x1a"
    assert classification.instruction_region == "mydriver!Func+0x1a"
    assert classification.root_cause_function == "mydriver!Func"
    assert "read of 0x0" in classification.trigger_condition
    assert "IRQL 2" in classification.trigger_condition
    assert crash_classification(classification) == "null_deref"


def test_0x19_pool_corruption_points_root_cause_at_target_caller():
    parsed = parse_windbg_analysis(ANALYZE_19_POOL_HEADER)
    classification = classify_defect(parsed, target_module="mydriver")

    assert classification.category == "pool_corruption"
    assert classification.attribution == "target_driver"
    assert classification.confidence == "medium"
    # The fault fired in an OS free routine; the vendor-relevant function
    # is the target driver that supplied the corrupted block.
    assert classification.faulting_function == "nt!ExFreePoolWithTag+0x123"
    assert classification.instruction_region == "mydriver!Cleanup+0x4a"
    assert classification.root_cause_function == "mydriver!Cleanup"
    assert classification.first_target_frame is not None
    assert classification.first_target_frame.location == "mydriver!Cleanup+0x4a"
    assert "responsible frame mydriver!Cleanup+0x4a" in classification.trigger_condition
    assert any("already corrupt" in reason for reason in classification.reasons)
    assert crash_classification(classification) == "pool_corruption"


def test_0xc2_double_free_is_use_after_free():
    parsed = parse_windbg_analysis(ANALYZE_C2_BAD_POOL_CALLER)
    classification = classify_defect(parsed, target_module="mydriver")

    assert classification.category == "use_after_free"
    assert classification.attribution == "target_driver"
    assert classification.instruction_region == "mydriver!Cleanup+0x4a"
    assert any("already freed" in reason for reason in classification.reasons)
    assert crash_classification(classification) == "use_after_free"


def test_0x50_controlled_write_is_full_controllability():
    parsed = parse_windbg_analysis(ANALYZE_50_CONTROLLED_WRITE)
    classification = classify_defect(parsed, target_module="mydriver")
    poc_values = [0x4141414141414141]

    assert classification.category == "invalid_memory_access"
    assert classification.attribution == "target_driver"
    assert classification.instruction_region == "mydriver!CopyData+0x33"

    control = assess_controllability(parsed, poc_values=poc_values)
    assert control.controllability == "full"
    assert control.address_controlled is True
    assert control.write_address_controlled is True
    assert control.value_controlled is True
    assert "0x4141414141414141" in control.controlled_values
    assert any("WRITE_ADDRESS" in match for match in control.matches)

    exploitability = assess_exploitability(
        parsed,
        classification,
        reproducibility="always",
        poc_values=poc_values,
    )
    assert exploitability.level == "demonstrated"
    assert exploitability.reliability == "reliable"
    assert "0x4141414141414141" in exploitability.controlled_values
    assert "Defensive assessment only" in exploitability.notes
    # No weaponized exploit material is produced.
    assert "weaponized" not in exploitability.notes.lower()


def test_0x50_no_poc_values_yields_unknown_controllability():
    parsed = parse_windbg_analysis(ANALYZE_50_CONTROLLED_WRITE)
    classification = classify_defect(parsed, target_module="mydriver")
    control = assess_controllability(parsed, poc_values=[])
    assert control.controllability == "unknown"
    assert control.poc_values_supplied is False

    exploitability = assess_exploitability(parsed, classification, poc_values=[])
    assert exploitability.level == "plausible"  # memory-corruption class
    assert exploitability.controllability == "unknown"
    assert any("PoC input values" in item for item in exploitability.constraints)


# ---------------------------------------------------------------------------
# Third-party / environment ownership
# ---------------------------------------------------------------------------


def test_third_party_fault_is_not_attributed_to_target_driver():
    parsed = parse_windbg_analysis(ANALYZE_50_THIRD_PARTY)
    classification = classify_defect(parsed, target_module="mydriver")

    assert classification.attribution == "third_party_driver"
    assert classification.faulting_function == "otherdrv!BadWrite+0x42"
    assert classification.instruction_region == "otherdrv!BadWrite+0x42"
    assert "otherdrv" in classification.third_party_modules
    assert classification.first_target_frame is not None
    assert classification.first_target_frame.location == "mydriver!DispatchIoctl+0x77"
    assert crash_classification(classification) == "third_party"
    # The target appears in the call chain, but that must not make it the
    # owner of the fault.
    assert any("caller, not the faulting component" in r for r in classification.reasons)

    exploitability = assess_exploitability(parsed, classification, reproducibility="always")
    assert exploitability.level == "theoretical"
    assert any("third-party module" in c for c in exploitability.constraints)

    impact = assess_impact(classification, exploitability, hypothesis=_hypothesis())
    assert impact.impact_type == "third_party_component_failure"
    assert impact.privilege_boundary_crossed is False
    assert impact.confidentiality == "none"
    assert impact.integrity == "none"
    assert impact.availability == "high"


def test_lock_validation_failure_is_classified_as_race():
    parsed = parse_windbg_analysis(ANALYZE_C4_VERIFIER)
    classification = classify_defect(parsed, target_module="mydriver")

    assert classification.category == "race"
    assert classification.attribution == "target_driver"
    assert classification.instruction_region == "mydriver!Func+0x10"
    assert any("synchronization defect" in reason for reason in classification.reasons)


def test_exception_bugcheck_maps_integer_overflow():
    parsed = parse_windbg_analysis(ANALYZE_3B_INTEGER_OVERFLOW)
    classification = classify_defect(parsed, target_module="mydriver")

    assert parsed.bugcheck_arguments[0] == 0xC0000095
    assert classification.category == "integer_overflow"
    assert classification.attribution == "target_driver"
    assert classification.instruction_region == "mydriver!ScaleLength+0x10"


def test_verifier_and_hvci_are_reported_only_when_visible():
    parsed = parse_windbg_analysis(ANALYZE_C4_VERIFIER)
    assert parsed.driver_verifier is True
    assert parsed.probably_invalid_acquire == "fffff80512345678"
    assert parsed.probably_invalid_release == "fffff80512345679"
    assert "Driver Verifier" in parsed.observed_mitigations
    assert "HVCI" in parsed.observed_mitigations

    plain = parse_windbg_analysis(ANALYZE_A_NULL_DEREF)
    assert plain.observed_mitigations == ()


# ---------------------------------------------------------------------------
# Graph nodes
# ---------------------------------------------------------------------------


def test_four_nodes_produce_linked_records_and_evidence(fresh_env):
    ops = build_ops()
    hypothesis = _hypothesis()
    HypothesisStore(SETTINGS.data_dir / "hypotheses").add(hypothesis)

    crash = _crash(
        text=ANALYZE_50_CONTROLLED_WRITE,
        hypothesis_id=hypothesis.id,
        poc_input={"write_buffer": "0x4141414141414141"},
        trial_count=5,
        reproduced_trials=5,
    )
    ops.crashes.add(crash)
    state = _state([crash.id], hypothesis_ids=[hypothesis.id])

    state = _run_nodes(ops, state)

    stored = ops.crashes.get(crash.id)
    assert stored is not None
    assert stored.analysis_status == "parsed"
    assert stored.bugcheck_code == "0x50"
    assert stored.bugcheck_name == "PAGE_FAULT_IN_NONPAGED_AREA"
    assert stored.process_name == "poc.exe"
    assert stored.failure_bucket_id == "AV_4141414141414141_mydriver!CopyData"
    assert stored.classification == "invalid_memory_access"
    assert stored.attribution == "target_driver"
    assert stored.faulting_function == "mydriver!CopyData+0x33"
    assert stored.target_frame == "mydriver!CopyData+0x33"
    assert stored.parsed_analysis
    assert stored.root_cause_id and stored.impact_id and stored.exploitability_id
    assert stored.analysis_evidence_id

    assert state["triage_done"] is True
    assert state["triage_summary"]["analyzed"] == 1
    assert len(state["root_cause_ids"]) == 1
    assert len(state["impact_ids"]) == 1
    assert len(state["exploitability_ids"]) == 1
    # crash + root_cause + impact + exploitability evidence
    assert len(state["evidence_ids"]) == 4

    root_cause = ops.root_causes.get(stored.root_cause_id)
    assert root_cause is not None
    assert root_cause.category == "invalid_memory_access"
    assert root_cause.attribution == "target_driver"
    assert root_cause.function == "mydriver!CopyData"
    assert root_cause.instruction_region == "mydriver!CopyData+0x33"
    assert root_cause.reproducibility == "always"
    assert root_cause.related_hypothesis_id == hypothesis.id
    assert root_cause.crash_id == crash.id
    assert root_cause.notes
    assert root_cause.input_field and "matched PoC value" in root_cause.input_field

    impact = ops.impacts.get(stored.impact_id)
    assert impact is not None
    assert impact.impact_type == "potential_privilege_escalation"
    assert impact.privilege_boundary_crossed is True
    assert impact.confidentiality == "high"
    assert impact.integrity == "high"
    assert impact.availability == "high"
    assert impact.required_privilege == "unprivileged"
    assert impact.attack_vector == "local"
    assert impact.root_cause_id == root_cause.id

    exploitability = ops.exploitabilities.get(stored.exploitability_id)
    assert exploitability is not None
    assert exploitability.exploitability_level == "demonstrated"
    assert exploitability.controllability == "full"
    assert exploitability.reliability == "reliable"
    assert exploitability.mitigations_observed == []
    assert "0x4141414141414141" in exploitability.controlled_values
    assert "Defensive assessment only" in exploitability.notes

    evidences = [ops.evidence.get(eid) for eid in state["evidence_ids"]]
    by_type = {ev.evidence_type: ev for ev in evidences if ev is not None}
    assert set(by_type) == {"crash", "root_cause", "impact", "exploitability"}
    crash_evidence = by_type["crash"]
    assert crash_evidence.related_crash_id == crash.id
    assert crash_evidence.location == "mydriver!CopyData+0x33"
    assert is_real_location(crash_evidence.location)
    assert crash_evidence.evidence_strength == EvidenceStrength.E4
    assert evidence_proves_defect(crash_evidence)
    assert by_type["root_cause"].evidence_strength == EvidenceStrength.E5
    assert by_type["impact"].evidence_strength == EvidenceStrength.E6


def test_missing_analysis_produces_unknown_records_not_fabrication(fresh_env):
    ops = build_ops()
    crash = _crash(text=None)
    ops.crashes.add(crash)
    state = _state([crash.id])

    state = _run_nodes(ops, state)

    stored = ops.crashes.get(crash.id)
    assert stored is not None
    assert stored.analysis_status == "missing_analysis"
    assert stored.classification == "unknown"
    assert stored.attribution == "unknown"
    assert stored.bugcheck_code is None
    assert stored.parsed_analysis == {}
    assert set(CORE_FIELDS).issubset(set(stored.unknown_fields))
    assert "unknown" in stored.summary.lower()

    root_cause = ops.root_causes.get(stored.root_cause_id)
    assert root_cause is not None
    assert root_cause.category == "unknown"
    assert root_cause.attribution == "unknown"
    assert root_cause.function == "unknown"
    assert root_cause.instruction_region == "unknown"
    assert root_cause.reproducibility == "unknown"
    assert root_cause.trigger_condition.startswith("unknown")
    assert set(CORE_FIELDS).issubset(set(root_cause.unknown_fields))

    impact = ops.impacts.get(stored.impact_id)
    assert impact is not None
    assert impact.impact_type == "unknown"
    assert impact.privilege_boundary_crossed is False
    assert impact.confidentiality == "none"
    assert impact.integrity == "none"
    assert impact.required_privilege == "unknown"
    assert impact.attack_vector == "unknown"

    exploitability = ops.exploitabilities.get(stored.exploitability_id)
    assert exploitability is not None
    assert exploitability.exploitability_level == "theoretical"
    assert exploitability.controllability == "unknown"
    assert exploitability.reliability == "unknown"

    crash_evidence = ops.evidence.get(stored.analysis_evidence_id)
    assert crash_evidence is not None
    assert crash_evidence.location is None
    # A crash with no analysis cannot establish a defect at a real
    # location, so the QA gate must not accept it.
    assert evidence_proves_defect(crash_evidence) is False


def test_partial_analysis_keeps_category_but_ownership_unknown(fresh_env):
    ops = build_ops()
    crash = _crash(text=ANALYZE_ONLY_BUGCHECK)
    ops.crashes.add(crash)
    state = _state([crash.id])

    state = _run_nodes(ops, state)

    stored = ops.crashes.get(crash.id)
    assert stored is not None
    assert stored.analysis_status == "partial"
    assert stored.classification == "unknown"  # ownership unknown overrides
    assert stored.attribution == "unknown"
    assert "stack_text" in stored.unknown_fields

    root_cause = ops.root_causes.get(stored.root_cause_id)
    assert root_cause is not None
    # The bugcheck tells us this is pool corruption even though the stack
    # is missing; ownership and function remain explicitly unknown.
    assert root_cause.category == "pool_corruption"
    assert root_cause.attribution == "unknown"
    assert root_cause.function == "unknown"
    assert root_cause.instruction_region == "unknown"


def test_reproducibility_from_trial_counts(fresh_env):
    ops = build_ops()
    always = _crash(text=ANALYZE_A_NULL_DEREF, trial_count=5, reproduced_trials=5)
    flaky = _crash(text=ANALYZE_A_NULL_DEREF, trial_count=5, reproduced_trials=2)
    never_reproduced = _crash(text=ANALYZE_A_NULL_DEREF, trial_count=5, reproduced_trials=0)
    for crash in (always, flaky, never_reproduced):
        ops.crashes.add(crash)
    state = _state([always.id, flaky.id, never_reproduced.id])

    state = _run_nodes(ops, state)

    root_causes = [ops.root_causes.get(cid) for cid in state["root_cause_ids"]]
    by_crash = {rc.crash_id: rc.reproducibility for rc in root_causes if rc is not None}
    assert by_crash[always.id] == "always"
    assert by_crash[flaky.id] == "intermittent"
    assert by_crash[never_reproduced.id] == "once"

    exploitabilities = [
        ops.exploitabilities.get(xid) for xid in state["exploitability_ids"]
    ]
    reliability = {
        ex.crash_id: ex.reliability for ex in exploitabilities if ex is not None
    }
    assert reliability[always.id] == "reliable"
    assert reliability[flaky.id] == "intermittent"
    assert reliability[never_reproduced.id] == "unreliable"


def test_no_crash_nodes_are_noops(fresh_env):
    ops = build_ops()
    state = _state([])

    state = _run_nodes(ops, state)

    assert state["triage_done"] is True
    assert state["triage_summary"]["crashes"] == 0
    assert state["root_cause_ids"] == []
    assert state["impact_ids"] == []
    assert state["exploitability_ids"] == []
    assert state["evidence_ids"] == []
    assert ops.root_causes.count() == 0
    assert ops.impacts.count() == 0
    assert ops.exploitabilities.count() == 0


def test_validation_ingests_crash_records_for_the_research_run(fresh_env):
    ops = build_ops()
    crash = _crash(text=ANALYZE_A_NULL_DEREF)
    ops.crashes.add(crash)

    state = {
        "project_id": "PRJ-1",
        "research_id": "RES-1",
        "crash_ids": [],
        "crash_analysis_notes": [],
    }
    update = asyncio.run(validation_node(state, ops))
    assert update["crash_ids"] == [crash.id]
    assert update["validation_skipped"] is False

    empty = {
        "project_id": "PRJ-1",
        "research_id": "RES-OTHER",
        "crash_ids": [],
        "crash_analysis_notes": [],
    }
    update = asyncio.run(validation_node(empty, ops))
    assert update["crash_ids"] == []
    assert update["validation_skipped"] is True


def test_full_graph_discovers_and_triages_a_research_crash(fresh_env):
    import struct

    import dra.tools.tools.analyze_pe  # noqa: F401
    import dra.tools.tools.attack_surface_extract  # noqa: F401
    import dra.tools.tools.ioctl_extract  # noqa: F401
    import dra.tools.tools.mock_lab  # noqa: F401
    import dra.tools.tools.static_strings  # noqa: F401

    from dra.graph.main_graph import build_research_graph
    from dra.storage.filesystem import ProjectStore

    blob = (
        b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x40)
        + b"PE\x00\x00" + b"\x00" * 100
    )
    target = fresh_env / "mydriver.sys"
    target.write_bytes(blob)

    pid = new_id(IDPrefix.PROJECT)
    ProjectStore(SETTINGS.projects_dir).add(
        {"id": pid, "name": "demo", "authorized_use": True, "authorization_ref": "R-1"}
    )

    ops = build_ops()
    research_id = "RES-CRASH-INTEGRATION"
    crash = _crash(
        project_id=pid,
        research_id=research_id,
        text=ANALYZE_50_CONTROLLED_WRITE,
        poc_input={"write_buffer": "0x4141414141414141"},
    )
    ops.crashes.add(crash)

    graph = build_research_graph(ops)
    result = asyncio.run(
        graph.run(
            project_id=pid,
            target_id="TGT-1",
            target_path=str(target),
            research_id=research_id,
        )
    )

    assert result.get("status") == "completed"
    assert result.get("triage_done") is True
    stored = ops.crashes.get(crash.id)
    assert stored is not None
    assert stored.analysis_status == "parsed"
    assert stored.root_cause_id and stored.impact_id and stored.exploitability_id
    assert result["root_cause_ids"] == [stored.root_cause_id]
    assert result["impact_ids"] == [stored.impact_id]
    assert result["exploitability_ids"] == [stored.exploitability_id]

    root_cause = ops.root_causes.get(stored.root_cause_id)
    assert root_cause is not None
    assert root_cause.attribution == "target_driver"
    assert root_cause.category == "invalid_memory_access"

    exploitability = ops.exploitabilities.get(stored.exploitability_id)
    assert exploitability is not None
    assert exploitability.controllability == "full"
    assert exploitability.exploitability_level == "demonstrated"

    # The crash evidence must survive the subsequent evidence-registrar
    # node, otherwise QA can never see the defect-level evidence.
    evidence_ids = result.get("evidence_ids", [])
    assert stored.analysis_evidence_id in evidence_ids
    crash_evidence = ops.evidence.get(stored.analysis_evidence_id)
    assert crash_evidence is not None
    assert crash_evidence.location == "mydriver!CopyData+0x33"


def test_analysis_reference_file_is_read(fresh_env):
    ops = build_ops()
    analysis_path = fresh_env / "recorded-analyze.txt"
    analysis_path.write_text(ANALYZE_C2_BAD_POOL_CALLER, encoding="utf-8")
    crash = _crash(text=None, analysis_ref=str(analysis_path))
    ops.crashes.add(crash)
    state = _state([crash.id])

    state = _run_nodes(ops, state)

    stored = ops.crashes.get(crash.id)
    assert stored is not None
    assert stored.analysis_status == "parsed"
    assert stored.bugcheck_code == "0xC2"
    root_cause = ops.root_causes.get(stored.root_cause_id)
    assert root_cause is not None
    assert root_cause.category == "use_after_free"
    assert root_cause.instruction_region == "mydriver!Cleanup+0x4a"
