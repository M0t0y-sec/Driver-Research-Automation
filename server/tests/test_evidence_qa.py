"""Evidence + QA tests.

The important invariant: a mock/pass-happy LLM must not be able to turn
thin evidence into `qa_pass`. Deterministic rules run first and veto the
result at `inconclusive` without even calling the LLM.

A second invariant, learned from a real false positive: a real IOCTL
constant / device name / handler RVA proves the *attack surface*, not a
defect.  A finding resting on such facts must never reach `qa_pass`; it
needs a defect-level evidence (sink / control_flow / crash) anchored to
a real location.
"""
import asyncio
import shutil

import pytest

from dra.agents._ops import build_ops
from dra.agents.qa_auditor import qa_auditor_node
from dra.config import SETTINGS
from dra.evidence.kinds import EvidenceKind, derive_evidence_kind
from dra.evidence.registrar import EvidenceRegistrar
from dra.evidence.strength import (
    derive_evidence_strength,
    effective_evidence_strength,
    evidence_kind,
    evidence_proves_defect,
    is_real_location,
)
from dra.llm.mock import MockLLMClient
from dra.llm.router import LLMRouter
from dra.models.common import EvidenceStrength, FindingStatus, IDPrefix, new_id
from dra.models.evidence import Evidence
from dra.models.finding import Finding
from dra.models.hypothesis import Hypothesis
from dra.models.observation import Observation
from dra.qa.auditor import QAAuditor


@pytest.fixture
def fresh_env(tmp_path):
    """Point every store at a throw-away directory for one test."""
    SETTINGS.__dict__["data_dir"] = tmp_path / "data"
    SETTINGS.__dict__["artifacts_dir"] = tmp_path / "artefacts"
    SETTINGS.__dict__["audit_log_path"] = tmp_path / "data" / "audit.log.jsonl"
    SETTINGS.data_dir.mkdir(parents=True, exist_ok=True)
    SETTINGS.artifacts_dir.mkdir(parents=True, exist_ok=True)
    yield tmp_path
    shutil.rmtree(tmp_path, ignore_errors=True)


class CountingMockLLM(MockLLMClient):
    """Mock LLM that records how often QA actually consults it."""

    def __init__(self) -> None:
        self.calls = 0

    def complete(self, messages, *, task, response_schema=None, temperature=None):
        self.calls += 1
        return super().complete(
            messages, task=task, response_schema=response_schema, temperature=temperature
        )


def _evidence(
    *,
    evidence_type: str = "static_observation",
    producer_agent: str = "recon",
    strength: EvidenceStrength = EvidenceStrength.E1,
    summary: str = "",
    source_artifact_hash: str = "a" * 64,
    related_crash_id: str | None = None,
) -> Evidence:
    return Evidence(
        id=new_id(IDPrefix.EVIDENCE),
        project_id="PRJ-1",
        target_id="TGT-1",
        evidence_type=evidence_type,
        producer_agent=producer_agent,
        source_artifact_hash=source_artifact_hash,
        evidence_strength=strength,
        related_crash_id=related_crash_id,
        summary=summary,
    )


def _finding(
    *,
    evidence_ids: list[str],
    trigger_condition: str | None,
    title: str = "t",
) -> Finding:
    return Finding(
        id=new_id(IDPrefix.FINDING),
        project_id="PRJ-1",
        target_id="TGT-1",
        title=title,
        summary="s",
        vulnerability_class="memory_safety",
        trigger_condition=trigger_condition,
        evidence_ids=evidence_ids,
        lineage_ids=["TGT-1"] + evidence_ids,
        limitations=["static only"],
        status=FindingStatus.CANDIDATE,
    )


# ---------------------------------------------------------------------------
# Strength derivation
# ---------------------------------------------------------------------------

def test_register_derives_strength_instead_of_trusting_caller(fresh_env):
    reg = EvidenceRegistrar()

    # Static observation anchored to a real address: E1.
    anchored = reg.register(
        project_id="PRJ-1",
        evidence_type="static_observation",
        producer_agent="recon",
        source_artifact_hash="a" * 64,
        location="rva:0x140001000",
        evidence_strength=EvidenceStrength.E1,
        summary="IOCTL handler at rva:0x140001000",
    )
    assert anchored.evidence_strength == EvidenceStrength.E1

    # A model opinion claiming E3 is clamped to E0.
    opinion = reg.register(
        project_id="PRJ-1",
        evidence_type="hypothesis_rule_signal",
        producer_agent="hypothesis",
        source_artifact_hash="b" * 64,
        evidence_strength=EvidenceStrength.E3,
        summary="model thinks this is exploitable",
    )
    assert opinion.evidence_strength == EvidenceStrength.E0

    # Import names can never exceed E1.
    imported = reg.register(
        project_id="PRJ-1",
        evidence_type="static_observation",
        producer_agent="recon",
        source_artifact_hash="c" * 64,
        location="IoCreateDevice",
        evidence_strength=EvidenceStrength.E6,
        summary="Driver imports IoCreateDevice",
    )
    assert imported.evidence_strength == EvidenceStrength.E1

    # No location at all downgrades a static observation to E0.
    unlocated = reg.register(
        project_id="PRJ-1",
        evidence_type="static_observation",
        producer_agent="recon",
        source_artifact_hash="d" * 64,
        summary="something happened somewhere",
    )
    assert unlocated.evidence_strength == EvidenceStrength.E0

    # Dynamic observation = E2; reproducible + real location = E3.
    dynamic = reg.register(
        project_id="PRJ-1",
        evidence_type="dynamic_observation",
        producer_agent="validation",
        source_artifact_hash="e" * 64,
        location="rva:0x140002000",
        dynamic=True,
    )
    assert dynamic.evidence_strength == EvidenceStrength.E2
    reproduced = reg.register(
        project_id="PRJ-1",
        evidence_type="control_flow_repro_signal",
        producer_agent="validation",
        source_artifact_hash="f" * 64,
        location="rva:0x140002000",
        dynamic=True,
        reproducible=True,
    )
    assert reproduced.evidence_strength == EvidenceStrength.E3

    # A missing hash downgrades even a reproducible signal.
    no_hash = derive_evidence_strength(
        evidence_type="control_flow_repro_signal",
        producer_agent="validation",
        source_artifact_hash="",
        location="rva:0x140002000",
        dynamic=True,
        reproducible=True,
    )
    assert no_hash == EvidenceStrength.E2


def test_surface_evidence_is_capped_at_e2():
    """Reproducing an attack surface never makes a finding look strong."""
    surface_repro = derive_evidence_strength(
        evidence_type="repro_signal",
        producer_agent="validation",
        source_artifact_hash="a" * 64,
        location="rva:0x140001000",
        dynamic=True,
        reproducible=True,
    )
    assert surface_repro == EvidenceStrength.E2

    defect_repro = derive_evidence_strength(
        evidence_type="control_flow_repro_signal",
        producer_agent="validation",
        source_artifact_hash="a" * 64,
        location="rva:0x140001000",
        dynamic=True,
        reproducible=True,
    )
    assert defect_repro == EvidenceStrength.E3


def test_effective_strength_rederives_from_facts():
    # Stored E3 but only a static observation: QA sees E1 at best.
    inflated = _evidence(evidence_type="static_observation", strength=EvidenceStrength.E3)
    assert effective_evidence_strength(inflated, "rva:0x140001000") == EvidenceStrength.E1
    # Stored E2 with no location -> E1 after the location downgrade.
    assert effective_evidence_strength(inflated, None) == EvidenceStrength.E0
    dynamic = _evidence(evidence_type="dynamic_observation", strength=EvidenceStrength.E2)
    assert effective_evidence_strength(dynamic, "rva:0x140002000") == EvidenceStrength.E2
    assert effective_evidence_strength(dynamic, "unknown") == EvidenceStrength.E1


def test_real_location_classification():
    assert is_real_location("rva:0x140001000")
    assert is_real_location("IOCTL 0x222004 at section:.text+0x40")
    assert is_real_location("driver.sys!DriverEntry+0x20")
    assert not is_real_location("unknown")
    assert not is_real_location(None)
    assert not is_real_location("PE:imports")
    assert not is_real_location("IoCreateDevice")


def test_evidence_kind_classification():
    # Attack surface: real facts about an interface, not about a defect.
    assert derive_evidence_kind(evidence_type="static_observation") is EvidenceKind.SURFACE
    assert derive_evidence_kind(evidence_type="dynamic_observation") is EvidenceKind.SURFACE
    assert derive_evidence_kind(evidence_type="hypothesis_rule_signal") is EvidenceKind.SURFACE
    assert derive_evidence_kind(evidence_type="ioctl_code_comparison") is EvidenceKind.SURFACE
    assert derive_evidence_kind(evidence_type="device_name_scan") is EvidenceKind.SURFACE
    assert derive_evidence_kind(evidence_type="import_RtlCopyMemory") is EvidenceKind.SURFACE

    # Defect-level mechanisms.
    assert derive_evidence_kind(evidence_type="memory_copy_sink") is EvidenceKind.SINK
    assert derive_evidence_kind(evidence_type="missing_probe") is EvidenceKind.CONTROL_FLOW
    assert derive_evidence_kind(evidence_type="taint_path") is EvidenceKind.CONTROL_FLOW
    assert derive_evidence_kind(evidence_type="bounds_violation") is EvidenceKind.CONTROL_FLOW
    assert derive_evidence_kind(evidence_type="integer_overflow") is EvidenceKind.CONTROL_FLOW
    assert derive_evidence_kind(evidence_type="crash") is EvidenceKind.CRASH
    assert (
        derive_evidence_kind(
            evidence_type="static_observation", related_crash_id="CRS-1"
        )
        is EvidenceKind.CRASH
    )

    # Supporting facts that presuppose a defect but do not establish one.
    assert derive_evidence_kind(evidence_type="root_cause_link") is EvidenceKind.ROOT_CAUSE
    assert derive_evidence_kind(evidence_type="impact_confirmed") is EvidenceKind.IMPACT


def test_only_defect_kinds_prove_a_defect():
    surface = _evidence(
        evidence_type="static_observation", summary="IOCTL 0x00010000 at rva:0x1010"
    )
    assert evidence_kind(surface) is EvidenceKind.SURFACE
    assert not evidence_proves_defect(surface, "rva:0x1010")

    # A defect kind without a real location is not verifiable either.
    unlocated_sink = _evidence(evidence_type="memory_copy_sink", summary="copy sink")
    assert not evidence_proves_defect(unlocated_sink, "unknown")

    sink = _evidence(evidence_type="memory_copy_sink", summary="copy sink")
    assert evidence_proves_defect(sink, "rva:0x140002000")

    # A model opinion is never proof, even when typed as a sink.
    opinion = _evidence(
        evidence_type="memory_copy_sink",
        producer_agent="hypothesis",
        summary="model claims a sink",
    )
    assert not evidence_proves_defect(opinion, "rva:0x140002000")


# ---------------------------------------------------------------------------
# Auditor: deterministic gate vs. a pass-happy mock LLM
# ---------------------------------------------------------------------------

def test_weak_evidence_with_mock_pass_is_inconclusive(fresh_env):
    llm = CountingMockLLM()
    auditor = QAAuditor(LLMRouter(llm))

    # Import-table material only ("Potential issue ... at unknown" in spirit).
    ev = _evidence(
        evidence_type="static_observation",
        strength=EvidenceStrength.E1,
        summary="Driver imports IoCreateDevice (potential IOCTL/memory primitive).",
    )
    finding = _finding(evidence_ids=[ev.id], trigger_condition="PE:imports")

    review = auditor.review_finding(
        finding,
        evidences=[ev],
        evidence_locations={ev.id: "IoCreateDevice"},
    )

    assert review.decision.value != "pass"
    assert review.decision.value == "inconclusive"
    assert llm.calls == 0, "deterministic veto must not spend an LLM call"
    assert any("deterministic veto" in r for r in review.reasons)
    assert any(h.rule_id == "finding.supporting_strength" and not h.passed for h in review.rule_hits)


def test_unknown_location_blocks_pass_even_with_dynamic_evidence(fresh_env):
    llm = CountingMockLLM()
    auditor = QAAuditor(LLMRouter(llm))

    # Defect-typed evidence, so only the location rule can veto this one.
    ev = _evidence(
        evidence_type="dynamic_observation_sink",
        strength=EvidenceStrength.E2,
        summary="observed IOCTL at rva:0x140002000",
    )
    finding = _finding(evidence_ids=[ev.id], trigger_condition="unknown")

    review = auditor.review_finding(
        finding, evidences=[ev], evidence_locations={ev.id: "rva:0x140002000"}
    )

    assert review.decision.value == "inconclusive"
    assert llm.calls == 0
    assert any(h.rule_id == "finding.location_known" and not h.passed for h in review.rule_hits)


def test_import_only_evidence_cannot_pass_even_if_high_strength(fresh_env):
    llm = CountingMockLLM()
    auditor = QAAuditor(LLMRouter(llm))

    ev = _evidence(
        evidence_type="evidence_from_import_table",
        strength=EvidenceStrength.E3,
        summary="imports RtlCopyMemory",
    )
    finding = _finding(evidence_ids=[ev.id], trigger_condition="IRP_MJ_DEVICE_CONTROL")

    review = auditor.review_finding(
        finding, evidences=[ev], evidence_locations={ev.id: "PE:imports"}
    )

    assert review.decision.value == "inconclusive"
    assert llm.calls == 0
    assert any(h.rule_id == "finding.not_import_only" and not h.passed for h in review.rule_hits)
    assert any(h.rule_id == "finding.supporting_strength" and not h.passed for h in review.rule_hits)


def test_defect_evidence_still_passes(fresh_env):
    llm = CountingMockLLM()
    auditor = QAAuditor(LLMRouter(llm))

    ev = _evidence(
        evidence_type="dynamic_observation_sink",
        strength=EvidenceStrength.E2,
        summary="IOCTL 0x222004 reaches RtlCopyMemory at rva:0x140002000",
    )
    finding = _finding(
        evidence_ids=[ev.id],
        trigger_condition="IOCTL 0x222004 with an oversized input buffer",
    )

    review = auditor.review_finding(
        finding, evidences=[ev], evidence_locations={ev.id: "rva:0x140002000"}
    )

    assert review.decision.value == "pass"
    assert llm.calls == 1
    assert all(h.passed for h in review.rule_hits)


def test_e1_defect_evidence_with_real_location_also_passes(fresh_env):
    llm = CountingMockLLM()
    auditor = QAAuditor(LLMRouter(llm))

    ev = _evidence(
        evidence_type="missing_probe",
        strength=EvidenceStrength.E1,
        summary="handler at rva:0x140003000 calls RtlCopyMemory without ProbeForWrite",
    )
    finding = _finding(
        evidence_ids=[ev.id],
        trigger_condition="IOCTL 0x222008 at rva:0x140003000",
    )

    review = auditor.review_finding(
        finding, evidences=[ev], evidence_locations={ev.id: "rva:0x140003000"}
    )

    assert review.decision.value == "pass"
    assert llm.calls == 1


def test_surface_facts_with_real_addresses_cannot_pass(fresh_env):
    """The reproduced beep.sys false positive.

    A real IOCTL constant, a real device name and a real handler RVA are
    all true - but they only establish the attack surface.  The mock LLM
    answers "pass"; the deterministic gate must veto before the LLM is
    consulted.
    """
    llm = CountingMockLLM()
    auditor = QAAuditor(LLMRouter(llm))

    ioctl_ev = _evidence(
        evidence_type="static_observation",
        summary=(
            "IOCTL 0x00010000 compared in the IRP_MJ_DEVICE_CONTROL handler "
            "(handler_rva=0x1010); decoded as device_type=0x0001 access=any "
            "function=0x0000 method=buffered."
        ),
    )
    device_ev = _evidence(
        evidence_type="static_observation",
        summary="Device/symlink name \\Device\\Beep recovered from a UTF-16LE literal.",
    )
    dispatch_ev = _evidence(
        evidence_type="static_observation",
        summary=(
            "DriverEntry writes MajorFunction[IRP_MJ_DEVICE_CONTROL] "
            "(handler_rva=0x1010, ioctl_count=1)."
        ),
    )
    finding = _finding(
        evidence_ids=[ioctl_ev.id, device_ev.id, dispatch_ev.id],
        trigger_condition="IOCTL 0x00010000 at rva:0x1010",
        title="Potential issue in ioctl_code at IOCTL 0x00010000",
    )

    review = auditor.review_finding(
        finding,
        evidences=[ioctl_ev, device_ev, dispatch_ev],
        evidence_locations={
            ioctl_ev.id: "rva:0x1010",
            device_ev.id: "rva:0x1040",
            dispatch_ev.id: "rva:0x1000",
        },
    )

    assert review.decision.value == "inconclusive"
    assert review.decision.value != "pass"
    assert llm.calls == 0, "the gate must not ask the LLM to bless attack-surface facts"
    assert any(
        h.rule_id == "finding.defect_evidence" and not h.passed
        for h in review.rule_hits
    )
    defect_hit = next(
        h for h in review.rule_hits if h.rule_id == "finding.defect_evidence"
    )
    assert "surface" in (defect_hit.detail or "")


def test_sink_evidence_with_user_controlled_length_passes(fresh_env):
    llm = CountingMockLLM()
    auditor = QAAuditor(LLMRouter(llm))

    ev = _evidence(
        evidence_type="memory_copy_sink",
        strength=EvidenceStrength.E1,
        summary=(
            "RtlCopyMemory at rva:0x140002000 copies OutputBufferLength "
            "(user-controlled, read from the IRP) into a 16-byte kernel buffer; "
            "no length check precedes the call."
        ),
    )
    finding = _finding(
        evidence_ids=[ev.id],
        trigger_condition="IOCTL 0x222004 with an oversized output buffer",
    )

    review = auditor.review_finding(
        finding, evidences=[ev], evidence_locations={ev.id: "rva:0x140002000"}
    )

    assert review.decision.value == "pass"
    assert llm.calls == 1
    assert all(h.passed for h in review.rule_hits)


def test_real_crash_stack_evidence_passes(fresh_env):
    llm = CountingMockLLM()
    auditor = QAAuditor(LLMRouter(llm))

    ev = _evidence(
        evidence_type="crash",
        strength=EvidenceStrength.E4,
        summary=(
            "Bugcheck 0x50 (PAGE_FAULT_IN_NONPAGED_AREA) at "
            "beep!BeepCopyIoctl+0x2a -> nt!RtlCopyMemory."
        ),
        related_crash_id="CRS-TEST-1",
    )
    finding = _finding(
        evidence_ids=[ev.id],
        trigger_condition="IOCTL 0x00010000 with output length 0xFFFFFFFF",
    )

    review = auditor.review_finding(
        finding,
        evidences=[ev],
        evidence_locations={ev.id: "beep.sys!BeepCopyIoctl+0x2a"},
    )

    assert review.decision.value == "pass"
    assert llm.calls == 1
    assert all(h.passed for h in review.rule_hits)


def test_mixed_surface_and_defect_evidence_passes(fresh_env):
    llm = CountingMockLLM()
    auditor = QAAuditor(LLMRouter(llm))

    surface = _evidence(
        evidence_type="static_observation",
        summary="IOCTL 0x222004 compared in the device-control handler.",
    )
    sink = _evidence(
        evidence_type="memory_copy_sink",
        summary="RtlCopyMemory at rva:0x140002000 uses the user-controlled length.",
    )
    finding = _finding(
        evidence_ids=[surface.id, sink.id],
        trigger_condition="IOCTL 0x222004 with an oversized output buffer",
    )

    review = auditor.review_finding(
        finding,
        evidences=[surface, sink],
        evidence_locations={
            surface.id: "rva:0x1010",
            sink.id: "rva:0x140002000",
        },
    )

    assert review.decision.value == "pass"
    assert llm.calls == 1
    assert all(h.passed for h in review.rule_hits)


def test_uncited_defect_evidence_cannot_rescue_a_finding(fresh_env):
    llm = CountingMockLLM()
    auditor = QAAuditor(LLMRouter(llm))

    surface = _evidence(
        evidence_type="static_observation",
        summary="IOCTL 0x222004 compared in the device-control handler.",
    )
    sink = _evidence(
        evidence_type="memory_copy_sink",
        summary="RtlCopyMemory at rva:0x140002000 uses the user-controlled length.",
    )
    # The sink exists in the evidence store, but the finding does not cite
    # it - so the finding is still supported only by attack-surface facts.
    finding = _finding(
        evidence_ids=[surface.id],
        trigger_condition="IOCTL 0x222004",
    )

    review = auditor.review_finding(
        finding,
        evidences=[surface, sink],
        evidence_locations={
            surface.id: "rva:0x1010",
            sink.id: "rva:0x140002000",
        },
    )

    assert review.decision.value == "inconclusive"
    assert llm.calls == 0
    assert any(
        h.rule_id == "finding.defect_evidence" and not h.passed
        for h in review.rule_hits
    )


def test_malformed_llm_verdict_defaults_to_inconclusive(fresh_env):
    class MalformedLLM(CountingMockLLM):
        def complete(self, messages, *, task, response_schema=None, temperature=None):
            self.calls += 1
            from dra.llm.base import LLMResponse

            return LLMResponse(content="not json", structured={"decision": "banana"})

    llm = MalformedLLM()
    auditor = QAAuditor(LLMRouter(llm))
    ev = _evidence(
        evidence_type="dynamic_observation_sink",
        strength=EvidenceStrength.E2,
        summary="observed at rva:0x140002000",
    )
    finding = _finding(evidence_ids=[ev.id], trigger_condition="IOCTL 0x222004")

    review = auditor.review_finding(
        finding, evidences=[ev], evidence_locations={ev.id: "rva:0x140002000"}
    )

    assert review.decision.value == "inconclusive"
    assert llm.calls == 1


def test_qa_rejects_finding_without_evidence(fresh_env):
    auditor = QAAuditor(LLMRouter(MockLLMClient()))
    bad = _finding(evidence_ids=[], trigger_condition=None)
    review = auditor.review_finding(bad)
    assert review.decision.value == "retry"
    assert any(h.rule_id == "finding.has_evidence" for h in review.rule_hits)


# ---------------------------------------------------------------------------
# Agent node wiring
# ---------------------------------------------------------------------------

def test_inconclusive_review_lands_on_needs_human(fresh_env):
    ops = build_ops()

    obs = Observation(
        id=new_id(IDPrefix.OBSERVATION),
        target_id="TGT-1",
        project_id="PRJ-1",
        category="ioctl_dispatch",
        location="IoCreateDevice",  # import name, not a code location
        description="Driver imports IoCreateDevice (potential IOCTL/memory primitive).",
        source="static",
        source_tool="analyze_pe",
    )
    ops.observations.add(obs)

    hypothesis = Hypothesis(
        id=new_id(IDPrefix.HYPOTHESIS),
        project_id="PRJ-1",
        target_id="TGT-1",
        category="memory_safety",
        location=None,
        description="Potential issue in ioctl_dispatch at unknown; see observation.",
        observation_ids=[obs.id],
    )
    ops.hypotheses.add(hypothesis)

    ev = ops.evidence.register(
        project_id="PRJ-1",
        evidence_type="static_observation",
        producer_agent="recon",
        target_id="TGT-1",
        source_artifact_hash="a" * 64,
        evidence_strength=EvidenceStrength.E1,
        summary=obs.description,
        lineage_ids=["TGT-1", obs.id],
    )

    state = {
        "project_id": "PRJ-1",
        "research_id": "RES-TEST",
        "target_id": "TGT-1",
        "hypothesis_ids": [hypothesis.id],
        "selected_hypothesis_ids": [hypothesis.id],
        "evidence_ids": [ev.id],
    }
    result = asyncio.run(qa_auditor_node(state, ops))

    finding = ops.findings.get(result["finding_ids"][0])
    assert finding is not None
    assert finding.qa_status == "inconclusive"
    assert finding.status == FindingStatus.NEEDS_HUMAN
    assert finding.status != FindingStatus.QA_PASS


def test_real_surface_facts_land_on_needs_human_not_qa_pass(fresh_env):
    """End-to-end version of the reproduced false positive.

    Real IOCTL constant + real handler RVA + real device name, exactly
    what ioctl_extract produced for beep.sys.  The hypothesis becomes a
    finding (the graph must still emit one), but QA must not bless it.
    """
    ops = build_ops()

    obs = Observation(
        id=new_id(IDPrefix.OBSERVATION),
        target_id="TGT-1",
        project_id="PRJ-1",
        category="ioctl_code",
        location="rva:0x1010",
        description=(
            "IOCTL 0x00010000 compared in the IRP_MJ_DEVICE_CONTROL handler "
            "(handler_rva=0x1010); device name \\Device\\Beep."
        ),
        source="static",
        source_tool="ioctl_extract",
        source_method="dispatch_comparison",
    )
    ops.observations.add(obs)

    hypothesis = Hypothesis(
        id=new_id(IDPrefix.HYPOTHESIS),
        project_id="PRJ-1",
        target_id="TGT-1",
        category="memory_safety",
        location=None,
        description="Potential issue in ioctl_code at IOCTL 0x00010000",
        observation_ids=[obs.id],
    )
    ops.hypotheses.add(hypothesis)

    ev = ops.evidence.register(
        project_id="PRJ-1",
        evidence_type="static_observation",
        producer_agent="recon",
        target_id="TGT-1",
        source_artifact_hash="a" * 64,
        evidence_strength=EvidenceStrength.E1,
        summary=obs.description,
        lineage_ids=["TGT-1", obs.id],
    )

    state = {
        "project_id": "PRJ-1",
        "research_id": "RES-TEST",
        "target_id": "TGT-1",
        "hypothesis_ids": [hypothesis.id],
        "selected_hypothesis_ids": [hypothesis.id],
        "evidence_ids": [ev.id],
    }
    result = asyncio.run(qa_auditor_node(state, ops))

    finding = ops.findings.get(result["finding_ids"][0])
    assert finding is not None
    assert finding.status == FindingStatus.NEEDS_HUMAN
    assert finding.status != FindingStatus.QA_PASS
    assert finding.qa_status == "inconclusive"
    assert any("attack surface only" in lim for lim in finding.limitations)
