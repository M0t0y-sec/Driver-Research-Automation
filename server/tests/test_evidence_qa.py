"""Evidence + QA tests.

The important invariant: a mock/pass-happy LLM must not be able to turn
thin evidence into `qa_pass`. Deterministic rules run first and veto the
result at `inconclusive` without even calling the LLM.
"""
import asyncio
import shutil

import pytest

from dra.agents._ops import build_ops
from dra.agents.qa_auditor import qa_auditor_node
from dra.config import SETTINGS
from dra.evidence.registrar import EvidenceRegistrar
from dra.evidence.strength import (
    derive_evidence_strength,
    effective_evidence_strength,
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
) -> Evidence:
    return Evidence(
        id=new_id(IDPrefix.EVIDENCE),
        project_id="PRJ-1",
        target_id="TGT-1",
        evidence_type=evidence_type,
        producer_agent=producer_agent,
        source_artifact_hash=source_artifact_hash,
        evidence_strength=strength,
        summary=summary,
    )


def _finding(*, evidence_ids: list[str], trigger_condition: str | None) -> Finding:
    return Finding(
        id=new_id(IDPrefix.FINDING),
        project_id="PRJ-1",
        target_id="TGT-1",
        title="t",
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
        evidence_type="repro_signal",
        producer_agent="validation",
        source_artifact_hash="f" * 64,
        location="rva:0x140002000",
        dynamic=True,
        reproducible=True,
    )
    assert reproduced.evidence_strength == EvidenceStrength.E3

    # A missing hash downgrades even a reproducible signal.
    no_hash = derive_evidence_strength(
        evidence_type="repro_signal",
        producer_agent="validation",
        source_artifact_hash="",
        location="rva:0x140002000",
        dynamic=True,
        reproducible=True,
    )
    assert no_hash == EvidenceStrength.E2


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

    ev = _evidence(
        evidence_type="dynamic_observation",
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


def test_strong_evidence_still_passes(fresh_env):
    llm = CountingMockLLM()
    auditor = QAAuditor(LLMRouter(llm))

    ev = _evidence(
        evidence_type="dynamic_observation",
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


def test_e1_with_real_location_also_passes(fresh_env):
    llm = CountingMockLLM()
    auditor = QAAuditor(LLMRouter(llm))

    ev = _evidence(
        evidence_type="static_observation",
        strength=EvidenceStrength.E1,
        summary="dispatch table at rva:0x140003000",
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


def test_malformed_llm_verdict_defaults_to_inconclusive(fresh_env):
    class MalformedLLM(CountingMockLLM):
        def complete(self, messages, *, task, response_schema=None, temperature=None):
            self.calls += 1
            from dra.llm.base import LLMResponse

            return LLMResponse(content="not json", structured={"decision": "banana"})

    llm = MalformedLLM()
    auditor = QAAuditor(LLMRouter(llm))
    ev = _evidence(
        evidence_type="dynamic_observation",
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
