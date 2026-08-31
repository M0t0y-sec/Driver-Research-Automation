"""Evidence + QA smoke tests."""
import shutil

import pytest

from dra.evidence.registrar import EvidenceRegistrar
from dra.llm.router import LLMRouter
from dra.llm.mock import MockLLMClient
from dra.qa.auditor import QAAuditor
from dra.models.common import IDPrefix, new_id
from dra.models.evidence import Evidence, EvidenceStrength
from dra.models.finding import Finding, FindingStatus
from dra.config import SETTINGS


@pytest.fixture
def fresh_dir(tmp_path):
    SETTINGS.__dict__["evidence_dir"] = tmp_path / "evidence"
    SETTINGS.evidence_dir.mkdir(parents=True, exist_ok=True)
    yield tmp_path
    shutil.rmtree(tmp_path, ignore_errors=True)


def test_evidence_register_and_lookup(fresh_dir):
    reg = EvidenceRegistrar()
    ev = reg.register(
        project_id="PRJ-1",
        evidence_type="static_observation",
        producer_agent="recon",
        source_artifact_hash="a" * 64,
        evidence_strength=EvidenceStrength.E1,
        summary="x",
    )
    got = reg.get(ev.id)
    assert got is not None
    assert got.evidence_strength == EvidenceStrength.E1


def test_qa_rejects_finding_without_evidence():
    auditor = QAAuditor(LLMRouter(MockLLMClient()))
    bad = Finding(
        id=new_id(IDPrefix.FINDING),
        project_id="PRJ-1",
        target_id="TGT-1",
        title="t",
        summary="s",
        vulnerability_class="memory_safety",
    )
    review = auditor.review_finding(bad)
    assert review.decision.value == "retry"
    assert any(h.rule_id == "finding.has_evidence" for h in review.rule_hits)


def test_qa_passes_good_candidate():
    auditor = QAAuditor(LLMRouter(MockLLMClient()))
    ev = Evidence(
        id=new_id(IDPrefix.EVIDENCE),
        project_id="PRJ-1",
        evidence_type="static_observation",
        producer_agent="recon",
        source_artifact_hash="a" * 64,
        evidence_strength=EvidenceStrength.E1,
        summary="obs",
    )
    good = Finding(
        id=new_id(IDPrefix.FINDING),
        project_id="PRJ-1",
        target_id="TGT-1",
        title="ok",
        summary="s",
        vulnerability_class="memory_safety",
        evidence_ids=[ev.id],
        lineage_ids=[ev.id],
        limitations=["x"],
        status=FindingStatus.CANDIDATE,
    )
    review = auditor.review_finding(good, evidences=[ev])
    assert review.decision.value == "pass"
