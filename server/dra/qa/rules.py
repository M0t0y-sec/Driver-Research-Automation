"""Rule-based QA.

Each rule is a small function that inspects an object and returns a
`QARuleHit`. Rules are intentionally cheap and deterministic; the LLM
review is layered on top of the rule results (see `auditor.py`).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from ..models.evidence import Evidence
from ..models.finding import Finding, FindingStatus
from ..models.qa import QARuleHit


@dataclass(frozen=True)
class QARule:
    rule_id: str
    description: str
    fn: Callable[[object], QARuleHit]


def _hit(rule_id: str, description: str, passed: bool, detail: str | None = None) -> QARuleHit:
    return QARuleHit(rule_id=rule_id, description=description, passed=passed, detail=detail)


# --- Finding rules ---

def rule_finding_has_evidence(f: Finding) -> QARuleHit:
    rid = "finding.has_evidence"
    return _hit(rid, "Finding must reference at least one evidence_id.", len(f.evidence_ids) > 0,
                detail=f"evidence_ids={f.evidence_ids}")


def rule_finding_has_lineage(f: Finding) -> QARuleHit:
    rid = "finding.has_lineage"
    return _hit(rid, "Finding must record at least one lineage id.", len(f.lineage_ids) > 0,
                detail=f"lineage_ids={f.lineage_ids[:5]}")


def rule_finding_has_root_cause_or_impact(f: Finding) -> QARuleHit:
    rid = "finding.has_root_cause_or_impact"
    # Candidate findings are explicitly allowed to lack RCA/Impact; the
    # rule only fires on findings that are leaving the platform.
    if f.status in {FindingStatus.CANDIDATE, FindingStatus.EVIDENCE_REVIEW}:
        return _hit(
            rid,
            "Candidate findings may omit RCA/Impact until validation completes.",
            True,
            detail=f"status={f.status.value}",
        )
    return _hit(
        rid,
        "Finding should link to a root cause or impact analysis.",
        f.root_cause_id is not None or f.impact_id is not None,
        detail=f"root_cause_id={f.root_cause_id} impact_id={f.impact_id}",
    )


def rule_finding_lists_limitations(f: Finding) -> QARuleHit:
    rid = "finding.lists_limitations"
    return _hit(
        rid,
        "Finding must list at least one explicit limitation.",
        len(f.limitations) > 0,
        detail=f"limitations={f.limitations[:3]}",
    )


# --- Evidence rules ---

def rule_evidence_has_source_hash(e: Evidence) -> QARuleHit:
    rid = "evidence.has_source_hash"
    return _hit(
        rid,
        "Evidence must record a non-empty source_artifact_hash.",
        bool(e.source_artifact_hash),
        detail=f"hash={e.source_artifact_hash[:16] if e.source_artifact_hash else None}",
    )


def rule_evidence_has_producer(e: Evidence) -> QARuleHit:
    rid = "evidence.has_producer"
    return _hit(
        rid,
        "Evidence must record the producer agent name.",
        bool(e.producer_agent),
    )


def rule_evidence_strength_matches_type(e: Evidence) -> QARuleHit:
    """E0 (LLM opinion) cannot be the only evidence for a finding."""
    rid = "evidence.strength_floor"
    return _hit(
        rid,
        "Evidence used in a finding should be E1 or above.",
        e.evidence_strength.value not in {"E0"},
        detail=f"strength={e.evidence_strength.value}",
    )


# --- Bundle ---

FINDING_RULES: list[QARule] = [
    QARule("finding.has_evidence", "Finding must reference evidence.", rule_finding_has_evidence),
    QARule("finding.has_lineage", "Finding must record lineage.", rule_finding_has_lineage),
    QARule("finding.has_root_cause_or_impact", "Finding must reference RCA or impact.", rule_finding_has_root_cause_or_impact),
    QARule("finding.lists_limitations", "Finding must list limitations.", rule_finding_lists_limitations),
]

EVIDENCE_RULES: list[QARule] = [
    QARule("evidence.has_source_hash", "Evidence has source hash.", rule_evidence_has_source_hash),
    QARule("evidence.has_producer", "Evidence has producer.", rule_evidence_has_producer),
    QARule("evidence.strength_floor", "Evidence is at least E1.", rule_evidence_strength_matches_type),
]

BUILTIN_RULES: dict[str, list[QARule]] = {
    "finding": FINDING_RULES,
    "evidence": EVIDENCE_RULES,
}
