"""Rule-based QA.

Each rule is a small function that inspects an object and returns a
`QARuleHit`. Rules are intentionally cheap and deterministic; the LLM
review is layered on top of the rule results (see `auditor.py`).

The finding gate (:func:`evaluate_finding_gate`) is the part that matters
for evidence integrity. It runs *before* the LLM and cannot be overridden
by it:

* a finding needs at least one defect-level evidence (sink / control_flow
  / crash) anchored to a real location - attack-surface facts (IOCTL
  constants, device names, imported primitives) are never enough;
* a finding needs at least one dynamic (E2+) evidence, or an E1 evidence
  anchored to a real location;
* findings without a usable location / trigger condition top out at
  ``inconclusive``;
* import-table-only support tops out at ``inconclusive``.

A failed gate rule is a *veto*: the auditor returns ``inconclusive``
without spending an LLM call.
"""

from dataclasses import dataclass
from typing import Callable, Mapping

from ..evidence.strength import (
    effective_evidence_strength,
    evidence_is_import_only,
    evidence_kind,
    evidence_proves_defect,
    is_import_location,
    is_placeholder_location,
    is_real_location,
    strength_rank,
)
from ..models.common import EvidenceStrength
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


# --- Deterministic finding gate (vetoes pass; LLM cannot override) ---

@dataclass(frozen=True)
class FindingGateResult:
    rule_hits: list[QARuleHit]

    @property
    def blocked(self) -> bool:
        return any(not h.passed for h in self.rule_hits)

    @property
    def reasons(self) -> list[str]:
        return [
            f"deterministic veto: {h.rule_id} ({h.detail})"
            for h in self.rule_hits
            if not h.passed
        ]


def _evidence_location(
    ev: Evidence, locations: Mapping[str, str | None] | None
) -> str | None:
    if locations:
        loc = locations.get(ev.id)
        if loc:
            return loc
    return getattr(ev, "location", None)


def rule_finding_supporting_strength(
    f: Finding,
    evidences: list[Evidence],
    evidence_locations: Mapping[str, str | None] | None = None,
) -> QARuleHit:
    """At least one E2+ evidence, or an E1 with a real location.

    Effective strength is re-derived from facts, so caller-claimed grades
    cannot outrank what the evidence actually shows. Import-only material
    is capped at E1 by the derivation helper.
    """
    rid = "finding.supporting_strength"
    effective: dict[str, str] = {}
    qualifying: list[str] = []
    for ev in evidences:
        loc = _evidence_location(ev, evidence_locations)
        eff = effective_evidence_strength(ev, loc)
        effective[ev.id] = eff.value
        if strength_rank(eff) >= strength_rank(EvidenceStrength.E2):
            qualifying.append(ev.id)
        elif eff == EvidenceStrength.E1 and is_real_location(loc):
            qualifying.append(ev.id)

    if not evidences:
        return _hit(
            rid,
            "Finding must cite at least one verifiable evidence object.",
            False,
            detail="no evidence objects supplied to QA",
        )
    return _hit(
        rid,
        "Finding needs one E2+ (dynamic) evidence, or one E1 evidence with a real location.",
        bool(qualifying),
        detail=f"effective={effective} qualifying={qualifying}",
    )


def rule_finding_location_known(
    f: Finding, supplied_location: str | None = None
) -> QARuleHit:
    """Location / trigger_condition must not be empty or a placeholder."""
    rid = "finding.location_known"
    declared = [
        value
        for value in (getattr(f, "location", None), f.trigger_condition)
        if value is not None and str(value).strip()
    ]
    if any(is_placeholder_location(value) for value in declared):
        return _hit(
            rid,
            "Finding location / trigger_condition must not be unknown/null.",
            False,
            detail=f"declared={declared}",
        )
    effective = declared[0] if declared else supplied_location
    if not effective or is_placeholder_location(effective):
        return _hit(
            rid,
            "Finding must record a location / trigger_condition.",
            False,
            detail=f"location={effective!r} supplied={supplied_location!r}",
        )
    if is_import_location(effective):
        return _hit(
            rid,
            "Finding location must identify code, not an import-table name.",
            False,
            detail=f"location={effective!r}",
        )
    return _hit(
        rid,
        "Finding records a usable location / trigger_condition.",
        True,
        detail=f"location={effective!r}",
    )


def rule_finding_defect_evidence(
    f: Finding,
    evidences: list[Evidence],
    evidence_locations: Mapping[str, str | None] | None = None,
) -> QARuleHit:
    """At least one evidence must establish a concrete defect mechanism.

    Attack-surface material - an IOCTL constant, a device name, an
    imported ``IoCreateDevice`` / ``RtlCopyMemory``, a MajorFunction
    store - is real evidence *of the attack surface*.  It does not show
    that any code path mishandles attacker input, so a finding resting on
    it alone tops out at ``inconclusive`` regardless of how real its
    addresses are.

    Qualifying kinds are :data:`dra.evidence.kinds.DEFECT_KINDS`: a sink
    call site, a control-flow / missing-check path, or a real crash
    stack.  Each must be anchored to a real location and be E1+ after
    re-derivation (a model opinion never qualifies).
    """
    rid = "finding.defect_evidence"
    if not evidences:
        return _hit(
            rid,
            "Finding needs one defect-level evidence (sink / control_flow / crash).",
            False,
            detail="no evidence objects supplied to QA",
        )
    cited = set(f.evidence_ids)
    kinds: dict[str, str] = {}
    qualifying: list[str] = []
    for ev in evidences:
        loc = _evidence_location(ev, evidence_locations)
        kinds[ev.id] = evidence_kind(ev).value
        # The finding must cite the defect evidence; a defect record that
        # merely sits in the evidence store does not support this finding.
        if ev.id in cited and evidence_proves_defect(ev, loc):
            qualifying.append(ev.id)
    return _hit(
        rid,
        "Finding needs one cited defect-level evidence (sink / control_flow / "
        "crash) anchored to a real location; attack-surface facts are not enough.",
        bool(qualifying),
        detail=f"kinds={kinds} cited={sorted(cited)} qualifying={qualifying}",
    )


def rule_finding_not_import_only(
    f: Finding,
    evidences: list[Evidence],
    evidence_locations: Mapping[str, str | None] | None = None,
) -> QARuleHit:
    """A finding supported only by import names tops out at inconclusive."""
    rid = "finding.not_import_only"
    if not evidences:
        return _hit(
            rid,
            "Finding must not rest solely on import-table evidence.",
            False,
            detail="no evidence objects supplied to QA",
        )
    flags = {
        ev.id: evidence_is_import_only(ev, _evidence_location(ev, evidence_locations))
        for ev in evidences
    }
    passed = any(not flag for flag in flags.values())
    return _hit(
        rid,
        "Finding must not rest solely on import-table evidence.",
        passed,
        detail=f"import_only={flags}",
    )


def evaluate_finding_gate(
    finding: Finding,
    evidences: list[Evidence] | None = None,
    *,
    finding_location: str | None = None,
    evidence_locations: Mapping[str, str | None] | None = None,
) -> FindingGateResult:
    """Run every deterministic veto rule for a finding."""
    evs = list(evidences or [])
    return FindingGateResult(
        rule_hits=[
            rule_finding_location_known(finding, finding_location),
            rule_finding_defect_evidence(finding, evs, evidence_locations),
            rule_finding_supporting_strength(finding, evs, evidence_locations),
            rule_finding_not_import_only(finding, evs, evidence_locations),
        ]
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
