"""QA Auditor Agent."""
from __future__ import annotations

from ..agents._ops import AgentOps
from ..evidence.strength import (
    evidence_proves_defect,
    is_placeholder_location,
    is_real_location,
)
from ..graph.state import ResearchState
from ..models.common import FindingStatus, IDPrefix, QADecision, new_id
from ..models.evidence import Evidence
from ..models.finding import Finding
from ..models.hypothesis import Hypothesis


def _observation_locations(ops: AgentOps, hypothesis: Hypothesis) -> dict[str, str]:
    """Recover observation locations for the QA gate.

    `Hypothesis.location` is often empty (the hypothesis prompt does not
    carry it), but the underlying observations do. QA is allowed to read
    them; it must not accept a finding without a location.
    """
    out: dict[str, str] = {}
    for obs_id in hypothesis.observation_ids:
        obs = ops.observations.get(obs_id)
        if obs is not None and obs.location:
            out[obs_id] = obs.location
    return out


def _evidence_location(ev: Evidence, observation_locations: dict[str, str]) -> str | None:
    for lineage_id in ev.lineage_ids:
        loc = observation_locations.get(lineage_id)
        if loc:
            return loc
    return getattr(ev, "location", None)


def _resolve_finding_location(
    hypothesis_location: str | None, observation_locations: dict[str, str]
) -> str | None:
    """Prefer a real address; fall back to the first usable location string."""
    candidates = ([hypothesis_location] if hypothesis_location else []) + list(
        observation_locations.values()
    )
    for loc in candidates:
        if loc and is_real_location(loc):
            return loc
    for loc in candidates:
        if loc and not is_placeholder_location(loc):
            return loc
    return None


async def qa_auditor_node(state: ResearchState, ops: AgentOps) -> dict:
    hyp_ids: list[str] = state.get("hypothesis_ids", [])
    ev_ids: list[str] = state.get("evidence_ids", [])
    selected = state.get("selected_hypothesis_ids", [])
    if not hyp_ids:
        return {"finding_ids": [], "current_phase": "report", "current_node": "qa_auditor"}

    top_id = selected[0] if selected else hyp_ids[0]
    h = ops.hypotheses.get(top_id)
    if h is None:
        return {"finding_ids": [], "current_phase": "report", "current_node": "qa_auditor"}

    target_id = h.target_id
    observation_locations = _observation_locations(ops, h)
    finding_location = _resolve_finding_location(h.location, observation_locations)
    trigger_condition = (
        finding_location
        if finding_location and not is_placeholder_location(finding_location)
        else None
    )

    # Evidence is needed *before* the finding is built: the QA gate only
    # passes a finding that cites a defect-level evidence, so the record
    # itself should state when that condition is unmet.
    evidences = [ev for ev in (ops.evidence.get(eid) for eid in ev_ids if eid) if ev is not None]
    evidence_locations = {
        ev.id: _evidence_location(ev, observation_locations) for ev in evidences
    }
    cited_evidence_ids = set(ev_ids[:8])
    defect_evidence_ids = [
        ev.id
        for ev in evidences
        if ev.id in cited_evidence_ids
        and evidence_proves_defect(ev, evidence_locations.get(ev.id))
    ]
    limitations = [
        "Phase 0/1: static research only. No execution / Lab / dynamic validation.",
        "No reverse engineering performed beyond PE import scrape.",
        "No detection evaluation. Verdict not assessed.",
    ]
    if not defect_evidence_ids:
        limitations.append(
            "QA gate: cited evidence establishes attack surface only (no sink / "
            "control-flow / crash evidence); this finding cannot be qa_pass."
        )

    finding = Finding(
        id=new_id(IDPrefix.FINDING),
        project_id=h.project_id,
        target_id=target_id,
        title=h.description[:120] or f"Hypothesis {h.id}",
        summary=h.description,
        vulnerability_class=h.category if h.category in {
            "memory_safety", "privilege", "info_disclosure", "denial_of_service",
            "logic", "input_validation", "race_condition", "other",
        } else "other",
        severity="info",
        trigger_condition=trigger_condition,
        evidence_ids=ev_ids[:8],
        lineage_ids=[target_id] + list(h.observation_ids) + [h.id] + ev_ids[:8],
        limitations=limitations,
        status=FindingStatus.CANDIDATE,
    )
    ops.findings.add(finding)

    review = ops.qa.review_finding(
        finding,
        evidences=evidences,
        finding_location=finding_location,
        evidence_locations=evidence_locations,
    )
    finding.qa_status = review.decision.value
    finding.qa_review_id = review.id
    # Inconclusive is explicitly *not* a pass: it must reach a human.
    if review.decision == QADecision.PASS:
        finding.status = FindingStatus.QA_PASS
    elif review.decision == QADecision.RETRY:
        finding.status = FindingStatus.EVIDENCE_REVIEW
    elif review.decision == QADecision.REJECT:
        finding.status = FindingStatus.FALSE_POSITIVE
    else:  # INCONCLUSIVE (and any future decision) -> human review
        finding.status = FindingStatus.NEEDS_HUMAN
    ops.findings.add(finding)
    return {
        "finding_ids": state.get("finding_ids", []) + [finding.id],
        "qa_review_ids": state.get("qa_review_ids", []) + [review.id],
        "current_phase": "report",
        "current_node": "qa_auditor",
    }
