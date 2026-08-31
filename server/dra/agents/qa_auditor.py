"""QA Auditor Agent."""
from __future__ import annotations

from ..agents._ops import AgentOps
from ..graph.state import ResearchState
from ..models.common import FindingStatus, IDPrefix, new_id
from ..models.finding import Finding


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
        evidence_ids=ev_ids[:8],
        lineage_ids=[target_id] + list(h.observation_ids) + [h.id] + ev_ids[:8],
        limitations=[
            "Phase 0/1: static research only. No execution / Lab / dynamic validation.",
            "No reverse engineering performed beyond PE import scrape.",
            "No detection evaluation. Verdict not assessed.",
        ],
        status=FindingStatus.CANDIDATE,
    )
    ops.findings.add(finding)
    review = ops.qa.review_finding(finding, evidences=[ops.evidence.get(e) for e in ev_ids if e])
    finding.qa_status = review.decision.value
    finding.qa_review_id = review.id
    if review.decision.value == "pass":
        finding.status = FindingStatus.QA_PASS
    elif review.decision.value == "retry":
        finding.status = FindingStatus.EVIDENCE_REVIEW
    elif review.decision.value == "reject":
        finding.status = FindingStatus.FALSE_POSITIVE
    else:
        finding.status = FindingStatus.NEEDS_HUMAN
    ops.findings.add(finding)
    return {
        "finding_ids": state.get("finding_ids", []) + [finding.id],
        "qa_review_ids": state.get("qa_review_ids", []) + [review.id],
        "current_phase": "report",
        "current_node": "qa_auditor",
    }
