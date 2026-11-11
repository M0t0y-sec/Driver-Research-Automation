"""Hypothesis / Experiment / Finding / Evidence / Approval / Tool-Run routers.

All read-only; the writers are the graph nodes + the tool gateway.
Phase 2+ adds mutation endpoints gated by authorisation.
"""

from fastapi import APIRouter, HTTPException

from ..config import SETTINGS
from ..evidence.lineage import LineageBuilder
from ..storage.filesystem import (
    ApprovalStore,
    DetectionStore,
    EvidenceStore,
    ExperimentStore,
    FindingStore,
    HypothesisStore,
    QAReviewStore,
    RobustnessStore,
    TargetStore,
    ToolRunStore,
    VisibilityStore,
)

router = APIRouter(tags=["read"])


@router.get("/hypotheses")
def list_hypotheses(project_id: str | None = None) -> list[dict]:
    items = HypothesisStore(SETTINGS.data_dir / "hypotheses").list()
    if project_id is not None:
        items = [h for h in items if h.project_id == project_id]
    return [h.model_dump(mode="json") for h in items]


@router.get("/hypotheses/{hypothesis_id}")
def get_hypothesis(hypothesis_id: str) -> dict:
    h = HypothesisStore(SETTINGS.data_dir / "hypotheses").get(hypothesis_id)
    if h is None:
        raise HTTPException(404, "hypothesis not found")
    return h.model_dump(mode="json")


@router.get("/experiments")
def list_experiments(project_id: str | None = None) -> list[dict]:
    items = ExperimentStore(SETTINGS.data_dir / "experiments").list()
    if project_id is not None:
        items = [e for e in items if e.project_id == project_id]
    return [e.model_dump(mode="json") for e in items]


@router.get("/findings")
def list_findings(project_id: str | None = None) -> list[dict]:
    items = FindingStore(SETTINGS.findings_dir).list()
    if project_id is not None:
        items = [f for f in items if f.project_id == project_id]
    return [f.model_dump(mode="json") for f in items]


@router.get("/findings/{finding_id}")
def get_finding(finding_id: str) -> dict:
    f = FindingStore(SETTINGS.findings_dir).get(finding_id)
    if f is None:
        raise HTTPException(404, "finding not found")
    return f.model_dump(mode="json")


@router.get("/findings/{finding_id}/evidence-chain")
def finding_evidence_chain(finding_id: str) -> dict:
    f = FindingStore(SETTINGS.findings_dir).get(finding_id)
    if f is None:
        raise HTTPException(404, "finding not found")
    evidences = [EvidenceStore(SETTINGS.evidence_dir).get(eid) for eid in f.evidence_ids]
    evidences = [e for e in evidences if e is not None]
    chain = LineageBuilder.from_finding(f, evidences)
    return {
        "finding": f.model_dump(mode="json"),
        "evidences": [e.model_dump(mode="json") for e in evidences],
        "lineage": chain,
    }


@router.get("/findings/{finding_id}/replay-bundle")
def finding_replay_bundle(finding_id: str) -> dict:
    """Phase 0/1 placeholder: bundle the IDs and stored entity snapshots.

    Real replay execution is Phase 2+.
    """
    f = FindingStore(SETTINGS.findings_dir).get(finding_id)
    if f is None:
        raise HTTPException(404, "finding not found")
    return {
        "finding": f.model_dump(mode="json"),
        "replay_supported": False,
        "reason": "Phase 0/1: real replay execution not yet implemented.",
    }


@router.get("/evidence")
def list_evidence(project_id: str | None = None) -> list[dict]:
    items = EvidenceStore(SETTINGS.evidence_dir).list()
    if project_id is not None:
        items = [e for e in items if e.project_id == project_id]
    return [e.model_dump(mode="json") for e in items]


@router.get("/evidence/{evidence_id}")
def get_evidence(evidence_id: str) -> dict:
    e = EvidenceStore(SETTINGS.evidence_dir).get(evidence_id)
    if e is None:
        raise HTTPException(404, "evidence not found")
    return e.model_dump(mode="json")


@router.get("/qa-reviews")
def list_qa_reviews(project_id: str | None = None) -> list[dict]:
    items = QAReviewStore(SETTINGS.data_dir / "qa_reviews").list()
    if project_id is not None:
        items = [q for q in items if q.project_id == project_id]
    return [q.model_dump(mode="json") for q in items]


@router.get("/approvals")
def list_approvals(project_id: str | None = None) -> list[dict]:
    items = ApprovalStore(SETTINGS.approvals_dir).list()
    if project_id is not None:
        items = [a for a in items if a.project_id == project_id]
    return [a.model_dump(mode="json") for a in items]


@router.get("/approvals/pending")
def list_pending_approvals(project_id: str | None = None) -> list[dict]:
    items = [a for a in ApprovalStore(SETTINGS.approvals_dir).list() if a.decision == "pending"]
    if project_id is not None:
        items = [a for a in items if a.project_id == project_id]
    return [a.model_dump(mode="json") for a in items]


@router.post("/approvals/{approval_id}/decide")
def decide_approval(approval_id: str, decision: str, decided_by: str, notes: str | None = None) -> dict:
    from ..tools.approval import ApprovalService
    svc = ApprovalService(ApprovalStore(SETTINGS.approvals_dir))
    a = svc.decide(approval_id, decision=decision, decided_by=decided_by, notes=notes)
    return a.model_dump(mode="json")


@router.get("/tool-runs")
def list_tool_runs(project_id: str | None = None) -> list[dict]:
    items = ToolRunStore(SETTINGS.tool_runs_dir).list()
    if project_id is not None:
        items = [r for r in items if r.project_id == project_id]
    return [r.model_dump(mode="json") for r in items]


@router.get("/tool-runs/{run_id}")
def get_tool_run(run_id: str) -> dict:
    r = ToolRunStore(SETTINGS.tool_runs_dir).get(run_id)
    if r is None:
        raise HTTPException(404, "tool run not found")
    return r.model_dump(mode="json")


# --- Detection / Visibility / Robustness (read-only, Phase 0/1 stub data) ---

@router.get("/visibility")
def list_visibility(project_id: str | None = None) -> list[dict]:
    items = VisibilityStore(SETTINGS.data_dir / "visibility").list()
    if project_id is not None:
        items = [v for v in items if v.project_id == project_id]
    return [v.model_dump(mode="json") for v in items]


@router.get("/detection-results")
def list_detection(project_id: str | None = None) -> list[dict]:
    items = DetectionStore(SETTINGS.data_dir / "detection").list()
    if project_id is not None:
        items = [d for d in items if d.project_id == project_id]
    return [d.model_dump(mode="json") for d in items]


@router.get("/robustness-results")
def list_robustness(project_id: str | None = None) -> list[dict]:
    items = RobustnessStore(SETTINGS.data_dir / "robustness").list()
    if project_id is not None:
        items = [r for r in items if r.project_id == project_id]
    return [r.model_dump(mode="json") for r in items]
