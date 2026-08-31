"""Dashboard summary endpoint."""
from __future__ import annotations

from fastapi import APIRouter

from ..config import SETTINGS
from ..storage.filesystem import (
    ApprovalStore,
    EvidenceStore,
    FindingStore,
    HypothesisStore,
    ProjectStore,
    QAReviewStore,
    ResearchStore,
    TargetStore,
    ToolRunStore,
)

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("")
def dashboard() -> dict:
    return {
        "projects": ProjectStore(SETTINGS.projects_dir).count(),
        "targets": TargetStore(SETTINGS.targets_dir).count(),
        "research_runs": ResearchStore(SETTINGS.research_dir).count(),
        "hypotheses": HypothesisStore(SETTINGS.data_dir / "hypotheses").count(),
        "evidence": EvidenceStore(SETTINGS.evidence_dir).count(),
        "findings": FindingStore(SETTINGS.findings_dir).count(),
        "qa_reviews": QAReviewStore(SETTINGS.data_dir / "qa_reviews").count(),
        "tool_runs": ToolRunStore(SETTINGS.tool_runs_dir).count(),
        "pending_approvals": len([a for a in ApprovalStore(SETTINGS.approvals_dir).list() if a.decision == "pending"]),
    }
