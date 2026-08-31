from __future__ import annotations

from pydantic import BaseModel, Field

from .attack_surface import AttackActor
from .common import HypothesisStatus, utc_now


class HypothesisScoreBreakdown(BaseModel):
    """Each component is 0.0 - 1.0. Final priority is product (or human override)."""
    impact: float = 0.0
    confidence: float = 0.0
    reachability: float = 0.0
    testability: float = 0.0
    rule_score: float = 0.0
    model_explanation: str = ""
    human_calibration: float | None = None
    uncertainty: str | None = None
    feature_signals: dict[str, float] = Field(default_factory=dict)


class Hypothesis(BaseModel):
    id: str
    project_id: str
    target_id: str
    category: str  # memory_safety, privilege, info_disclosure, logic, race, input_validation
    location: str | None = None
    source: str | None = None
    sink: str | None = None
    description: str
    evidence_ids: list[str] = Field(default_factory=list)
    observation_ids: list[str] = Field(default_factory=list)
    attack_surface_item_ids: list[str] = Field(default_factory=list)
    related_attack_actor: AttackActor = "unprivileged_local_user"
    confidence: float = 0.0
    priority: float = 0.0
    priority_breakdown: HypothesisScoreBreakdown = Field(default_factory=HypothesisScoreBreakdown)
    requires_human_review: bool = False
    validation_required: bool = True
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    created_at: str = Field(default_factory=lambda: utc_now().isoformat())
