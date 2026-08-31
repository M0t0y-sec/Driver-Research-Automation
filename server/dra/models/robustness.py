from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from .common import utc_now

RobustnessLevel = Literal["high", "medium", "low"]


class RobustnessResult(BaseModel):
    id: str
    project_id: str
    detection_id: str | None = None
    baseline_detection_rate: float = 0.0
    per_variant_detection_rate: dict[str, float] = Field(default_factory=dict)
    robustness_score: RobustnessLevel = "high"
    weak_dimension: str | None = None  # behavior_correlation | telemetry_signal | rule_coverage | event_correlation | policy_coverage
    variant_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    notes: str | None = None
    created_at: str = Field(default_factory=lambda: utc_now().isoformat())
