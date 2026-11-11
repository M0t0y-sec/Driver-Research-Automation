
from typing import Literal

from pydantic import BaseModel, Field

from .common import utc_now

AttackVector = Literal["local", "adjacent", "network", "physical", "unknown"]
UserInteraction = Literal["none", "passive", "active"]


class SecurityImpact(BaseModel):
    id: str
    project_id: str
    impact_type: str
    privilege_boundary_crossed: bool = False
    confidentiality: Literal["none", "low", "high"] = "none"
    integrity: Literal["none", "low", "high"] = "none"
    availability: Literal["none", "low", "high"] = "none"
    attack_vector: AttackVector = "local"
    required_privilege: str = "unprivileged"
    user_interaction: UserInteraction = "none"
    notes: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: utc_now().isoformat())

    # --- lineage / confidence -------------------------------------------
    crash_id: str | None = None
    root_cause_id: str | None = None
    related_hypothesis_id: str | None = None
    attribution: str = "unknown"
    confidence: Literal["high", "medium", "low"] = "low"
