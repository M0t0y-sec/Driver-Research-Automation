from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from .common import utc_now

AttackVector = Literal["local", "adjacent", "network", "physical"]
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
