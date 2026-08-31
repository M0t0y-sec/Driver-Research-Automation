from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from .common import RiskLevel, utc_now

ApprovalDecision = Literal["pending", "approved", "rejected", "auto_approved", "expired"]


class Approval(BaseModel):
    id: str
    project_id: str
    requester: str  # agent or user
    tool_run_id: str | None = None
    tool: str
    risk_level: RiskLevel
    justification: str
    parameters: dict = Field(default_factory=dict)
    decision: ApprovalDecision = "pending"
    decided_by: str | None = None
    decided_at: str | None = None
    expires_at: str | None = None
    notes: str | None = None
    created_at: str = Field(default_factory=lambda: utc_now().isoformat())
