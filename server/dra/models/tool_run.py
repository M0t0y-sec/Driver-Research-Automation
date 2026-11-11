
from pydantic import BaseModel, Field

from .common import RiskLevel, ToolRunStatus, utc_now


class ToolRun(BaseModel):
    id: str
    request_id: str
    idempotency_key: str
    project_id: str
    target_id: str | None = None
    tool: str
    parameters: dict = Field(default_factory=dict)
    policy_context: dict = Field(default_factory=dict)
    status: ToolRunStatus = ToolRunStatus.QUEUED
    risk_level: RiskLevel = RiskLevel.LOW
    approval_id: str | None = None
    timeout_seconds: int = 3600
    priority: str = "normal"
    tool_version: str | None = None
    result: dict | None = None
    error: str | None = None
    artifact_refs: list[dict] = Field(default_factory=list)
    parameters_hash: str | None = None
    created_at: str = Field(default_factory=lambda: utc_now().isoformat())
    started_at: str | None = None
    finished_at: str | None = None
    audit_log_ref: str | None = None
