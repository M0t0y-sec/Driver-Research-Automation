from __future__ import annotations

from pydantic import BaseModel, Field

from .common import utc_now


class AgentRun(BaseModel):
    id: str
    project_id: str
    research_id: str | None = None
    agent: str
    node: str
    started_at: str = Field(default_factory=lambda: utc_now().isoformat())
    finished_at: str | None = None
    status: str = "running"
    inputs: dict = Field(default_factory=dict)
    outputs: dict = Field(default_factory=dict)
    model_version: str | None = None
    prompt_ref: str | None = None
    response_ref: str | None = None
    error: str | None = None
