
from typing import Literal

from pydantic import BaseModel, Field

from .common import utc_now

ExecutionStatus = Literal[
    "pending", "running", "succeeded", "failed", "timeout", "cancelled", "inconclusive"
]


class Execution(BaseModel):
    id: str
    experiment_id: str
    project_id: str
    environment_id: str
    vm_fingerprint: str
    snapshot_id: str | None = None
    tool_versions: dict[str, str] = Field(default_factory=dict)
    started_at: str | None = None
    finished_at: str | None = None
    status: ExecutionStatus = "pending"
    artifact_refs: list[str] = Field(default_factory=list)
    log_ref: str | None = None
    error: str | None = None
    created_at: str = Field(default_factory=lambda: utc_now().isoformat())
