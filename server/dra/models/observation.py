
from typing import Literal

from pydantic import BaseModel, Field

from .common import utc_now


ObservationSource = Literal["static", "dynamic", "model_interpretation", "tool_output", "manual"]
ObservationConfidence = Literal["high", "medium", "low"]


class Observation(BaseModel):
    id: str
    target_id: str
    project_id: str
    category: str  # e.g. "ioctl_dispatch", "memory_copy", "privilege_check", "string", "import"
    location: str | None = None  # e.g. "rva:0x12340" or "section:.text"
    description: str
    raw_excerpt: str | None = None
    source: ObservationSource = "static"
    source_tool: str | None = None
    source_method: str | None = None
    tool_version: str | None = None
    confidence: ObservationConfidence = "medium"
    cross_validation: list[str] = Field(default_factory=list)  # other observation IDs
    created_at: str = Field(default_factory=lambda: utc_now().isoformat())
