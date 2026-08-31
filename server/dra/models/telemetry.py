from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from .common import utc_now

TelemetryChannel = Literal[
    "process", "image_load", "driver", "file", "registry", "network", "etw", "event_log", "product"
]


class TelemetryEvent(BaseModel):
    id: str
    execution_id: str
    channel: TelemetryChannel
    timestamp: str
    event_type: str
    data: dict
    severity: str | None = None
    raw_excerpt: str | None = None


class TelemetryBatch(BaseModel):
    id: str
    project_id: str
    execution_id: str
    events: list[TelemetryEvent] = Field(default_factory=list)
    visibility_passed: bool = False
    collected_at: str = Field(default_factory=lambda: utc_now().isoformat())
