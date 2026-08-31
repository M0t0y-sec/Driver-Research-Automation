from __future__ import annotations

from pydantic import BaseModel, Field

from .common import utc_now


class VisibilityResult(BaseModel):
    id: str
    project_id: str
    execution_id: str
    process_event_visible: bool = False
    image_load_visible: bool = False
    driver_load_visible: bool = False
    file_event_visible: bool = False
    registry_event_visible: bool = False
    network_event_visible: bool = False
    kernel_callback_visible: bool = False
    etw_available: bool = False
    security_product_logs_available: bool = False
    event_complete: bool = False
    timestamp_aligned: bool = False
    passed: bool = False
    reasons: list[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: utc_now().isoformat())
