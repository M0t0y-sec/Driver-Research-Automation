from __future__ import annotations

from typing import Literal

from pydantic import BaseModel

from .common import utc_now

RootCauseCategory = Literal[
    "null_deref", "use_after_free", "out_of_bound", "race", "input_validation",
    "toctou", "uninit_memory", "integer_overflow", "format_string", "logic",
]


class RootCause(BaseModel):
    id: str
    project_id: str
    crash_id: str | None = None
    category: RootCauseCategory
    function: str | None = None
    instruction_region: str | None = None
    input_field: str | None = None
    trigger_condition: str
    reproducibility: str  # "always" | "intermittent" | "once"
    related_hypothesis_id: str | None = None
    evidence_ids: list[str] = []
    created_at: str = utc_now().isoformat()
