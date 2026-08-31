from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from .common import utc_now

CrashClassification = Literal[
    "null_deref",
    "use_after_free",
    "out_of_bound",
    "race",
    "input_validation",
    "assertion",
    "env_anomaly",
    "third_party",
    "unexploitable",
    "exploitable_memory",
    "privilege_boundary",
    "info_disclosure",
    "logic",
    "unknown",
]


class Crash(BaseModel):
    id: str
    project_id: str
    execution_id: str
    hypothesis_id: str | None = None
    classification: CrashClassification = "unknown"
    reproducible: bool = False
    related_to_hypothesis: bool = False
    dump_ref: str | None = None
    trace_ref: str | None = None
    summary: str
    created_at: str = Field(default_factory=lambda: utc_now().isoformat())
