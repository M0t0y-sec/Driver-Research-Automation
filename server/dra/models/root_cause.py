from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from .common import utc_now

RootCauseCategory = Literal[
    "null_deref",
    "use_after_free",
    "out_of_bound",
    "pool_corruption",
    "race",
    "input_validation",
    "toctou",
    "uninit_memory",
    "integer_overflow",
    "format_string",
    "invalid_memory_access",
    "stack_overflow",
    "control_flow",
    "logic",
    "unknown",
]

#: Who owns the faulting component.  This is the field a vendor triage
#: engineer checks first: a defect in a third-party module or the OS is
#: not a vulnerability in the target driver.
RootCauseAttribution = Literal[
    "target_driver",
    "third_party_driver",
    "os_component",
    "environment",
    "unknown",
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
    # "always" | "intermittent" | "once" | "reproducible" | "unknown".
    # "reproducible" means it reproduced at least once but no trial counts
    # were recorded; it is weaker than "always".
    reproducibility: str
    related_hypothesis_id: str | None = None
    evidence_ids: list[str] = []
    created_at: str = utc_now().isoformat()

    # --- attribution / confidence ---------------------------------------
    attribution: RootCauseAttribution = "unknown"
    confidence: Literal["high", "medium", "low"] = "low"
    bugcheck_code: str | None = None
    failure_bucket_id: str | None = None
    faulting_module: str | None = None

    # --- audit trail -----------------------------------------------------
    #: Structured reasons the classifier used, including the limitations
    #: of the bugcheck (e.g. "pool metadata was corrupted earlier").
    notes: list[str] = Field(default_factory=list)
    #: Fields the recorded analysis did not contain, recorded explicitly
    #: instead of being guessed.
    unknown_fields: list[str] = Field(default_factory=list)
