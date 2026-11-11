
from typing import Literal

from pydantic import BaseModel, Field

from .common import utc_now

CrashClassification = Literal[
    "null_deref",
    "use_after_free",
    "out_of_bound",
    "pool_corruption",
    "race",
    "input_validation",
    "assertion",
    "env_anomaly",
    "third_party",
    "os_component",
    "unexploitable",
    "exploitable_memory",
    "privilege_boundary",
    "info_disclosure",
    "logic",
    "invalid_memory_access",
    "integer_overflow",
    "stack_overflow",
    "control_flow",
    "uninit_memory",
    "unknown",
]


class Crash(BaseModel):
    """A recorded crash.

    The first block is the Phase 0/1 contract; the fields after it are
    populated by the triage agent from a recorded WinDbg ``!analyze -v``
    text.  Every derived field is optional with a safe default, so an
    older crash record still validates.
    """

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

    # --- research lineage ------------------------------------------------
    research_id: str | None = None

    # --- recorded analysis input ----------------------------------------
    #: Path or artifact hash of the recorded ``!analyze -v`` text.
    analysis_ref: str | None = None
    #: Inline analysis text, for small recordings and tests.  Prefer
    #: ``analysis_ref`` for real dumps.
    analysis_text: str | None = None
    #: ``not_analyzed`` | ``parsed`` | ``partial`` | ``missing_analysis`` |
    #: ``unreadable``
    analysis_status: str = "not_analyzed"

    # --- triage output ---------------------------------------------------
    bugcheck_code: str | None = None
    bugcheck_name: str | None = None
    process_name: str | None = None
    failure_bucket_id: str | None = None
    faulting_module: str | None = None
    faulting_function: str | None = None
    faulting_offset: str | None = None
    #: First stack frame inside the target driver (``mydriver!Dispatch+0x77``).
    target_frame: str | None = None
    attribution: str | None = None
    third_party_modules: list[str] = Field(default_factory=list)
    unknown_fields: list[str] = Field(default_factory=list)
    parse_warnings: list[str] = Field(default_factory=list)
    #: JSON-safe snapshot of the parsed analysis, so later nodes do not
    #: depend on the text file still being readable.
    parsed_analysis: dict = Field(default_factory=dict)

    # --- reproducibility -------------------------------------------------
    #: Explicit value recorded by the lab (``always`` / ``intermittent`` /
    #: ``once``).  When absent, trial counts and ``reproducible`` are used.
    reproducibility: str | None = None
    trial_count: int | None = None
    reproduced_trials: int | None = None

    # --- PoC input (used for controlled-value matching) ------------------
    #: Recorded PoC fields, e.g. ``{"ioctl": "0x222003", "buffer":
    #: "0x4141414141414141"}``.  Only numeric values are compared; this
    #: is evidence input, never executable exploit material.
    poc_input: dict = Field(default_factory=dict)

    # --- downstream links ------------------------------------------------
    analysis_evidence_id: str | None = None
    root_cause_id: str | None = None
    impact_id: str | None = None
    exploitability_id: str | None = None
