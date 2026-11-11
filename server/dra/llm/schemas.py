"""Pydantic response contracts for the LLM tasks.

Each contract serves two purposes:

* its JSON Schema is sent to the provider through
  ``output_config.format`` so the model is constrained to the shape the
  agents actually consume;
* it validates the parsed payload client-side, because a provider
  guarantee is not a trust boundary.

Fields are required unless the task genuinely allows absence. Defaults
are never substituted for a response that failed validation - the
client raises :class:`dra.llm.errors.LLMOutputError` instead.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .base import LLMTask


class _Contract(BaseModel):
    # Tolerate extra keys during validation (the wire schema forbids them
    # anyway); never coerce a missing required field into a default.
    model_config = ConfigDict(extra="ignore")


class HypothesisScoreBreakdown(_Contract):
    impact: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    reachability: float = Field(ge=0.0, le=1.0)
    testability: float = Field(ge=0.0, le=1.0)
    rule_score: float = Field(ge=0.0, le=1.0)
    model_explanation: str
    uncertainty: Literal["low", "medium", "high"]


class HypothesisDraft(_Contract):
    category: str
    location: str | None
    description: str
    observation_ids: list[str]
    # The falsifiable prediction is required by the hypothesis agent's own
    # policy (a draft without one is discarded), but it stays optional in
    # the schema so older payloads remain valid for the client.
    falsification: str | None = None
    source: str | None = None
    sink: str | None = None
    score_breakdown: HypothesisScoreBreakdown
    requires_human_review: bool


class HypothesisResponse(_Contract):
    # An empty list is a legitimate answer: it means "no observation
    # supports a falsifiable hypothesis". ``reasoning`` carries the why.
    hypotheses: list[HypothesisDraft]
    reasoning: str = ""


class ReverseSink(_Contract):
    kind: Literal["call", "pointer_write", "other"]
    symbol: str | None = None
    instruction_rva: int | None = None
    instruction: str = ""
    length_source: Literal["user_controlled", "constant", "unknown"] = "unknown"
    destination: Literal["stack_buffer", "user_buffer", "kernel_pool", "unknown"] = "unknown"
    probe_for_read: Literal["present", "absent", "unknown"] = "unknown"
    probe_for_write: Literal["present", "absent", "unknown"] = "unknown"
    input_derived: bool | None = None
    guard: str = ""
    confidence: Literal["low", "medium", "high"] = "low"


class ReverseFunction(_Contract):
    function_rva: int | None = None
    role: Literal["dispatch_handler", "helper", "unknown"] = "unknown"
    summary: str = ""
    sinks: list[ReverseSink] = Field(default_factory=list)


class ReverseDataflow(_Contract):
    source: str = ""
    sink: str = ""
    guard: Literal["none", "probe", "bounds_check", "unknown"] = "unknown"
    instruction_rvas: list[int] = Field(default_factory=list)
    summary: str = ""


class ReverseResponse(_Contract):
    functions: list[ReverseFunction]
    dataflow: list[ReverseDataflow]
    not_analyzed: list[str]


class StaticSummaryResponse(_Contract):
    summary: str
    highlights: list[str]


class QAReviewResponse(_Contract):
    decision: Literal["pass", "retry", "reject", "inconclusive"]
    reasons: list[str]
    counter_examples: list[str]


class DetectionGapResponse(_Contract):
    weak_dimension: str
    rationale: str


class ReportSection(_Contract):
    heading: str
    body: str


class ReportResponse(_Contract):
    title: str
    executive_summary: str
    sections: list[ReportSection]


class CodeExplainResponse(_Contract):
    explanation: str


class LabelExtractResponse(_Contract):
    labels: list[str]


# Tasks whose payload has a fixed, consumed shape. Tasks not listed here
# (TOOL_OUTPUT_PARSE, JSON_REPAIR, EXPERIMENT_DESIGN, EMBEDDING) either
# accept arbitrary JSON or have no call site yet; they are still parsed
# as JSON, and one repair attempt is still made.
TASK_CONTRACTS: dict[LLMTask, type[BaseModel]] = {
    LLMTask.HYPOTHESIS_GEN: HypothesisResponse,
    LLMTask.CROSS_FN_REASON: ReverseResponse,
    LLMTask.STATIC_SUMMARY: StaticSummaryResponse,
    LLMTask.QA_REVIEW: QAReviewResponse,
    LLMTask.DETECTION_GAP: DetectionGapResponse,
    LLMTask.REPORT_GEN: ReportResponse,
    LLMTask.CODE_EXPLAIN: CodeExplainResponse,
    LLMTask.LABEL_EXTRACT: LabelExtractResponse,
}


def contract_for(task: LLMTask) -> type[BaseModel] | None:
    """Return the Pydantic contract for ``task``, if one is defined."""
    return TASK_CONTRACTS.get(task)


def json_schema_for(task: LLMTask) -> dict | None:
    """Return the JSON Schema for ``task``'s contract, if one is defined."""
    model = contract_for(task)
    return model.model_json_schema() if model is not None else None


def hypothesis_generation_schema() -> dict:
    """Wire schema for the hypothesis agent's ``HYPOTHESIS_GEN`` call.

    Identical to :class:`HypothesisResponse` except that the model is
    *required* to emit ``reasoning`` and a non-null ``falsification``.
    The base contract keeps those fields optional so older payloads stay
    valid for other callers and tests; the agent asks for them at
    generation time because a draft without a falsifiable prediction is
    discarded anyway.
    """
    import copy

    schema = copy.deepcopy(HypothesisResponse.model_json_schema())
    draft = schema.get("$defs", {}).get("HypothesisDraft", {})
    properties = draft.setdefault("properties", {})
    properties["falsification"] = {"title": "Falsification", "type": "string"}
    required = draft.setdefault("required", [])
    if "falsification" not in required:
        required.append("falsification")
    top_required = schema.setdefault("required", [])
    if "reasoning" not in top_required:
        top_required.append("reasoning")
    return schema
