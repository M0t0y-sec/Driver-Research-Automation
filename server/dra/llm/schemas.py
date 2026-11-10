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
from __future__ import annotations

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
    score_breakdown: HypothesisScoreBreakdown
    requires_human_review: bool


class HypothesisResponse(_Contract):
    hypotheses: list[HypothesisDraft]


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
# (TOOL_OUTPUT_PARSE, JSON_REPAIR, CROSS_FN_REASON, EXPERIMENT_DESIGN,
# EMBEDDING) either accept arbitrary JSON or have no call site yet; they
# are still parsed as JSON, and one repair attempt is still made.
TASK_CONTRACTS: dict[LLMTask, type[BaseModel]] = {
    LLMTask.HYPOTHESIS_GEN: HypothesisResponse,
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
