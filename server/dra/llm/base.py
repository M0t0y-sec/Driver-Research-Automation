"""LLM client base types."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol


class ModelTier(str, Enum):
    SMALL = "small"  # classification, extraction, JSON repair
    MID = "mid"      # static analysis summary, code explanation
    LARGE = "large"  # cross-function reasoning, hypothesis generation, QA


class LLMTask(str, Enum):
    TOOL_OUTPUT_PARSE = "tool_output_parse"
    JSON_REPAIR = "json_repair"
    LABEL_EXTRACT = "label_extract"
    STATIC_SUMMARY = "static_summary"
    CODE_EXPLAIN = "code_explain"
    CROSS_FN_REASON = "cross_fn_reason"
    HYPOTHESIS_GEN = "hypothesis_gen"
    EXPERIMENT_DESIGN = "experiment_design"
    QA_REVIEW = "qa_review"
    DETECTION_GAP = "detection_gap"
    REPORT_GEN = "report_gen"
    EMBEDDING = "embedding"


@dataclass
class LLMMessage:
    role: str  # "system" | "user" | "assistant"
    content: str


@dataclass
class LLMResponse:
    content: str
    structured: dict | None = None
    model: str = "mock"
    temperature: float = 0.0
    usage: dict = field(default_factory=dict)
    raw: Any = None


class LLMClient(Protocol):
    """Single-call client interface. Implementations may stream; the
    caller only consumes the final structured response."""

    def complete(
        self,
        messages: list[LLMMessage],
        *,
        task: LLMTask,
        response_schema: dict | None = None,
        temperature: float | None = None,
    ) -> LLMResponse: ...
