"""Task -> model tier + temperature routing.

See integration plan section 16. The table is data, not code: tweak
ROUTING_TABLE without touching any caller.
"""
from __future__ import annotations

from dataclasses import dataclass

from .base import LLMClient, LLMMessage, LLMResponse, LLMTask, ModelTier


@dataclass(frozen=True)
class Route:
    tier: ModelTier
    temperature: float
    model: str = "mock"  # mock by default; real provider sets this


ROUTING_TABLE: dict[LLMTask, Route] = {
    LLMTask.TOOL_OUTPUT_PARSE: Route(ModelTier.SMALL, 0.0),
    LLMTask.JSON_REPAIR: Route(ModelTier.SMALL, 0.0),
    LLMTask.LABEL_EXTRACT: Route(ModelTier.SMALL, 0.0),
    LLMTask.STATIC_SUMMARY: Route(ModelTier.MID, 0.2),
    LLMTask.CODE_EXPLAIN: Route(ModelTier.MID, 0.2),
    LLMTask.CROSS_FN_REASON: Route(ModelTier.LARGE, 0.3),
    LLMTask.HYPOTHESIS_GEN: Route(ModelTier.LARGE, 0.4),
    LLMTask.EXPERIMENT_DESIGN: Route(ModelTier.LARGE, 0.3),
    LLMTask.QA_REVIEW: Route(ModelTier.LARGE, 0.1),
    LLMTask.DETECTION_GAP: Route(ModelTier.MID, 0.2),
    LLMTask.REPORT_GEN: Route(ModelTier.MID, 0.4),
    LLMTask.EMBEDDING: Route(ModelTier.SMALL, 0.0),
}


class LLMRouter:
    def __init__(self, client: LLMClient) -> None:
        self.client = client

    def route(self, task: LLMTask) -> Route:
        return ROUTING_TABLE.get(task, Route(ModelTier.MID, 0.2))

    def complete(
        self,
        messages: list[LLMMessage],
        *,
        task: LLMTask,
        response_schema: dict | None = None,
    ) -> LLMResponse:
        r = self.route(task)
        return self.client.complete(
            messages,
            task=task,
            response_schema=response_schema,
            temperature=r.temperature,
        )
