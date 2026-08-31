"""LLM client layer.

The platform treats the LLM as an untrusted, opaque, structured-output
producer. All calls go through the router (`LLMRouter`), which selects
a model tier and temperature per task. Real provider implementations
are stubbed; a deterministic `MockLLMClient` lets the pipeline run
end-to-end in Phase 0/1.
"""
from .base import LLMClient, LLMMessage, LLMResponse, LLMTask, ModelTier
from .mock import MockLLMClient
from .router import LLMRouter, ROUTING_TABLE

__all__ = [
    "LLMClient",
    "LLMMessage",
    "LLMResponse",
    "LLMTask",
    "ModelTier",
    "MockLLMClient",
    "LLMRouter",
    "ROUTING_TABLE",
]
