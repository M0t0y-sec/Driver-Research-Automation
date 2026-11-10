"""LLM client layer.

The platform treats the LLM as an untrusted, opaque, structured-output
producer. All calls go through the router (`LLMRouter`), which selects a
model tier and temperature per task.

`build_llm_router()` is the composition helper: it reads
`DRA_LLM_PROVIDER` (`mock` | `anthropic`) and returns a router around
either the deterministic `MockLLMClient` or the real
`AnthropicLLMClient`. Missing credentials fall back to the mock with a
visible warning rather than failing at request time.
"""
from .anthropic_client import AnthropicLLMClient
from .base import LLMClient, LLMMessage, LLMResponse, LLMTask, ModelTier
from .errors import (
    LLMConfigurationError,
    LLMError,
    LLMOutputError,
    LLMProviderError,
    LLMRefusalError,
)
from .factory import build_llm_client, build_llm_router
from .mock import MockLLMClient
from .router import LLMRouter, ROUTING_TABLE
from .schemas import TASK_CONTRACTS, contract_for, json_schema_for

__all__ = [
    "LLMClient",
    "LLMMessage",
    "LLMResponse",
    "LLMTask",
    "ModelTier",
    "MockLLMClient",
    "AnthropicLLMClient",
    "LLMRouter",
    "ROUTING_TABLE",
    "build_llm_client",
    "build_llm_router",
    "LLMError",
    "LLMConfigurationError",
    "LLMProviderError",
    "LLMRefusalError",
    "LLMOutputError",
    "TASK_CONTRACTS",
    "contract_for",
    "json_schema_for",
]
