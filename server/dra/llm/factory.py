"""Provider selection for the LLM layer.

``DRA_LLM_PROVIDER`` chooses the implementation:

* ``mock`` (default) - deterministic, no network, used by the test suite;
* ``anthropic`` - real Claude calls; requires an API key in
  ``DRA_ANTHROPIC_API_KEY`` (falling back to ``ANTHROPIC_API_KEY``).

A configured-but-unusable provider is never silent: we log a loud
warning and fall back to the mock so local runs and CI still work.
"""

import logging

from ..config import SETTINGS, Settings
from .anthropic_client import AnthropicLLMClient
from .base import LLMClient, ModelTier
from .mock import MockLLMClient
from .router import LLMRouter

logger = logging.getLogger("dra.llm.factory")

SUPPORTED_PROVIDERS = ("mock", "anthropic")


def build_llm_client(settings: Settings | None = None) -> LLMClient:
    """Build the configured LLM client, falling back to the mock."""
    settings = settings or SETTINGS
    provider = (settings.llm_provider or "mock").strip().lower()

    if provider == "mock":
        logger.info("LLM provider: mock (deterministic; no network calls)")
        return MockLLMClient()

    if provider != "anthropic":
        logger.warning(
            "Unknown DRA_LLM_PROVIDER=%r; falling back to MockLLMClient. "
            "Supported providers: %s.",
            provider,
            ", ".join(SUPPORTED_PROVIDERS),
        )
        return MockLLMClient()

    if not settings.anthropic_api_key:
        logger.warning(
            "DRA_LLM_PROVIDER=anthropic but no API key was found in "
            "DRA_ANTHROPIC_API_KEY or ANTHROPIC_API_KEY - falling back to "
            "MockLLMClient. AI output will be deterministic placeholders, "
            "NOT real model results."
        )
        return MockLLMClient()

    client = AnthropicLLMClient(
        api_key=settings.anthropic_api_key,
        models={
            ModelTier.SMALL: settings.anthropic_model_small,
            ModelTier.MID: settings.anthropic_model_mid,
            ModelTier.LARGE: settings.anthropic_model_large,
        },
        max_tokens=settings.anthropic_max_tokens,
        timeout=settings.anthropic_timeout_seconds,
        max_retries=settings.anthropic_max_retries,
        api_version=settings.anthropic_api_version,
    )
    logger.info(
        "LLM provider: anthropic (small=%s, mid=%s, large=%s)",
        settings.anthropic_model_small,
        settings.anthropic_model_mid,
        settings.anthropic_model_large,
    )
    return client


def build_llm_router(settings: Settings | None = None) -> LLMRouter:
    """Build a router around the configured client."""
    return LLMRouter(build_llm_client(settings))
