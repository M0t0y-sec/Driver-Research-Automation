"""Explicit error types for the LLM layer.

The platform treats every model response as untrusted input. A failed
call must fail loudly: callers get an exception, never a silently
defaulted payload that could later be mistaken for a model conclusion.
"""
from __future__ import annotations


class LLMError(RuntimeError):
    """Base class for all LLM-layer failures."""


class LLMConfigurationError(LLMError):
    """Provider/model configuration is missing or invalid."""


class LLMProviderError(LLMError):
    """The upstream provider call failed (network, auth, rate limit, 5xx)."""


class LLMRefusalError(LLMProviderError):
    """The model declined the request (``stop_reason == "refusal"``)."""


class LLMOutputError(LLMError):
    """Model output was not usable JSON after one repair attempt.

    Carries the offending text so the caller (or auditor) can persist it
    instead of guessing at a replacement payload.
    """

    def __init__(
        self,
        message: str,
        *,
        raw_text: str = "",
        schema_error: str | None = None,
    ) -> None:
        super().__init__(message)
        self.raw_text = raw_text
        self.schema_error = schema_error
