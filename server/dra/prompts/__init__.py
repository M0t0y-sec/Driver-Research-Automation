"""Versioned prompt templates for the reasoning agents.

Prompts live here instead of inside the agents so they can be reviewed,
diffed and versioned independently of control flow. Agents call the
builder functions and never concatenate prompt text themselves.

Every piece of target- or tool-derived content is passed through
:func:`dra.prompts.common.render_untrusted`, which wraps it in an
``<UNTRUSTED_DATA>`` envelope produced by
:mod:`dra.untrusted.wrapper`. The system prompts state explicitly that
envelope content is data, never instructions.
"""
from __future__ import annotations

from .common import render_untrusted
from .hypothesis import (
    HYPOTHESIS_PROMPT_VERSION,
    HYPOTHESIS_SYSTEM_PROMPT,
    build_hypothesis_messages,
)
from .reverse import (
    REVERSE_PROMPT_VERSION,
    REVERSE_SYSTEM_PROMPT,
    build_reverse_messages,
)

__all__ = [
    "HYPOTHESIS_PROMPT_VERSION",
    "HYPOTHESIS_SYSTEM_PROMPT",
    "REVERSE_PROMPT_VERSION",
    "REVERSE_SYSTEM_PROMPT",
    "build_hypothesis_messages",
    "build_reverse_messages",
    "render_untrusted",
]
