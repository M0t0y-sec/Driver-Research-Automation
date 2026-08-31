"""Context Builder.

Each agent sees only the slice of state it needs. This is also the
single point where the untrusted wrapper is applied to anything that
came from a sample / tool output / log / dump before it is shown to
the LLM.
"""
from __future__ import annotations

from typing import Any

from ..agents._ops import AgentOps
from ..untrusted.wrapper import untrusted_wrap
from .state import ResearchState


def build_node_context(state: ResearchState, ops: AgentOps) -> dict:
    """Return a context dict the agent can pass to its LLM calls."""
    return {
        "project_id": state.get("project_id"),
        "target_id": state.get("target_id"),
        "observation_ids": list(state.get("observation_ids", [])),
        "evidence_ids": list(state.get("evidence_ids", [])),
        "hypothesis_ids": list(state.get("hypothesis_ids", [])),
    }


def wrap_untrusted(value: Any, *, source: str) -> dict:
    """Public helper to wrap any external value into the untrusted envelope."""
    return untrusted_wrap(value, source=source)
