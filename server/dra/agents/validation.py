"""Validation Agent (Phase 0/1 stub)."""
from __future__ import annotations

from ..agents._ops import AgentOps
from ..graph.state import ResearchState


async def validation_node(state: ResearchState, ops: AgentOps) -> dict:
    return {
        "current_phase": "triage",
        "current_node": "validation",
        "validation_skipped": True,
    }
