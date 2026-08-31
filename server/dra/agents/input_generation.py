"""Input Generation Agent (Phase 0/1 stub)."""
from __future__ import annotations

from ..agents._ops import AgentOps
from ..graph.state import ResearchState


async def input_generation_node(state: ResearchState, ops: AgentOps) -> dict:
    return {
        "test_case_set_ids": state.get("test_case_set_ids", []),
        "current_phase": "experiment_plan",
        "current_node": "input_generation",
    }
