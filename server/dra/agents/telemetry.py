"""Telemetry Agent (Phase 0/1 stub)."""

from ..agents._ops import AgentOps
from ..graph.state import ResearchState


async def telemetry_node(state: ResearchState, ops: AgentOps) -> dict:
    return {
        "current_phase": "detection",
        "current_node": "telemetry",
    }
