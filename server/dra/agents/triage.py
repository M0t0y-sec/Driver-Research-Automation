"""Triage + Root Cause + Impact + Exploitability (Phase 0/1 stubs)."""
from __future__ import annotations

from ..agents._ops import AgentOps
from ..graph.state import ResearchState


async def triage_node(state: ResearchState, ops: AgentOps) -> dict:
    return {"current_phase": "evidence", "current_node": "triage", "triage_done": True}


async def root_cause_node(state: ResearchState, ops: AgentOps) -> dict:
    return {"current_phase": "evidence", "current_node": "root_cause"}


async def impact_node(state: ResearchState, ops: AgentOps) -> dict:
    return {"current_phase": "evidence", "current_node": "impact"}


async def exploitability_node(state: ResearchState, ops: AgentOps) -> dict:
    return {"current_phase": "evidence", "current_node": "exploitability"}
