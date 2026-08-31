"""Reverse Engineering Agent (helper / summary only in Phase 0/1).

Full Ghidra / IDA integration is Phase 2+. For now this node
synthesises a short human-readable summary of what the RE agent would
say about the imports / strings we already have.
"""
from __future__ import annotations

from ..agents._ops import AgentOps
from ..graph.state import ResearchState
from ..llm.base import LLMMessage, LLMTask


async def reverse_node(state: ResearchState, ops: AgentOps) -> dict:
    observation_ids: list[str] = state.get("observation_ids", [])
    observations = [ops.observations.get(i) for i in observation_ids if i]
    observations = [o for o in observations if o is not None]

    if not observations:
        return {
            "reverse_summary_id": None,
            "current_phase": "hypothesis",
            "current_node": "reverse",
        }

    prompt = (
        "You are the Reverse agent. Summarise the following observations "
        "into a short paragraph suitable for a security analyst.\n"
        + "\n".join(f"- [{o.category}] {o.location}: {o.description}" for o in observations)
    )
    resp = ops.llm.complete(
        [LLMMessage(role="user", content=prompt)],
        task=LLMTask.CODE_EXPLAIN,
    )
    summary_id = f"REV-{state['research_id']}"
    return {
        "reverse_summary_id": summary_id,
        "reverse_summary_text": (resp.structured or {}).get("explanation", ""),
        "current_phase": "hypothesis",
        "current_node": "reverse",
    }
