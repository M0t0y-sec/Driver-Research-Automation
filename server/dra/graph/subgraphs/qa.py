"""QA subgraph.

Phase 0/1 wires the QA Auditor node into the main research graph
directly, so this subgraph is a placeholder for the future split
when QA gets its own retries / counter-examples.
"""

from langgraph.graph import END, START, StateGraph

from ...agents import AgentOps, build_ops, qa_auditor_node
from ..state import ResearchState


def _bind(ops: AgentOps, fn):
    async def wrapper(state: ResearchState) -> dict:
        return await fn(state, ops)

    return wrapper


def build_qa_subgraph(ops: AgentOps | None = None) -> StateGraph:
    ops = ops or build_ops()
    g = StateGraph(ResearchState)
    g.add_node("qa_auditor", _bind(ops, qa_auditor_node))
    g.add_edge(START, "qa_auditor")
    g.add_edge("qa_auditor", END)
    return g
