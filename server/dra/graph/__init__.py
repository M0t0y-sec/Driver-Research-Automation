"""LangGraph layer.

The state, checkpointer and context builder are exposed at import
time. The main graph builder is *not* imported here to avoid a
circular dependency with `dra.agents`; callers do
`from dra.graph.main_graph import build_research_graph`.
"""
from .state import ResearchState, EMPTY_STATE
from .checkpointer import build_checkpointer
from .context import build_node_context

__all__ = [
    "ResearchState",
    "EMPTY_STATE",
    "build_checkpointer",
    "build_node_context",
]
