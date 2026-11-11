"""Top-level research graph builder."""

from datetime import datetime, timezone

from langgraph.graph import StateGraph

from ..agents import AgentOps, build_ops
from .checkpointer import build_checkpointer
from .state import EMPTY_STATE, ResearchState
from .subgraphs.research import build_research_subgraph


def build_research_graph(ops: AgentOps | None = None, *, checkpointer=None):
    ops = ops or build_ops()
    sub = build_research_subgraph(ops).compile()
    cp = checkpointer or build_checkpointer()
    return _GraphRunner(subgraph=sub, checkpointer=cp, ops=ops)


class _GraphRunner:
    def __init__(self, subgraph, checkpointer, ops: AgentOps) -> None:
        self._subgraph = subgraph
        self._checkpointer = checkpointer
        self._ops = ops

    @property
    def ops(self) -> AgentOps:
        return self._ops

    async def run(
        self,
        *,
        project_id: str,
        target_id: str,
        target_path: str,
        environment_id: str = "ENV-MOCK",
        research_id: str | None = None,
    ) -> ResearchState:
        # Allow the caller to pre-create a research record. We only
        # create a default id if none is supplied.
        if research_id is None:
            research_id = f"RES-{datetime.now(timezone.utc).strftime('%y%m%d%H%M%S')}"
        # Persist a Research record (idempotent — overwrites if exists).
        self._ops.research.add({
            "id": research_id,
            "project_id": project_id,
            "target_id": target_id,
            "environment_id": environment_id,
            "status": "running",
            "current_phase": "planner",
            "started_at": datetime.now(timezone.utc).isoformat(),
        })
        init: ResearchState = {
            **EMPTY_STATE,  # type: ignore[misc]
            "project_id": project_id,
            "research_id": research_id,
            "target_id": target_id,
            "target_path": target_path,
            "environment_id": environment_id,
            "status": "running",
            "current_phase": "planner",
            "current_node": "init",
        }
        config = {"configurable": {"thread_id": research_id}}
        result = await self._subgraph.ainvoke(init, config=config)
        return result


async def run_research(
    *,
    ops: AgentOps,
    project_id: str,
    target_id: str,
    target_path: str,
    research_id: str | None = None,
    environment_id: str = "ENV-MOCK",
) -> ResearchState:
    graph = build_research_graph(ops)
    return await graph.run(
        project_id=project_id,
        target_id=target_id,
        target_path=target_path,
        research_id=research_id,
        environment_id=environment_id,
    )
