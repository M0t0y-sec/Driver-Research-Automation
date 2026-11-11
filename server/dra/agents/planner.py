"""Planner Agent.

Decides what to do next at a coarse level. In Phase 0/1 it is a
no-op placeholder that simply records a research plan and moves on.
Phase 2+ will use the LLM to produce a structured plan.
"""

from ..agents._ops import AgentOps
from ..graph.state import ResearchState


async def planner_node(state: ResearchState, ops: AgentOps) -> dict:
    # Project authorization check
    project = ops.projects.get(state["project_id"])
    if project is None:
        raise KeyError(f"project {state['project_id']} not found")
    # ProjectStore returns dicts in Phase 0/1; adapt to the authz contract.
    authorized = bool(project.get("authorized_use", False))
    if not authorized:
        raise PermissionError(
            f"project {state['project_id']} is not marked authorized_use=true; "
            f"set the flag or provide a valid authorization_ref."
        )

    plan = {
        "id": state.get("plan_id") or f"PLAN-{state['research_id']}",
        "phases": ["recon", "static_summary", "attack_surface", "hypothesis", "ranking", "evidence", "qa", "report"],
        "auto_advance": True,
        "notes": "(mock) planner ran",
    }
    return {
        "plan_id": plan["id"],
        "plan_payload": plan,
        "current_phase": "recon",
        "current_node": "planner",
    }
