"""Validation Agent.

Phase 0/1 does not execute experiments.  Its one real job here is to
make crash records produced elsewhere (the lab provider, a manual
recording, an imported batch) visible to triage: if the caller did not
pass ``crash_ids`` in state, look for crash records belonging to this
research run in the crash store.

No crash is fabricated.  With no crash records, the node reports
``validation_skipped=True`` and the downstream triage nodes become no-ops.
"""

from ..agents._ops import AgentOps
from ..graph.state import ResearchState


async def validation_node(state: ResearchState, ops: AgentOps) -> dict:
    crash_ids = list(state.get("crash_ids", []))
    notes = list(state.get("crash_analysis_notes", []))
    project_id = state.get("project_id")
    research_id = state.get("research_id")

    if not crash_ids and project_id and research_id:
        discovered = [
            crash.id
            for crash in ops.crashes.list(project_id=project_id, research_id=research_id)
        ]
        crash_ids = [cid for cid in discovered if cid]

    return {
        "current_phase": "triage",
        "current_node": "validation",
        "validation_skipped": not bool(crash_ids),
        "crash_ids": crash_ids,
        "crash_analysis_notes": notes,
    }
