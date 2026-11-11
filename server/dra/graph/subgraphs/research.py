"""Sub-graph: the static-research pipeline.

Phase 0/1 path:

    planner -> recon -> reverse -> hypothesis -> ranking
           -> input_generation -> experiment_planner
           -> validation -> triage -> root_cause -> impact -> exploitability
           -> evidence_registrar -> telemetry
           -> visibility -> detection -> robustness
           -> qa_auditor -> reporter

Validation ingests recorded crash records for the run.  Triage, Root
Cause, Impact and Exploitability parse the recorded WinDbg
``!analyze -v`` text and write real records (see ``dra.triage``).  When
no crashes exist they are no-ops, so the static-only path is unchanged.
Telemetry, Visibility, Detection and Robustness are still stubs that
advance the state; the real versions wire into Lab + telemetry in
Phase 2+.
"""

from langgraph.graph import END, START, StateGraph

from ...agents import (
    AgentOps,
    build_ops,
    detection_node,
    evidence_registrar_node,
    exploitability_node,
    experiment_planner_node,
    hypothesis_node,
    hypothesis_ranking_node,
    impact_node,
    input_generation_node,
    planner_node,
    qa_auditor_node,
    recon_node,
    reporter_node,
    reverse_node,
    robustness_node,
    root_cause_node,
    telemetry_node,
    triage_node,
    validation_node,
    visibility_node,
)
from ..state import ResearchState


def _bind(ops: AgentOps, fn):
    async def wrapper(state: ResearchState) -> dict:
        return await fn(state, ops)

    return wrapper


def build_research_subgraph(ops: AgentOps | None = None) -> StateGraph:
    ops = ops or build_ops()
    g = StateGraph(ResearchState)

    g.add_node("planner", _bind(ops, planner_node))
    g.add_node("recon", _bind(ops, recon_node))
    g.add_node("reverse", _bind(ops, reverse_node))
    g.add_node("hypothesis", _bind(ops, hypothesis_node))
    g.add_node("hypothesis_ranking", _bind(ops, hypothesis_ranking_node))
    g.add_node("input_generation", _bind(ops, input_generation_node))
    g.add_node("experiment_planner", _bind(ops, experiment_planner_node))
    g.add_node("validation", _bind(ops, validation_node))
    g.add_node("triage", _bind(ops, triage_node))
    g.add_node("root_cause", _bind(ops, root_cause_node))
    g.add_node("impact", _bind(ops, impact_node))
    g.add_node("exploitability", _bind(ops, exploitability_node))
    g.add_node("evidence_registrar", _bind(ops, evidence_registrar_node))
    g.add_node("telemetry", _bind(ops, telemetry_node))
    g.add_node("visibility", _bind(ops, visibility_node))
    g.add_node("detection", _bind(ops, detection_node))
    g.add_node("robustness", _bind(ops, robustness_node))
    g.add_node("qa_auditor", _bind(ops, qa_auditor_node))
    g.add_node("reporter", _bind(ops, reporter_node))

    g.add_edge(START, "planner")
    g.add_edge("planner", "recon")
    g.add_edge("recon", "reverse")
    g.add_edge("reverse", "hypothesis")
    g.add_edge("hypothesis", "hypothesis_ranking")
    g.add_edge("hypothesis_ranking", "input_generation")
    g.add_edge("input_generation", "experiment_planner")
    g.add_edge("experiment_planner", "validation")
    g.add_edge("validation", "triage")
    g.add_edge("triage", "root_cause")
    g.add_edge("root_cause", "impact")
    g.add_edge("impact", "exploitability")
    g.add_edge("exploitability", "evidence_registrar")
    g.add_edge("evidence_registrar", "telemetry")
    g.add_edge("telemetry", "visibility")
    g.add_edge("visibility", "detection")
    g.add_edge("detection", "robustness")
    g.add_edge("robustness", "qa_auditor")
    g.add_edge("qa_auditor", "reporter")
    g.add_edge("reporter", END)

    return g
