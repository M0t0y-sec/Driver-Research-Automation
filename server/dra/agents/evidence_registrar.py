"""Evidence Registrar Agent."""

from ..agents._ops import AgentOps
from ..graph.state import ResearchState
from ..models.common import EvidenceStrength


async def evidence_registrar_node(state: ResearchState, ops: AgentOps) -> dict:
    obs_ids: list[str] = state.get("observation_ids", [])
    hyp_ids: list[str] = state.get("hypothesis_ids", [])
    new_evidence = []
    for oid in obs_ids:
        o = ops.observations.get(oid)
        if o is None:
            continue
        ev = ops.evidence.register(
            project_id=state["project_id"],
            evidence_type="static_observation",
            producer_agent="recon",
            target_id=o.target_id,
            source_artifact_hash=state.get("pe_report_sha") or "0" * 64,
            tool_version="0.1.0",
            confidence=o.confidence,
            evidence_strength=EvidenceStrength.E1,
            summary=o.description,
            lineage_ids=[o.target_id, o.id],
        )
        new_evidence.append(ev)
    for hid in hyp_ids:
        h = ops.hypotheses.get(hid)
        if h is None:
            continue
        ev = ops.evidence.register(
            project_id=state["project_id"],
            evidence_type="hypothesis_rule_signal",
            producer_agent="hypothesis",
            target_id=h.target_id,
            source_artifact_hash=state.get("pe_report_sha") or "0" * 64,
            tool_version="0.1.1",
            confidence="medium",
            evidence_strength=EvidenceStrength.E3,
            related_hypothesis_id=h.id,
            summary=h.description,
            lineage_ids=[h.target_id, h.id] + list(h.observation_ids),
        )
        new_evidence.append(ev)
    return {
        "evidence_ids": state.get("evidence_ids", []) + [e.id for e in new_evidence],
        "current_phase": "qa",
        "current_node": "evidence_registrar",
    }
