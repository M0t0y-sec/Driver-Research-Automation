"""Hypothesis Agent + Hypothesis Ranking.

Generates candidate hypotheses from observations + attack surface,
then computes a `priority_breakdown` for each.
"""
from __future__ import annotations

from ..agents._ops import AgentOps
from ..graph.state import ResearchState
from ..llm.base import LLMMessage, LLMTask
from ..models.attack_surface import AttackSurface
from ..models.common import HypothesisStatus, IDPrefix, new_id
from ..models.hypothesis import Hypothesis, HypothesisScoreBreakdown


def _priority_from_breakdown(b: HypothesisScoreBreakdown) -> float:
    base = b.impact * b.confidence * b.reachability * b.testability
    return round(base, 4)


async def hypothesis_node(state: ResearchState, ops: AgentOps) -> dict:
    obs_ids: list[str] = state.get("observation_ids", [])
    observations = [ops.observations.get(i) for i in obs_ids if i]
    observations = [o for o in observations if o is not None]

    as_id = state.get("attack_surface_id")
    as_obj: AttackSurface | None = ops.attack_surfaces.get(as_id) if as_id else None
    as_payload = []
    if as_obj is not None:
        for it in as_obj.items:
            as_payload.append(
                {
                    "name": it.name,
                    "kind": it.kind,
                    "reachability": {"required_privilege": it.reachability.required_privilege},
                }
            )

    user_prompt = (
        "Observations:\n"
        + "\n".join(f"- id: {o.id} category: {o.category}" for o in observations)
        + "\n\nAttack surface:\n"
        + "\n".join(f"- name: {x['name']} reachability: {x['reachability']}" for x in as_payload)
    )
    resp = ops.llm.complete(
        [LLMMessage(role="user", content=user_prompt)],
        task=LLMTask.HYPOTHESIS_GEN,
    )
    raw = (resp.structured or {}).get("hypotheses", [])

    hypotheses: list[Hypothesis] = []
    for entry in raw:
        breakdown = HypothesisScoreBreakdown(
            impact=float(entry.get("score_breakdown", {}).get("impact", 0.3)),
            confidence=float(entry.get("score_breakdown", {}).get("confidence", 0.3)),
            reachability=float(entry.get("score_breakdown", {}).get("reachability", 0.3)),
            testability=float(entry.get("score_breakdown", {}).get("testability", 0.3)),
            rule_score=float(entry.get("score_breakdown", {}).get("rule_score", 0.3)),
            model_explanation=entry.get("score_breakdown", {}).get("model_explanation", ""),
            uncertainty=entry.get("score_breakdown", {}).get("uncertainty", "medium"),
        )
        h = Hypothesis(
            id=new_id(IDPrefix.HYPOTHESIS),
            project_id=state["project_id"],
            target_id=state["target_id"],
            category=entry.get("category", "logic"),
            location=entry.get("location"),
            description=entry.get("description", ""),
            observation_ids=entry.get("observation_ids", []),
            attack_surface_item_ids=[],
            requires_human_review=bool(entry.get("requires_human_review", True)),
            status=HypothesisStatus.PROPOSED,
            priority_breakdown=breakdown,
            confidence=breakdown.confidence,
            priority=_priority_from_breakdown(breakdown),
        )
        hypotheses.append(h)
        ops.hypotheses.add(h)

    return {
        "hypothesis_ids": [h.id for h in hypotheses],
        "current_phase": "ranking",
        "current_node": "hypothesis",
    }


async def hypothesis_ranking_node(state: ResearchState, ops: AgentOps) -> dict:
    hyp_ids: list[str] = state.get("hypothesis_ids", [])
    items = [ops.hypotheses.get(i) for i in hyp_ids if i]
    items = [h for h in items if h is not None]
    items.sort(key=lambda h: h.priority, reverse=True)
    selected = [h.id for h in items[:5]]
    for h in items:
        if h.id in selected:
            h.status = HypothesisStatus.SELECTED
        else:
            h.status = HypothesisStatus.QUEUED
        ops.hypotheses.add(h)
    return {
        "selected_hypothesis_ids": selected,
        "current_phase": "evidence",
        "current_node": "hypothesis_ranking",
    }
