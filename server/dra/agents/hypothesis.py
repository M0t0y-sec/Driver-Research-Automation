"""Hypothesis Agent + Hypothesis Ranking.

Generates candidate hypotheses from observations + attack surface and
ranks them. The governing rule is that *zero hypotheses is a valid
result*: attack-surface facts alone (an IOCTL code, a device name, an
imported memory routine) do not justify a hypothesis.

Every draft is grounded before it is stored:

* it must cite at least one observation id that exists in this run;
* it must carry a falsifiable prediction (``falsification``).

Drafts that fail either check are discarded and recorded in
``hypothesis_rejected``; they never reach ranking, QA or a finding.
"""
from __future__ import annotations

import logging

from ..agents._ops import AgentOps
from ..graph.state import ResearchState
from ..llm.base import LLMTask
from ..llm.schemas import hypothesis_generation_schema
from ..models.attack_surface import AttackSurface
from ..models.common import HypothesisStatus, IDPrefix, new_id
from ..models.hypothesis import Hypothesis, HypothesisScoreBreakdown
from ..models.observation import Observation
from ..prompts import build_hypothesis_messages

logger = logging.getLogger("dra.agents.hypothesis")

_DEFAULT_SCORE = 0.3


def _priority_from_breakdown(b: HypothesisScoreBreakdown) -> float:
    base = b.impact * b.confidence * b.reachability * b.testability
    return round(base, 4)


def _unit(value, default: float = _DEFAULT_SCORE) -> float:
    """Coerce a model-provided score into [0.0, 1.0]."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return max(0.0, min(1.0, number))


def _score_breakdown(entry: dict) -> HypothesisScoreBreakdown:
    raw = entry.get("score_breakdown") or {}
    uncertainty = str(raw.get("uncertainty") or "medium").lower()
    if uncertainty not in {"low", "medium", "high"}:
        uncertainty = "medium"
    return HypothesisScoreBreakdown(
        impact=_unit(raw.get("impact")),
        confidence=_unit(raw.get("confidence")),
        reachability=_unit(raw.get("reachability")),
        testability=_unit(raw.get("testability")),
        rule_score=_unit(raw.get("rule_score")),
        model_explanation=str(raw.get("model_explanation") or ""),
        uncertainty=uncertainty,
    )


def _rejection(entry: object, reason: str) -> dict:
    """A compact, JSON-serialisable record of a discarded draft."""
    summary = ""
    if isinstance(entry, dict):
        summary = str(entry.get("description") or "")[:200]
    return {"reason": reason, "description": summary}


def _grounded(
    entry: object, known_observation_ids: set[str]
) -> tuple[dict | None, str | None]:
    """Validate one model draft. Returns ``(entry, None)`` or ``(None, reason)``."""
    if not isinstance(entry, dict):
        return None, "draft is not a JSON object"
    observation_ids = entry.get("observation_ids")
    if not isinstance(observation_ids, list) or not observation_ids:
        return None, "no observation id cited"
    cited = [str(oid) for oid in observation_ids]
    unknown = sorted({oid for oid in cited if oid not in known_observation_ids})
    if unknown:
        return None, "cited observation id(s) do not exist: " + ", ".join(unknown[:5])
    if not str(entry.get("description") or "").strip():
        return None, "empty description"
    if not str(entry.get("falsification") or "").strip():
        return None, "no falsifiable prediction (falsification is empty)"
    return entry, None


async def hypothesis_node(state: ResearchState, ops: AgentOps) -> dict:
    obs_ids: list[str] = state.get("observation_ids", [])
    observations: list[Observation] = [
        obs for obs in (ops.observations.get(i) for i in obs_ids if i) if obs is not None
    ]

    if not observations:
        return {
            "hypothesis_ids": [],
            "hypothesis_reasoning": (
                "No observations were produced for this target, so there is "
                "nothing to hypothesise about."
            ),
            "hypothesis_rejected": [],
            "current_phase": "ranking",
            "current_node": "hypothesis",
        }

    as_id = state.get("attack_surface_id")
    attack_surface: AttackSurface | None = (
        ops.attack_surfaces.get(as_id) if as_id else None
    )

    messages = build_hypothesis_messages(
        observations=observations,
        attack_surface=attack_surface,
        reverse_findings=state.get("reverse_findings") or None,
        reverse_status=state.get("reverse_analysis_status"),
    )
    resp = ops.llm.complete(
        messages,
        task=LLMTask.HYPOTHESIS_GEN,
        response_schema=hypothesis_generation_schema(),
    )
    payload = resp.structured or {}
    raw_hypotheses = payload.get("hypotheses")
    if not isinstance(raw_hypotheses, list):
        raw_hypotheses = []
    reasoning = str(payload.get("reasoning") or "")
    if not reasoning and getattr(resp, "model", "") == "mock":
        reasoning = (
            "(mock provider: template hypotheses, not model reasoning; "
            "set DRA_LLM_PROVIDER=anthropic for real analysis)"
        )

    known_ids = {obs.id for obs in observations}
    hypotheses: list[Hypothesis] = []
    rejected: list[dict] = []
    for entry in raw_hypotheses:
        grounded, reason = _grounded(entry, known_ids)
        if grounded is None:
            assert reason is not None
            rejected.append(_rejection(entry, reason))
            continue
        breakdown = _score_breakdown(grounded)
        hypothesis = Hypothesis(
            id=new_id(IDPrefix.HYPOTHESIS),
            project_id=state["project_id"],
            target_id=state["target_id"],
            category=str(grounded.get("category") or "logic"),
            location=(str(grounded["location"]) if grounded.get("location") else None),
            source=(str(grounded["source"]) if grounded.get("source") else None),
            sink=(str(grounded["sink"]) if grounded.get("sink") else None),
            description=str(grounded.get("description") or ""),
            falsification=str(grounded["falsification"]).strip(),
            observation_ids=[str(oid) for oid in grounded.get("observation_ids", [])],
            attack_surface_item_ids=[],
            requires_human_review=bool(grounded.get("requires_human_review", True)),
            status=HypothesisStatus.PROPOSED,
            priority_breakdown=breakdown,
            confidence=breakdown.confidence,
            priority=_priority_from_breakdown(breakdown),
        )
        hypotheses.append(hypothesis)
        ops.hypotheses.add(hypothesis)

    if rejected:
        logger.warning(
            "hypothesis node discarded %d draft(s): %s",
            len(rejected),
            "; ".join(record["reason"] for record in rejected[:5]),
        )
    logger.info(
        "hypothesis node: %d observation(s), %d draft(s), %d accepted, %d rejected, reasoning=%d chars",
        len(observations),
        len(raw_hypotheses),
        len(hypotheses),
        len(rejected),
        len(reasoning),
    )

    return {
        "hypothesis_ids": [h.id for h in hypotheses],
        "hypothesis_reasoning": reasoning,
        "hypothesis_rejected": rejected,
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
