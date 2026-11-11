"""QA Auditor: Rule + Evidence + LLM three-stage review.

The Auditor is *not* allowed to call `EvidenceRegistrar.register`.
It only reads. Any evidence it cites must already exist in the
Evidence Store.

Ordering matters:

1. Structural finding rules run first. A failure returns ``retry``
   without an LLM call (as before).
2. The deterministic evidence gate runs next. A veto caps the outcome at
   ``inconclusive`` and returns *without* calling the LLM - the model can
   never override it.  The gate requires: a usable location, supporting
   strength, non-import-only support, **and at least one defect-level
   evidence** (sink / control_flow / crash).  Attack-surface facts with
   real addresses - an IOCTL constant compared in a real handler, a
   device name, an imported primitive - clear the strength check but not
   the defect check, so they can never reach ``pass``.
3. Only a finding that clears the gate reaches the LLM. Its verdict may
   confirm ``pass`` or be stricter; a missing / malformed verdict now
   defaults to ``inconclusive`` instead of silently passing.
"""
from __future__ import annotations

from typing import Any, Mapping

from ..config import SETTINGS
from ..llm.base import LLMMessage, LLMTask
from ..llm.router import LLMRouter
from ..models.common import IDPrefix, QADecision, new_id
from ..models.evidence import Evidence
from ..models.finding import Finding
from ..models.qa import QARuleHit, QAReview
from ..storage.filesystem import QAReviewStore
from .prompts import QA_REVIEW_SYSTEM, QA_REVIEW_USER_TMPL
from .rules import BUILTIN_RULES, evaluate_finding_gate


class QAAuditor:
    def __init__(self, llm: LLMRouter, reviews: QAReviewStore | None = None) -> None:
        self.llm = llm
        self.reviews = reviews or QAReviewStore(SETTINGS.data_dir / "qa_reviews")

    # --- public ---

    def review_finding(
        self,
        finding: Finding,
        evidences: list[Evidence] | None = None,
        *,
        finding_location: str | None = None,
        evidence_locations: Mapping[str, str | None] | None = None,
    ) -> QAReview:
        evs = [e for e in (evidences or []) if e is not None]

        # 1. Structural rules: cheap, deterministic, no LLM spend.
        rule_hits = self._run_finding_rules(finding)
        failed = [h for h in rule_hits if not h.passed]
        if failed:
            return self._store(
                finding=finding,
                evidence_ids=list(finding.evidence_ids),
                rule_hits=rule_hits,
                decision=QADecision.RETRY,
                reasons=[f"rule failed: {h.rule_id} ({h.detail})" for h in failed],
                llm_summary=None,
            )

        # 2. Evidence gate: a veto is final. The LLM is not consulted.
        gate = evaluate_finding_gate(
            finding,
            evs,
            finding_location=finding_location,
            evidence_locations=evidence_locations,
        )
        rule_hits.extend(gate.rule_hits)
        if gate.blocked:
            return self._store(
                finding=finding,
                evidence_ids=list(finding.evidence_ids),
                rule_hits=rule_hits,
                decision=QADecision.INCONCLUSIVE,
                reasons=gate.reasons,
                llm_summary=None,
            )

        # 3. Only now ask the LLM. It may confirm or be stricter; it can
        #    never upgrade a gate result.
        llm_summary = self._llm_review(finding, rule_hits, evs)
        decision = self._decision_from_llm(llm_summary or {})
        if decision is None:
            decision = QADecision.INCONCLUSIVE
            reasons = ["llm review unavailable or malformed; defaulting to inconclusive"]
            reasons.extend(gate.reasons)
        else:
            reasons = list(llm_summary.get("reasons", [])) if llm_summary else []
        return self._store(
            finding=finding,
            evidence_ids=list(finding.evidence_ids),
            rule_hits=rule_hits,
            decision=decision,
            reasons=reasons,
            llm_summary=llm_summary,
        )

    def review_evidence(self, evidence: Evidence) -> QAReview:
        rule_hits = self._run_evidence_rules(evidence)
        passed = all(h.passed for h in rule_hits)
        return self._store(
            finding=None,
            evidence_ids=[evidence.id],
            rule_hits=rule_hits,
            decision=QADecision.PASS if passed else QADecision.RETRY,
            reasons=[f"rule failed: {h.rule_id} ({h.detail})" for h in rule_hits if not h.passed],
            llm_summary=None,
        )

    # --- internals ---

    def _run_finding_rules(self, f: Finding) -> list[QARuleHit]:
        return [rule.fn(f) for rule in BUILTIN_RULES["finding"]]

    def _run_evidence_rules(self, e: Evidence) -> list[QARuleHit]:
        return [rule.fn(e) for rule in BUILTIN_RULES["evidence"]]

    def _llm_review(
        self,
        finding: Finding,
        rule_hits: list[QARuleHit],
        evidences: list[Evidence],
    ) -> dict[str, Any]:
        rules_text = "\n".join(
            f"- {h.rule_id}: {'PASS' if h.passed else 'FAIL'} ({h.detail})" for h in rule_hits
        )
        evidence_text = ", ".join(
            f"{ev.id}:{ev.evidence_strength.value}:{ev.evidence_type}" for ev in evidences
        )
        messages = [
            LLMMessage(role="system", content=QA_REVIEW_SYSTEM),
            LLMMessage(
                role="user",
                content=QA_REVIEW_USER_TMPL.format(
                    project_id=finding.project_id,
                    target_id=finding.target_id or "",
                    finding_id=finding.id,
                    title=finding.title,
                    summary=finding.summary,
                    trigger_condition=finding.trigger_condition or "(none)",
                    evidence_ids=",".join(finding.evidence_ids),
                    evidence_strengths=evidence_text or "(none)",
                    lineage_ids=",".join(finding.lineage_ids[:8]),
                    rules=rules_text,
                ),
            ),
        ]
        resp = self.llm.complete(messages, task=LLMTask.QA_REVIEW)
        return resp.structured or {}

    @staticmethod
    def _decision_from_llm(payload: dict) -> QADecision | None:
        d = (payload.get("decision") or "").lower()
        return {
            "pass": QADecision.PASS,
            "retry": QADecision.RETRY,
            "reject": QADecision.REJECT,
            "inconclusive": QADecision.INCONCLUSIVE,
        }.get(d)

    def _store(
        self,
        *,
        finding: Finding | None,
        evidence_ids: list[str],
        rule_hits: list[QARuleHit],
        decision: QADecision,
        reasons: list[str],
        llm_summary: dict | None,
    ) -> QAReview:
        review = QAReview(
            id=new_id(IDPrefix.QA_REVIEW),
            project_id=(finding.project_id if finding else ""),
            target_id=(finding.target_id if finding else None),
            finding_id=(finding.id if finding else None),
            evidence_ids=evidence_ids,
            decision=decision,
            rule_hits=rule_hits,
            llm_review_summary=(str(llm_summary) if llm_summary else None),
            reasons=reasons,
        )
        self.reviews.add(review)
        return review
