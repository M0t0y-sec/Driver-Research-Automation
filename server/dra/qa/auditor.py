"""QA Auditor: Rule + Evidence + LLM three-stage review.

The Auditor is *not* allowed to call `EvidenceRegistrar.register`.
It only reads. Any evidence it cites must already exist in the
Evidence Store.
"""
from __future__ import annotations

from typing import Any

from ..config import SETTINGS
from ..llm.base import LLMMessage
from ..llm.router import LLMRouter
from ..models.common import IDPrefix, QADecision, new_id
from ..models.evidence import Evidence
from ..models.finding import Finding
from ..models.qa import QARuleHit, QAReview
from ..storage.filesystem import QAReviewStore
from .prompts import QA_REVIEW_SYSTEM, QA_REVIEW_USER_TMPL
from .rules import BUILTIN_RULES, QARule


class QAAuditor:
    def __init__(self, llm: LLMRouter, reviews: QAReviewStore | None = None) -> None:
        self.llm = llm
        self.reviews = reviews or QAReviewStore(SETTINGS.data_dir / "qa_reviews")

    # --- public ---

    def review_finding(
        self,
        finding: Finding,
        evidences: list[Evidence] | None = None,
    ) -> QAReview:
        evidences = evidences or []
        rule_hits = self._run_finding_rules(finding, evidences)
        passed = all(h.passed for h in rule_hits)
        if not passed:
            # Don't even call the LLM if deterministic rules already fail.
            return self._store(
                finding=finding,
                evidence_ids=list(finding.evidence_ids),
                rule_hits=rule_hits,
                decision=QADecision.RETRY,
                reasons=[f"rule failed: {h.rule_id} ({h.detail})" for h in rule_hits if not h.passed],
                llm_summary=None,
            )
        llm_summary = self._llm_review(finding, rule_hits)
        decision = self._decision_from_llm(llm_summary) or QADecision.PASS
        return self._store(
            finding=finding,
            evidence_ids=list(finding.evidence_ids),
            rule_hits=rule_hits,
            decision=decision,
            reasons=list(llm_summary.get("reasons", [])) if llm_summary else [],
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

    def _run_finding_rules(self, f: Finding, evidences: list[Evidence]) -> list[QARuleHit]:
        hits: list[QARuleHit] = []
        for rule in BUILTIN_RULES["finding"]:
            hits.append(rule.fn(f))
        # Cross-validate evidence strength floor
        for ev in evidences:
            for rule in BUILTIN_RULES["evidence"]:
                hits.append(rule.fn(ev))
        return hits

    def _run_evidence_rules(self, e: Evidence) -> list[QARuleHit]:
        return [rule.fn(e) for rule in BUILTIN_RULES["evidence"]]

    def _llm_review(self, finding: Finding, rule_hits: list[QARuleHit]) -> dict[str, Any]:
        rules_text = "\n".join(
            f"- {h.rule_id}: {'PASS' if h.passed else 'FAIL'} ({h.detail})" for h in rule_hits
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
                    evidence_ids=",".join(finding.evidence_ids),
                    lineage_ids=",".join(finding.lineage_ids[:8]),
                    rules=rules_text,
                ),
            ),
        ]
        resp = self.llm.complete(messages, task=self.llm.route(__import__("dra.llm.base", fromlist=["LLMTask"]).LLMTask.QA_REVIEW).tier and __import__("dra.llm.base", fromlist=["LLMTask"]).LLMTask.QA_REVIEW)
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
