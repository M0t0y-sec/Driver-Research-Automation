
from pydantic import BaseModel, Field

from .common import QADecision, utc_now


class QARuleHit(BaseModel):
    rule_id: str
    description: str
    passed: bool
    detail: str | None = None


class QAReview(BaseModel):
    id: str
    project_id: str
    target_id: str | None = None
    finding_id: str | None = None
    hypothesis_id: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    decision: QADecision = QADecision.INCONCLUSIVE
    rule_hits: list[QARuleHit] = Field(default_factory=list)
    llm_review_summary: str | None = None
    reasons: list[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: utc_now().isoformat())
