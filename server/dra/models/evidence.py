from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from .common import EvidenceStrength, utc_now

EvidenceQAStatus = Literal["pending", "passed", "challenged", "rejected"]


class Evidence(BaseModel):
    id: str
    project_id: str
    target_id: str | None = None
    evidence_type: str  # static_observation, dynamic_observation, repro_signal, crash, root_cause_link, impact, exploit, qa_pass
    producer_agent: str
    producer_run_id: str | None = None
    timestamp: str = Field(default_factory=lambda: utc_now().isoformat())
    source_artifact_hash: str
    environment_snapshot_id: str | None = None
    tool_version: str | None = None
    model_version: str | None = None
    confidence: str = "medium"  # free-form, audited
    evidence_strength: EvidenceStrength = EvidenceStrength.E1
    related_hypothesis_id: str | None = None
    related_experiment_id: str | None = None
    related_crash_id: str | None = None
    qa_status: EvidenceQAStatus = "pending"
    raw_artifact_ref: str | None = None
    normalized_artifact_ref: str | None = None
    lineage_ids: list[str] = Field(default_factory=list)
    summary: str = ""
