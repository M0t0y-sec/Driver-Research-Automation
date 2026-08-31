from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from .common import FindingStatus, utc_now

VulnerabilityClass = Literal[
    "memory_safety", "privilege_escalation", "info_disclosure", "denial_of_service",
    "logic", "input_validation", "race_condition", "other",
]


class CVSSVector(BaseModel):
    """Minimal CVSS:3.1 base vector. Kept simple in Phase 0/1."""
    version: Literal["3.1"] = "3.1"
    vector: str  # full CVSS vector string
    base_score: float = 0.0
    severity: Literal["none", "low", "medium", "high", "critical"] = "none"


class Finding(BaseModel):
    id: str
    project_id: str
    target_id: str
    title: str
    summary: str
    vulnerability_class: VulnerabilityClass
    cwe: list[str] = Field(default_factory=list)
    cvss: CVSSVector | None = None
    severity: Literal["info", "low", "medium", "high", "critical"] = "info"
    attack_vector: str = "local"
    required_privilege: str = "unprivileged"
    user_interaction: Literal["none", "passive", "active"] = "none"
    root_cause_id: str | None = None
    impact_id: str | None = None
    exploitability_id: str | None = None
    trigger_condition: str | None = None
    repro_steps: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    crash_ids: list[str] = Field(default_factory=list)
    experiment_ids: list[str] = Field(default_factory=list)
    execution_ids: list[str] = Field(default_factory=list)
    telemetry_ids: list[str] = Field(default_factory=list)
    lineage_ids: list[str] = Field(default_factory=list)  # full research lineage
    qa_status: str = "pending"
    qa_review_id: str | None = None
    confidence: str = "medium"
    limitations: list[str] = Field(default_factory=list)
    remediation: str | None = None
    disclosure_status: str = "internal"
    status: FindingStatus = FindingStatus.CANDIDATE
    created_at: str = Field(default_factory=lambda: utc_now().isoformat())
    updated_at: str = Field(default_factory=lambda: utc_now().isoformat())
