
from typing import Literal

from pydantic import BaseModel, Field

from .common import ExperimentStatus, utc_now


class TestCase(BaseModel):
    fingerprint: str
    name: str
    payload: dict
    expected_observable: str | None = None


class TestCaseSet(BaseModel):
    id: str
    hypothesis_id: str
    project_id: str
    cases: list[TestCase] = Field(default_factory=list)
    generation_strategy: str  # "ioctl_template", "boundary", "mutation", "symbolic"
    created_at: str = Field(default_factory=lambda: utc_now().isoformat())


class ExperimentPlan(BaseModel):
    id: str
    hypothesis_id: str
    project_id: str
    environment_id: str
    setup: list[str] = Field(default_factory=list)
    inputs: list[str] = Field(default_factory=list)  # TestCase IDs
    observation_points: list[str] = Field(default_factory=list)
    success_criteria: list[str] = Field(default_factory=list)
    failure_criteria: list[str] = Field(default_factory=list)
    rollback_requirement: str | None = None
    safety_constraints: list[str] = Field(default_factory=list)
    expected_telemetry: list[str] = Field(default_factory=list)
    timeout_seconds: int = 3600
    trial_count: int = 3
    experiment_fingerprint: str | None = None
    status: ExperimentStatus = ExperimentStatus.DRAFT
    risk_level: str = "medium"
    created_at: str = Field(default_factory=lambda: utc_now().isoformat())


class TrialResult(BaseModel):
    trial_index: int
    outcome: Literal["confirmed", "rejected", "inconclusive", "error"]
    artifact_refs: list[str] = Field(default_factory=list)
    notes: str | None = None
