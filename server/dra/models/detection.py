
from pydantic import BaseModel, Field

from .common import DetectionStage, DetectionVerdict, utc_now


class DetectionResult(BaseModel):
    id: str
    project_id: str
    execution_id: str
    behavior_confirmed: bool = False
    telemetry_collected: bool = False
    product_version: str | None = None
    product_policy: str | None = None
    observed_alert: bool = False
    observed_block: bool = False
    observed_telemetry_only: bool = False
    detection_stage: DetectionStage = DetectionStage.NONE
    product_detected: bool | None = None
    verdict: DetectionVerdict = DetectionVerdict.INCONCLUSIVE
    detection_confidence: str = "low"  # high|medium|low
    inconclusive_reason: str | None = None
    trials_total: int = 0
    trials_detected: int = 0
    trials_inconclusive: int = 0
    detection_rate: float = 0.0
    env_anomaly_rate: float = 0.0
    telemetry_missing_rate: float = 0.0
    positive_control_passed: bool | None = None
    negative_control_passed: bool | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: utc_now().isoformat())
