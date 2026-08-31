"""Shared enums, ID generator, and small utilities used across models."""
from __future__ import annotations

import re
import secrets
from datetime import datetime, timezone
from enum import Enum
from typing import Literal


# --- ID prefixes (matches the lineage chain in the design doc) ---
class IDPrefix:
    PROJECT = "PRJ"
    TARGET = "TGT"
    RESEARCH = "RES"
    OBSERVATION = "OBS"
    ATTACK_SURFACE = "ASF"
    HYPOTHESIS = "HYP"
    EXPERIMENT = "EXP"
    EXECUTION = "EXE"
    CRASH = "CRS"
    TELEMETRY = "TLM"
    EVIDENCE = "EVD"
    ROOT_CAUSE = "RCN"
    IMPACT = "IMP"
    EXPLOITABILITY = "XPL"
    FINDING = "FND"
    APPROVAL = "APR"
    TOOL_RUN = "TRN"
    AGENT_RUN = "ARN"
    VISIBILITY = "VIS"
    DETECTION = "DET"
    ROBUSTNESS = "RBT"
    QA_REVIEW = "QAR"
    ARTIFACT = "ART"


def new_id(prefix: str) -> str:
    """Generate a short, sortable, collision-resistant id.

    Format: PREFIX-YYMMDDHHMMSS-XXXXXXXX
    Where XXXXXXXX is 8 random hex chars.
    """
    ts = datetime.now(timezone.utc).strftime("%y%m%d%H%M%S")
    rand = secrets.token_hex(4).upper()
    return f"{prefix}-{ts}-{rand}"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


# --- Enums ---

class EvidenceStrength(str, Enum):
    """E0 = LLM opinion (not evidence); E7 = QA-passed finding."""
    E0 = "E0"
    E1 = "E1"
    E2 = "E2"
    E3 = "E3"
    E4 = "E4"
    E5 = "E5"
    E6 = "E6"
    E7 = "E7"


class FailureClass(str, Enum):
    ENV_FAILURE = "env_failure"
    TOOL_FAILURE = "tool_failure"
    TIMEOUT = "timeout"
    POLICY_DENIED = "policy_denied"
    INVALID_INPUT = "invalid_input"
    TARGET_ERROR = "target_error"
    EXPERIMENT_FAILURE = "experiment_failure"
    TELEMETRY_INVISIBLE = "telemetry_invisible"
    MODEL_ERROR = "model_error"
    EVIDENCE_INSUFFICIENT = "evidence_insufficient"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    EXTREME = "extreme"


class ToolRunStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    NEEDS_APPROVAL = "needs_approval"
    BLOCKED_BY_POLICY = "blocked_by_policy"


class HypothesisStatus(str, Enum):
    PROPOSED = "proposed"
    QUEUED = "queued"
    SELECTED = "selected"
    PLANNED = "planned"
    VALIDATING = "validating"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"
    NEEDS_HUMAN = "needs_human"
    ARCHIVED = "archived"


class ExperimentStatus(str, Enum):
    DRAFT = "draft"
    NEEDS_APPROVAL = "needs_approval"
    APPROVED = "approved"
    SCHEDULED = "scheduled"
    PREPARING = "preparing"
    RUNNING = "running"
    COLLECTING = "collecting"
    TRIAGING = "triaging"
    COMPLETED = "completed"
    FAILED_ENVIRONMENT = "failed_environment"
    FAILED_TARGET = "failed_target"
    FAILED_TELEMETRY = "failed_telemetry"
    INCONCLUSIVE = "inconclusive"
    ARCHIVED = "archived"


class FindingStatus(str, Enum):
    CANDIDATE = "candidate"
    EVIDENCE_REVIEW = "evidence_review"
    QA_PASS = "qa_pass"
    HUMAN_APPROVED = "human_approved"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    NEEDS_HUMAN = "needs_human"
    ARCHIVED = "archived"
    DISCLOSED = "disclosed"


class QADecision(str, Enum):
    PASS = "pass"
    RETRY = "retry"
    REJECT = "reject"
    INCONCLUSIVE = "inconclusive"


class DetectionVerdict(str, Enum):
    """Discriminated result that explicitly admits inconclusive states."""
    DETECTED = "detected"
    NOT_OBSERVED = "not_observed"
    INCONCLUSIVE = "inconclusive"
    BLOCKED = "blocked"


class DetectionStage(str, Enum):
    NONE = "none"
    REALTIME = "realtime"
    POST_EVENT = "post_event"
    DELAYED = "delayed"


Confidence = Literal["high", "medium", "low"]
Status = Literal["idle", "running", "paused", "waiting_approval", "failed", "completed"]


# --- Helpers ---

_SAFE_ID_RE = re.compile(r"^[A-Z]{2,5}-[0-9]{12}-[A-F0-9]{1,16}$")


def is_valid_id(value: str) -> bool:
    return bool(_SAFE_ID_RE.match(value))
