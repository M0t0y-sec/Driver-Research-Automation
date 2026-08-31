"""Flat-JSON + artefacts-on-disk storage.

Layout:

  <data_dir>/
    projects/<id>.json
    research/<id>.json
    findings/<id>.json
    evidence/<id>.json
    approvals/<id>.json
    tool_runs/<id>.json
    audit.log.jsonl

  <artifacts_dir>/
    <sha256>           (raw file contents)
    <sha256>.meta.json (artifact metadata)

This is a Phase 0/1 backend. The interface (`FileSystemStore`) is the
ONLY thing the rest of the system touches; the Postgres/S3 swap is a
future implementation.
"""
from __future__ import annotations

import json
import os
import shutil
import threading
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Generic, TypeVar

from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


def _ensure_dir(p: Path) -> Path:
    p.mkdir(parents=True, exist_ok=True)
    return p


class FileSystemStore(Generic[T]):
    """JSON-per-file CRUD store with a coarse per-dir lock."""

    def __init__(self, base_dir: Path) -> None:
        self.base_dir = _ensure_dir(base_dir)
        self._lock = threading.RLock()

    # ---- internals ----
    def _path(self, obj_id: str) -> Path:
        return self.base_dir / f"{obj_id}.json"

    def _read(self, obj_id: str) -> dict | None:
        p = self._path(obj_id)
        if not p.exists():
            return None
        with p.open("r", encoding="utf-8") as f:
            return json.load(f)

    def _write(self, obj_id: str, data: dict) -> None:
        p = self._path(obj_id)
        tmp = p.with_suffix(".json.tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, p)

    def _delete_file(self, obj_id: str) -> bool:
        p = self._path(obj_id)
        if p.exists():
            p.unlink()
            return True
        return False

    # ---- generic API ----
    def add(self, obj: T) -> T:
        with self._lock:
            self._write(obj.id, obj.model_dump(mode="json"))
        return obj

    def get(self, obj_id: str) -> T | None:
        data = self._read(obj_id)
        if data is None:
            return None
        # Caller supplies the model class via subclass or wrapper.
        return self._coerce(data)

    def list(self, **filters: Any) -> list[T]:
        with self._lock:
            files = sorted(self.base_dir.glob("*.json"))
        out: list[T] = []
        for f in files:
            try:
                with f.open("r", encoding="utf-8") as fh:
                    data = json.load(fh)
            except json.JSONDecodeError:
                continue
            if not self._matches(data, filters):
                continue
            out.append(self._coerce(data))
        return out

    def update(self, obj: T) -> T:
        return self.add(obj)

    def delete(self, obj_id: str) -> bool:
        with self._lock:
            return self._delete_file(obj_id)

    def count(self, **filters: Any) -> int:
        return len(self.list(**filters))

    # ---- extension points (subclass overrides) ----
    def _coerce(self, data: dict) -> T:  # pragma: no cover - overridden
        raise NotImplementedError("Subclasses must implement _coerce")

    @staticmethod
    def _matches(data: dict, filters: dict[str, Any]) -> bool:
        for k, v in filters.items():
            if data.get(k) != v:
                return False
        return True


# --- Concrete typed stores ---

from ..models.target import TargetInfo
from ..models.evidence import Evidence
from ..models.hypothesis import Hypothesis
from ..models.experiment import ExperimentPlan
from ..models.execution import Execution
from ..models.crash import Crash
from ..models.telemetry import TelemetryBatch
from ..models.observation import Observation
from ..models.attack_surface import AttackSurface
from ..models.root_cause import RootCause
from ..models.impact import SecurityImpact
from ..models.exploitability import ExploitabilityAssessment
from ..models.finding import Finding
from ..models.approval import Approval
from ..models.tool_run import ToolRun
from ..models.agent_run import AgentRun
from ..models.visibility import VisibilityResult
from ..models.detection import DetectionResult
from ..models.robustness import RobustnessResult
from ..models.qa import QAReview


class TargetStore(FileSystemStore[TargetInfo]):
    def _coerce(self, data: dict) -> TargetInfo:
        return TargetInfo.model_validate(data)


class EvidenceStore(FileSystemStore[Evidence]):
    def _coerce(self, data: dict) -> Evidence:
        return Evidence.model_validate(data)


class HypothesisStore(FileSystemStore[Hypothesis]):
    def _coerce(self, data: dict) -> Hypothesis:
        return Hypothesis.model_validate(data)


class ExperimentStore(FileSystemStore[ExperimentPlan]):
    def _coerce(self, data: dict) -> ExperimentPlan:
        return ExperimentPlan.model_validate(data)


class ExecutionStore(FileSystemStore[Execution]):
    def _coerce(self, data: dict) -> Execution:
        return Execution.model_validate(data)


class CrashStore(FileSystemStore[Crash]):
    def _coerce(self, data: dict) -> Crash:
        return Crash.model_validate(data)


class TelemetryStore(FileSystemStore[TelemetryBatch]):
    def _coerce(self, data: dict) -> TelemetryBatch:
        return TelemetryBatch.model_validate(data)


class ObservationStore(FileSystemStore[Observation]):
    def _coerce(self, data: dict) -> Observation:
        return Observation.model_validate(data)


class AttackSurfaceStore(FileSystemStore[AttackSurface]):
    def _coerce(self, data: dict) -> AttackSurface:
        return AttackSurface.model_validate(data)


class RootCauseStore(FileSystemStore[RootCause]):
    def _coerce(self, data: dict) -> RootCause:
        return RootCause.model_validate(data)


class ImpactStore(FileSystemStore[SecurityImpact]):
    def _coerce(self, data: dict) -> SecurityImpact:
        return SecurityImpact.model_validate(data)


class ExploitabilityStore(FileSystemStore[ExploitabilityAssessment]):
    def _coerce(self, data: dict) -> ExploitabilityAssessment:
        return ExploitabilityAssessment.model_validate(data)


class FindingStore(FileSystemStore[Finding]):
    def _coerce(self, data: dict) -> Finding:
        return Finding.model_validate(data)


class ApprovalStore(FileSystemStore[Approval]):
    def _coerce(self, data: dict) -> Approval:
        return Approval.model_validate(data)


class ToolRunStore(FileSystemStore[ToolRun]):
    def _coerce(self, data: dict) -> ToolRun:
        return ToolRun.model_validate(data)


class AgentRunStore(FileSystemStore[AgentRun]):
    def _coerce(self, data: dict) -> AgentRun:
        return AgentRun.model_validate(data)


class VisibilityStore(FileSystemStore[VisibilityResult]):
    def _coerce(self, data: dict) -> VisibilityResult:
        return VisibilityResult.model_validate(data)


class DetectionStore(FileSystemStore[DetectionResult]):
    def _coerce(self, data: dict) -> DetectionResult:
        return DetectionResult.model_validate(data)


class RobustnessStore(FileSystemStore[RobustnessResult]):
    def _coerce(self, data: dict) -> RobustnessResult:
        return RobustnessStore._coerce_impl(data)  # type: ignore[arg-type]

    @staticmethod
    def _coerce_impl(data: dict) -> RobustnessResult:
        return RobustnessResult.model_validate(data)


class QAReviewStore(FileSystemStore[QAReview]):
    def _coerce(self, data: dict) -> QAReview:
        return QAReview.model_validate(data)


# Projects and Research are simple dict records in Phase 0/1.
class ProjectStore(FileSystemStore[dict]):
    def _coerce(self, data: dict) -> dict:
        return data

    def add(self, obj: dict) -> dict:  # type: ignore[override]
        # Project records are arbitrary dicts in Phase 0/1; the `id` is
        # the only field the rest of the system relies on.
        with self._lock:
            self._write(obj["id"], obj)
        return obj

    def update(self, obj: dict) -> dict:  # type: ignore[override]
        return self.add(obj)


class ResearchStore(FileSystemStore[dict]):
    def _coerce(self, data: dict) -> dict:
        return data

    def add(self, obj: dict) -> dict:  # type: ignore[override]
        with self._lock:
            self._write(obj["id"], obj)
        return obj

    def update(self, obj: dict) -> dict:  # type: ignore[override]
        return self.add(obj)


# --- Audit log (append-only) ---

class AuditLog:
    """Append-only JSONL audit log.

    Used by Tool Gateway, Evidence Registrar, QA Auditor and the
    Compliance layer. Writes are line-buffered; readers do not get
    partial lines because each call writes exactly one record.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def record(self, kind: str, payload: dict) -> None:
        import datetime as _dt
        line = json.dumps(
            {"ts": _dt.datetime.utcnow().isoformat() + "Z", "kind": kind, **payload},
            ensure_ascii=False,
        )
        with self._lock:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")

    def tail(self, n: int = 200) -> list[dict]:
        if not self.path.exists():
            return []
        with self.path.open("r", encoding="utf-8") as f:
            lines = f.readlines()[-n:]
        out: list[dict] = []
        for line in lines:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out
