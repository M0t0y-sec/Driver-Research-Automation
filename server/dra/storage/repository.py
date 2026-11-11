"""Generic repository contract.

We don't bind to SQLAlchemy in Phase 0/1; instead we provide a tiny
generic repository protocol and a JSON-backed implementation. The
generic typing lets us type-check at call sites without a real ORM.
"""

from typing import Generic, Iterable, Protocol, TypeVar

T = TypeVar("T")


class Repository(Protocol, Generic[T]):
    """Minimal contract every concrete repository must implement."""

    def add(self, obj: T) -> T: ...
    def get(self, obj_id: str) -> T | None: ...
    def list(self, **filters) -> list[T]: ...
    def update(self, obj: T) -> T: ...
    def delete(self, obj_id: str) -> bool: ...
    def count(self, **filters) -> int: ...


# Concrete repository aliases - just class names; instances live in
# the FileSystemStore. They exist so the API layer can declare typed
# dependencies without importing the storage class everywhere.
from ..models.target import TargetInfo as _TargetInfo  # noqa: E402
from ..models.evidence import Evidence as _Evidence  # noqa: E402
from ..models.hypothesis import Hypothesis as _Hypothesis  # noqa: E402
from ..models.experiment import ExperimentPlan as _ExperimentPlan  # noqa: E402
from ..models.execution import Execution as _Execution  # noqa: E402
from ..models.crash import Crash as _Crash  # noqa: E402
from ..models.telemetry import TelemetryBatch as _TelemetryBatch  # noqa: E402
from ..models.observation import Observation as _Observation  # noqa: E402
from ..models.attack_surface import AttackSurface as _AttackSurface  # noqa: E402
from ..models.root_cause import RootCause as _RootCause  # noqa: E402
from ..models.impact import SecurityImpact as _SecurityImpact  # noqa: E402
from ..models.exploitability import ExploitabilityAssessment as _ExploitabilityAssessment  # noqa: E402
from ..models.finding import Finding as _Finding  # noqa: E402
from ..models.approval import Approval as _Approval  # noqa: E402
from ..models.tool_run import ToolRun as _ToolRun  # noqa: E402
from ..models.agent_run import AgentRun as _AgentRun  # noqa: E402
from ..models.visibility import VisibilityResult as _VisibilityResult  # noqa: E402
from ..models.detection import DetectionResult as _DetectionResult  # noqa: E402
from ..models.robustness import RobustnessResult as _RobustnessResult  # noqa: E402
from ..models.qa import QAReview as _QAReview  # noqa: E402


# Project / Research are simple containers (not full Pydantic models
# in Phase 0/1) - declared inline below.
class _Project:  # placeholder; real dict-shaped record
    pass


class _Research:
    pass


ProjectRepository = Repository[_Project]
TargetRepository = Repository[_TargetInfo]
ResearchRepository = Repository[_Research]
ObservationRepository = Repository[_Observation]
AttackSurfaceRepository = Repository[_AttackSurface]
HypothesisRepository = Repository[_Hypothesis]
ExperimentRepository = Repository[_ExperimentPlan]
ExecutionRepository = Repository[_Execution]
CrashRepository = Repository[_Crash]
TelemetryRepository = Repository[_TelemetryBatch]
EvidenceRepository = Repository[_Evidence]
RootCauseRepository = Repository[_RootCause]
ImpactRepository = Repository[_SecurityImpact]
ExploitabilityRepository = Repository[_ExploitabilityAssessment]
FindingRepository = Repository[_Finding]
ApprovalRepository = Repository[_Approval]
ToolRunRepository = Repository[_ToolRun]
AgentRunRepository = Repository[_AgentRun]
VisibilityRepository = Repository[_VisibilityResult]
DetectionRepository = Repository[_DetectionResult]
RobustnessRepository = Repository[_RobustnessResult]
QAReviewRepository = Repository[_QAReview]


def all_entity_ids(obj) -> Iterable[str]:
    """Helper: yield all string id-like fields from a Pydantic model."""
    if hasattr(obj, "id"):
        yield obj.id
    for key, value in getattr(obj, "__dict__", {}).items():
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str) and "-" in item:
                    yield item
        elif isinstance(value, str) and key.endswith("_id"):
            yield value
