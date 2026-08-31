"""Storage layer package.

Phase 0/1 uses a flat-JSON + artefacts-on-disk backend. The Repository
ABC is the only contract that consumers (graph nodes, API routes) should
depend on. The Postgres implementation can drop in later without
touching call sites.
"""
from .artifact_store import ArtifactStore, FileSystemArtifactStore
from .filesystem import FileSystemStore
from .repository import (
    Repository,
    ProjectRepository,
    TargetRepository,
    ResearchRepository,
    ObservationRepository,
    AttackSurfaceRepository,
    HypothesisRepository,
    ExperimentRepository,
    ExecutionRepository,
    CrashRepository,
    TelemetryRepository,
    EvidenceRepository,
    RootCauseRepository,
    ImpactRepository,
    ExploitabilityRepository,
    FindingRepository,
    ApprovalRepository,
    ToolRunRepository,
    AgentRunRepository,
    VisibilityRepository,
    DetectionRepository,
    RobustnessRepository,
    QAReviewRepository,
)

__all__ = [
    "ArtifactStore",
    "FileSystemArtifactStore",
    "FileSystemStore",
    "Repository",
    "ProjectRepository",
    "TargetRepository",
    "ResearchRepository",
    "ObservationRepository",
    "AttackSurfaceRepository",
    "HypothesisRepository",
    "ExperimentRepository",
    "ExecutionRepository",
    "CrashRepository",
    "TelemetryRepository",
    "EvidenceRepository",
    "RootCauseRepository",
    "ImpactRepository",
    "ExploitabilityRepository",
    "FindingRepository",
    "ApprovalRepository",
    "ToolRunRepository",
    "AgentRunRepository",
    "VisibilityRepository",
    "DetectionRepository",
    "RobustnessRepository",
    "QAReviewRepository",
]
