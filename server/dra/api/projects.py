"""Project endpoints."""

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from ..config import SETTINGS
from ..evidence.lineage import LineageBuilder
from ..models.common import IDPrefix, new_id
from ..storage.filesystem import ProjectStore

router = APIRouter(prefix="/projects", tags=["projects"])


class ProjectIn(BaseModel):
    name: str
    description: str = ""
    authorized_use: bool = False
    authorization_ref: str | None = None
    tags: list[str] = Field(default_factory=list)


class ProjectOut(BaseModel):
    id: str
    name: str
    description: str = ""
    authorized_use: bool
    authorization_ref: str | None = None
    tags: list[str] = Field(default_factory=list)
    created_at: str | None = None


def _coerce(rec: dict) -> dict:
    """Backfill fields that older records may be missing."""
    out = dict(rec)
    out.setdefault("description", "")
    out.setdefault("authorization_ref", None)
    out.setdefault("tags", [])
    out.setdefault("created_at", None)
    return out


@router.post("", response_model=ProjectOut, status_code=status.HTTP_201_CREATED)
def create_project(payload: ProjectIn) -> ProjectOut:
    store = ProjectStore(SETTINGS.projects_dir)
    rec = {
        "id": new_id(IDPrefix.PROJECT),
        "name": payload.name,
        "description": payload.description,
        "authorized_use": payload.authorized_use,
        "authorization_ref": payload.authorization_ref,
        "tags": payload.tags,
        "created_at": _now_iso(),
    }
    store.add(rec)
    return ProjectOut(**rec)


@router.get("", response_model=list[ProjectOut])
def list_projects() -> list[ProjectOut]:
    store = ProjectStore(SETTINGS.projects_dir)
    return [ProjectOut(**_coerce(r)) for r in store.list()]


@router.get("/{project_id}", response_model=ProjectOut)
def get_project(project_id: str) -> ProjectOut:
    store = ProjectStore(SETTINGS.projects_dir)
    rec = store.get(project_id)
    if rec is None:
        raise HTTPException(404, "project not found")
    return ProjectOut(**_coerce(rec))


@router.get("/{project_id}/lineage")
def project_lineage(project_id: str) -> dict:
    """Materialise the lineage chain for a project.

    Phase 0/1 walks the storage directories to collect the IDs. Phase 2+
    will be backed by a dedicated `lineage` table.
    """
    from ..storage.filesystem import (
        EvidenceStore, FindingStore, HypothesisStore, ObservationStore, ResearchStore,
    )
    b = LineageBuilder().add(project_id, "project", "project")
    for o in ObservationStore(SETTINGS.data_dir / "observations").list(project_id=project_id):
        b.add(o.id, "observation", o.category)
    for h in HypothesisStore(SETTINGS.data_dir / "hypotheses").list(project_id=project_id):
        b.add(h.id, "hypothesis", h.description[:40])
    for e in EvidenceStore(SETTINGS.evidence_dir).list(project_id=project_id):
        b.add(e.id, "evidence", e.evidence_type)
    for f in FindingStore(SETTINGS.findings_dir).list(project_id=project_id):
        b.add(f.id, "finding", f.title)
    for r in ResearchStore(SETTINGS.research_dir).list(project_id=project_id):
        b.add(r["id"], "research", r.get("current_phase", ""))
    return b.build()


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
