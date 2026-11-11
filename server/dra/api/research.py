"""Research run endpoints."""

import json
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..agents._ops import build_ops
from ..config import SETTINGS
from ..graph.main_graph import build_research_graph
from ..models.common import IDPrefix, new_id
from ..storage.filesystem import ProjectStore, ResearchStore

router = APIRouter(prefix="/research", tags=["research"])


class ResearchStartIn(BaseModel):
    project_id: str
    target_id: str


class ResearchStartOut(BaseModel):
    research_id: str
    project_id: str
    target_id: str
    status: str
    current_phase: str
    current_node: str
    started_at: str | None = None
    completed_at: str | None = None
    finding_ids: list[str] = []
    evidence_ids: list[str] = []
    hypothesis_ids: list[str] = []
    qa_review_ids: list[str] = []
    report: dict | None = None
    error: str | None = None


@router.post("/start", response_model=ResearchStartOut, status_code=200)
async def start_research(payload: ResearchStartIn) -> ResearchStartOut:
    project = ProjectStore(SETTINGS.projects_dir).get(payload.project_id)
    if project is None:
        raise HTTPException(404, "project not found")
    if not project.get("authorized_use", False):
        raise HTTPException(403, "project not authorized")

    target_path = _resolve_target_path(payload.target_id)
    if target_path is None:
        raise HTTPException(404, "target file not found on disk")

    research_id = f"{IDPrefix.RESEARCH}-{new_id('RUN').split('-', 1)[1]}"
    rec = {
        "id": research_id,
        "project_id": payload.project_id,
        "target_id": payload.target_id,
        "status": "running",
        "current_phase": "planner",
        "current_node": "init",
        "started_at": _now_iso(),
        "finding_ids": [],
        "evidence_ids": [],
        "hypothesis_ids": [],
        "qa_review_ids": [],
    }
    ResearchStore(SETTINGS.research_dir).add(rec)

    try:
        ops = build_ops()
        graph = build_research_graph(ops)
        await graph.run(
            project_id=payload.project_id,
            target_id=payload.target_id,
            target_path=str(target_path),
            research_id=research_id,
        )
    except Exception as e:  # noqa: BLE001
        rec["status"] = "failed"
        rec["error"] = f"{type(e).__name__}: {e}"
        rec["completed_at"] = _now_iso()
        ResearchStore(SETTINGS.research_dir).add(rec)
    final = ResearchStore(SETTINGS.research_dir).get(research_id) or rec
    return _to_out(final)


@router.get("/{research_id}", response_model=ResearchStartOut)
def get_research(research_id: str) -> ResearchStartOut:
    rec = ResearchStore(SETTINGS.research_dir).get(research_id)
    if rec is None:
        raise HTTPException(404, "research not found")
    return _to_out(rec)


@router.get("", response_model=list[ResearchStartOut])
def list_research(project_id: str | None = None) -> list[ResearchStartOut]:
    items = ResearchStore(SETTINGS.research_dir).list()
    if project_id is not None:
        items = [r for r in items if r.get("project_id") == project_id]
    return [_to_out(r) for r in items]


@router.post("/{research_id}/cancel")
def cancel_research(research_id: str) -> dict:
    store = ResearchStore(SETTINGS.research_dir)
    rec = store.get(research_id)
    if rec is None:
        raise HTTPException(404, "research not found")
    rec["status"] = "cancelled"
    rec["completed_at"] = _now_iso()
    store.add(rec)
    return {"research_id": research_id, "status": "cancelled"}


def _to_out(rec: dict) -> ResearchStartOut:
    return ResearchStartOut(
        research_id=rec["id"],
        project_id=rec.get("project_id", ""),
        target_id=rec.get("target_id", ""),
        status=rec.get("status", "unknown"),
        current_phase=rec.get("current_phase", ""),
        current_node=rec.get("current_node", ""),
        started_at=rec.get("started_at"),
        completed_at=rec.get("completed_at"),
        finding_ids=rec.get("finding_ids", []),
        evidence_ids=rec.get("evidence_ids", []),
        hypothesis_ids=rec.get("hypothesis_ids", []),
        qa_review_ids=rec.get("qa_review_ids", []),
        report=rec.get("report"),
        error=rec.get("error"),
    )


def _resolve_target_path(target_id: str) -> Path | None:
    p = Path(SETTINGS.data_dir) / "targets_index" / f"{target_id}.json"
    if not p.exists():
        return None
    rec = json.loads(p.read_text(encoding="utf-8"))
    return Path(rec.get("path", ""))


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
