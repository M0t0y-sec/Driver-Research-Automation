"""Target upload + listing.

Phase 0/1 stores uploaded files in the local artefacts store and
returns the sha256 as the canonical target id. The API stays
unchanged when the real S3/MinIO backend is wired in.
"""

import shutil
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, UploadFile, status
from pydantic import BaseModel

from ..config import SETTINGS
from ..models.common import IDPrefix, new_id
from ..storage.artifact_store import FileSystemArtifactStore
from ..storage.filesystem import ProjectStore

router = APIRouter(prefix="/targets", tags=["targets"])


class TargetOut(BaseModel):
    id: str
    project_id: str
    name: str
    sha256: str
    size: int
    file_type: str
    authorized_use: bool
    submitted_at: str
    path: str


@router.post("", response_model=TargetOut, status_code=status.HTTP_201_CREATED)
async def upload_target(
    project_id: str = Form(...),
    name: str = Form(...),
    file: UploadFile = File(...),
) -> TargetOut:
    project = ProjectStore(SETTINGS.projects_dir).get(project_id)
    if project is None:
        raise HTTPException(404, "project not found")
    if not project.get("authorized_use", False):
        raise HTTPException(403, "project not authorized for research")

    # Stream to a temp file, then put into the artefact store.
    uploads_dir = Path(SETTINGS.artefact_root) / "uploads"
    uploads_dir.mkdir(parents=True, exist_ok=True)
    tmp = uploads_dir / f"tmp-{new_id('TMP')}"
    try:
        with tmp.open("wb") as out:
            shutil.copyfileobj(file.file, out)
        data = tmp.read_bytes()
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass

    artefacts = FileSystemArtifactStore(SETTINGS.artefact_root)
    sha = artefacts.put(data, content_type=file.content_type or "application/octet-stream")
    target_id = f"{IDPrefix.TARGET}-{sha[:24].upper()}"
    rec = {
        "id": target_id,
        "project_id": project_id,
        "name": name,
        "sha256": sha,
        "size": len(data),
        "file_type": _peek_file_type(data),
        "authorized_use": True,
        "submitted_at": datetime.now(timezone.utc).isoformat(),
        "path": str(artefacts.path_for(sha)),
    }
    # Persist a target record under data_dir/targets
    from ..storage.filesystem import TargetStore
    TargetStore(SETTINGS.targets_dir).add(_to_target_info(rec))
    # Also keep a copy in data_dir for cheap lookup alongside other records
    (Path(SETTINGS.data_dir) / "targets_index").mkdir(parents=True, exist_ok=True)
    (Path(SETTINGS.data_dir) / "targets_index" / f"{target_id}.json").write_text(
        __import__("json").dumps(rec, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return TargetOut(**rec)


@router.get("", response_model=list[TargetOut])
def list_targets(project_id: str | None = None) -> list[TargetOut]:
    index = Path(SETTINGS.data_dir) / "targets_index"
    if not index.exists():
        return []
    out = []
    import json
    for f in sorted(index.glob("*.json")):
        rec = json.loads(f.read_text(encoding="utf-8"))
        if project_id is not None and rec.get("project_id") != project_id:
            continue
        out.append(TargetOut(**rec))
    return out


@router.get("/{target_id}", response_model=TargetOut)
def get_target(target_id: str) -> TargetOut:
    import json
    p = Path(SETTINGS.data_dir) / "targets_index" / f"{target_id}.json"
    if not p.exists():
        raise HTTPException(404, "target not found")
    return TargetOut(**json.loads(p.read_text(encoding="utf-8")))


def _peek_file_type(data: bytes) -> str:
    if data.startswith(b"MZ"):
        return "pe"
    if data.startswith(b"\x7fELF"):
        return "elf"
    return "raw"


def _to_target_info(rec: dict):
    from ..models.target import TargetInfo
    return TargetInfo(
        id=rec["id"],
        project_id=rec["project_id"],
        name=rec["name"],
        sha256=rec["sha256"],
        size=rec["size"],
        file_type=rec["file_type"],
        submitted_at=rec["submitted_at"],
        authorized_use=rec["authorized_use"],
    )
