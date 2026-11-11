"""Artifact store: hash-addressed blob storage with metadata sidecar.

Mirrors a minimal S3-style API. Phase 0/1 stores blobs in
`<artifacts_dir>/<sha256>` and metadata in `<artifacts_dir>/<sha256>.meta.json`.
"""

import hashlib
import shutil
import threading
from pathlib import Path
from typing import Protocol


class ArtifactStore(Protocol):
    def put(self, data: bytes, content_type: str | None = None) -> str: ...
    def get(self, sha256: str) -> bytes | None: ...
    def get_meta(self, sha256: str) -> dict | None: ...
    def exists(self, sha256: str) -> bool: ...
    def path_for(self, sha256: str) -> Path: ...


class FileSystemArtifactStore:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _blob_path(self, sha256: str) -> Path:
        return self.root / sha256

    def _meta_path(self, sha256: str) -> Path:
        return self.root / f"{sha256}.meta.json"

    def put(self, data: bytes, content_type: str | None = None) -> str:
        import json as _json
        import datetime as _dt
        sha = hashlib.sha256(data).hexdigest()
        with self._lock:
            blob = self._blob_path(sha)
            if not blob.exists():
                blob.write_bytes(data)
            meta = self._meta_path(sha)
            if not meta.exists():
                meta.write_text(
                    _json.dumps(
                        {
                            "sha256": sha,
                            "size": len(data),
                            "content_type": content_type or "application/octet-stream",
                            "created_at": _dt.datetime.utcnow().isoformat() + "Z",
                        },
                        ensure_ascii=False,
                    ),
                    encoding="utf-8",
                )
        return sha

    def get(self, sha256: str) -> bytes | None:
        p = self._blob_path(sha256)
        return p.read_bytes() if p.exists() else None

    def get_meta(self, sha256: str) -> dict | None:
        p = self._meta_path(sha256)
        if not p.exists():
            return None
        import json as _json
        return _json.loads(p.read_text(encoding="utf-8"))

    def exists(self, sha256: str) -> bool:
        return self._blob_path(sha256).exists()

    def path_for(self, sha256: str) -> Path:
        return self._blob_path(sha256)

    def write_from_path(self, source: Path, content_type: str | None = None) -> str:
        data = Path(source).read_bytes()
        return self.put(data, content_type=content_type)

    def copy_to(self, sha256: str, dest: Path) -> Path:
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self._blob_path(sha256), dest)
        return dest
