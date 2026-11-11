"""GET /health and /dashboard.

`/health` is the only endpoint that must always be 200 in Phase 0/1
so monitoring / liveness probes work even when storage is empty.
"""

from fastapi import APIRouter

from .. import __version__
from ..config import SETTINGS

router = APIRouter(tags=["health"])


@router.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "version": __version__,
        "data_dir": str(SETTINGS.data_dir),
        "artifacts_dir": str(SETTINGS.artifacts_dir),
        "auth_mode": SETTINGS.auth_mode,
        "llm_provider": SETTINGS.llm_provider,
        "lab_provider": SETTINGS.lab_provider,
        "langgraph": _safe_import_langgraph(),
    }


def _safe_import_langgraph() -> str:
    try:
        import langgraph  # noqa: F401
        return "ok"
    except ImportError as e:
        return f"missing: {e}"
