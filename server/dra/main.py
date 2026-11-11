"""FastAPI entry point."""
from __future__ import annotations

import logging

# Compat shim MUST be installed before any router module is imported,
# because the routers instantiate APIRouter at import time.
import dra._compat  # noqa: F401

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import __version__
from .api import dashboard, health, lab, projects, reads, research, targets
from .config import SETTINGS

# Tool registration side-effect imports.
from .tools.tools import analyze_pe  # noqa: E401
from .tools.tools import static_strings  # noqa: F401
from .tools.tools import attack_surface_extract  # noqa: F401
from .tools.tools import poc_generate  # noqa: F401
from .tools.tools import mock_lab  # noqa: F401


logging.basicConfig(
    level=SETTINGS.log_level,
    format="%(asctime)s %(levelname)s %(name)s :: %(message)s",
)
log = logging.getLogger("dra")


def create_app() -> FastAPI:
    app = FastAPI(
        title="DRA — Driver Research Automation",
        version=__version__,
        description="Phase 0/1 server. Local JSON + filesystem storage. Mock LLM / Lab.",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(health.router)
    app.include_router(dashboard.router)
    app.include_router(projects.router)
    app.include_router(targets.router)
    app.include_router(research.router)
    app.include_router(reads.router)
    app.include_router(lab.router)
    return app


app = create_app()
log.info("DRA %s ready (data_dir=%s)", __version__, SETTINGS.data_dir)
