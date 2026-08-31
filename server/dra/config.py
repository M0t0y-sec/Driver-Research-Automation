"""Centralised configuration for the DRA server.

Reads environment variables (with safe defaults) and exposes a single
`Settings` instance. We deliberately avoid `pydantic-settings` to keep
the dependency surface small; the team can swap in `BaseSettings` later
without changing call sites.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _resolve(base: Path, override: str | None, default_relative: str) -> Path:
    if override:
        return Path(override).expanduser().resolve()
    return (base / default_relative).resolve()


@dataclass
class Settings:
    server_root: Path
    data_dir: Path
    artifacts_dir: Path
    log_level: str
    auth_mode: str
    llm_provider: str
    lab_provider: str

    @property
    def projects_dir(self) -> Path:
        return self.data_dir / "projects"

    @property
    def targets_dir(self) -> Path:
        return self.data_dir / "targets"

    @property
    def research_dir(self) -> Path:
        return self.data_dir / "research"

    @property
    def evidence_dir(self) -> Path:
        return self.data_dir / "evidence"

    @property
    def findings_dir(self) -> Path:
        return self.data_dir / "findings"

    @property
    def approvals_dir(self) -> Path:
        return self.data_dir / "approvals"

    @property
    def tool_runs_dir(self) -> Path:
        return self.data_dir / "tool_runs"

    @property
    def audit_log_path(self) -> Path:
        return self.data_dir / "audit.log.jsonl"

    @property
    def artefact_root(self) -> Path:
        return self.artifacts_dir


def load_settings() -> Settings:
    here = Path(__file__).resolve().parent.parent  # server/
    repo_root = here.parent  # Driver Research Automation/

    data_dir = _resolve(repo_root, os.environ.get("DRA_DATA_DIR"), "artifacts/data")
    artifacts_dir = _resolve(repo_root, os.environ.get("DRA_ARTIFACTS_DIR"), "artifacts/artefacts")

    # Ensure directories exist
    for d in (data_dir, artifacts_dir):
        d.mkdir(parents=True, exist_ok=True)

    return Settings(
        server_root=here,
        data_dir=data_dir,
        artifacts_dir=artifacts_dir,
        log_level=os.environ.get("DRA_LOG_LEVEL", "INFO"),
        auth_mode=os.environ.get("DRA_AUTH_MODE", "local"),
        llm_provider=os.environ.get("DRA_LLM_PROVIDER", "mock"),
        lab_provider=os.environ.get("DRA_LAB_PROVIDER", "mock"),
    )


SETTINGS = load_settings()
