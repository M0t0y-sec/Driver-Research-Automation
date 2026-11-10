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


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


@dataclass
class Settings:
    server_root: Path
    data_dir: Path
    artifacts_dir: Path
    log_level: str
    auth_mode: str
    llm_provider: str
    lab_provider: str
    # Real-model provider (DRA_LLM_PROVIDER=anthropic). The mock provider
    # ignores these; they are read here so every consumer shares one view.
    anthropic_api_key: str | None = None
    anthropic_model_small: str = "claude-haiku-5-5"
    anthropic_model_mid: str = "claude-sonnet-5-5"
    anthropic_model_large: str = "claude-opus-5-5"
    anthropic_max_tokens: int = 16000
    anthropic_timeout_seconds: float = 300.0
    anthropic_max_retries: int = 2
    # Optional legacy API version pin. Per-task temperature is only sent
    # when this is set below the version that removed sampling parameters
    # (2026-10-21).
    anthropic_api_version: str | None = None

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
        anthropic_api_key=(
            os.environ.get("DRA_ANTHROPIC_API_KEY")
            or os.environ.get("ANTHROPIC_API_KEY")
            or None
        ),
        anthropic_model_small=os.environ.get(
            "DRA_ANTHROPIC_MODEL_SMALL", "claude-haiku-5-5"
        ),
        anthropic_model_mid=os.environ.get(
            "DRA_ANTHROPIC_MODEL_MID", "claude-sonnet-5-5"
        ),
        anthropic_model_large=os.environ.get(
            "DRA_ANTHROPIC_MODEL_LARGE", "claude-opus-5-5"
        ),
        anthropic_max_tokens=_env_int("DRA_ANTHROPIC_MAX_TOKENS", 16000),
        anthropic_timeout_seconds=_env_float("DRA_ANTHROPIC_TIMEOUT", 300.0),
        anthropic_max_retries=_env_int("DRA_ANTHROPIC_MAX_RETRIES", 2),
        anthropic_api_version=os.environ.get("DRA_ANTHROPIC_API_VERSION") or None,
    )


SETTINGS = load_settings()
