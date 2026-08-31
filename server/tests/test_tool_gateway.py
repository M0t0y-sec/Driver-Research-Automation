"""Tool Gateway smoke tests."""
import shutil

import pytest

from dra.tools.gateway import ToolGateway, ToolRequest
from dra.tools.registry import tool
from dra.models.common import RiskLevel
from dra.storage.filesystem import ProjectStore
from dra.config import SETTINGS


@pytest.fixture
def fresh_gateway(tmp_path):
    SETTINGS.__dict__["data_dir"] = tmp_path / "data"
    SETTINGS.__dict__["artifacts_dir"] = tmp_path / "artefacts"
    SETTINGS.__dict__["audit_log_path"] = tmp_path / "audit.log.jsonl"
    for d in (SETTINGS.data_dir, SETTINGS.artifacts_dir):
        d.mkdir(parents=True, exist_ok=True)
    gw = ToolGateway()
    yield gw
    shutil.rmtree(tmp_path, ignore_errors=True)


@tool("smoke.echo", description="echo test", risk_level=RiskLevel.LOW)
def _echo(value: str = "hi") -> dict:
    return {"value": value}


def test_low_risk_runs_and_is_idempotent(fresh_gateway):
    gw = fresh_gateway
    pid = "PRJ-TEST-0001"
    ProjectStore(SETTINGS.projects_dir).add({"id": pid, "authorized_use": True, "authorization_ref": "R-1"})
    req = ToolRequest(project_id=pid, target_id=None, tool="smoke.echo", parameters={"value": "a"}, requester="t")
    r1 = gw.submit(req)
    assert r1.status.value == "succeeded"
    assert r1.result == {"value": "a"}
    r2 = gw.submit(req)
    assert r2.run_id == r1.run_id
    assert r2.status == r1.status


@tool("smoke.hot", description="hot test", risk_level=RiskLevel.HIGH)
def _hot():
    return {"boom": True}


def test_unauthorised_high_risk_is_blocked(fresh_gateway):
    gw = fresh_gateway
    pid = "PRJ-TEST-0002"
    ProjectStore(SETTINGS.projects_dir).add({"id": pid, "authorized_use": False})
    req = ToolRequest(project_id=pid, target_id=None, tool="smoke.hot", parameters={}, requester="t")
    res = gw.submit(req)
    assert res.status.value == "blocked_by_policy"


def test_authorised_high_risk_needs_approval(fresh_gateway):
    gw = fresh_gateway
    pid = "PRJ-TEST-0003"
    ProjectStore(SETTINGS.projects_dir).add({"id": pid, "authorized_use": True, "authorization_ref": "R-1"})
    req = ToolRequest(project_id=pid, target_id=None, tool="smoke.hot", parameters={}, requester="t")
    res = gw.submit(req)
    assert res.status.value == "needs_approval"
    pending = gw.approvals.pending(project_id=pid)
    assert len(pending) == 1
