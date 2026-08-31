"""Debug: trace whether the graph really runs in a TestClient request."""
import shutil, struct
import pytest
from fastapi.testclient import TestClient

from dra.config import SETTINGS
from dra.main import app

import dra.tools.tools.analyze_pe  # noqa
import dra.tools.tools.static_strings  # noqa
import dra.tools.tools.attack_surface_extract  # noqa
import dra.tools.tools.mock_lab  # noqa

import logging
logging.basicConfig(level=logging.INFO)


def test_graph_runs_in_api(tmp_path):
    SETTINGS.__dict__["data_dir"] = tmp_path / "data"
    SETTINGS.__dict__["artifacts_dir"] = tmp_path / "artefacts"
    SETTINGS.__dict__["audit_log_path"] = tmp_path / "data" / "audit.log.jsonl"
    SETTINGS.data_dir.mkdir(parents=True, exist_ok=True)
    SETTINGS.artifacts_dir.mkdir(parents=True, exist_ok=True)

    c = TestClient(app)
    r = c.post("/projects", json={"name": "x", "authorized_use": True, "authorization_ref": "R-1"})
    pid = r.json()["id"]
    blob = (b"MZ" + b"\x00" * 0x3a + struct.pack("<I", 0x40) + b"PE\x00\x00" + b"\x00" * 100)
    r2 = c.post("/targets", data={"project_id": pid, "name": "x.sys"},
                files={"file": ("x.sys", blob, "application/octet-stream")})
    tid = r2.json()["id"]
    print("TID:", tid)
    r3 = c.post("/research/start", json={"project_id": pid, "target_id": tid})
    print("RES:", r3.json())
    assert r3.status_code == 200
    assert r3.json()["status"] == "completed"
    assert r3.json()["finding_ids"]
