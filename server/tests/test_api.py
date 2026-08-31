"""FastAPI smoke test using TestClient."""
import shutil
import struct

import pytest
from fastapi.testclient import TestClient

from dra.config import SETTINGS
from dra.main import app


def _set_paths(tmp_path):
    SETTINGS.__dict__["data_dir"] = tmp_path / "data"
    SETTINGS.__dict__["artifacts_dir"] = tmp_path / "artefacts"
    SETTINGS.__dict__["audit_log_path"] = tmp_path / "data" / "audit.log.jsonl"
    for d in (SETTINGS.data_dir, SETTINGS.artifacts_dir):
        d.mkdir(parents=True, exist_ok=True)


@pytest.fixture
def client(tmp_path):
    _set_paths(tmp_path)
    yield TestClient(app)
    shutil.rmtree(tmp_path, ignore_errors=True)


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["version"] == "0.1.0"


def test_project_lifecycle(client):
    r = client.post("/projects", json={"name": "demo", "authorized_use": False})
    assert r.status_code == 201
    pid = r.json()["id"]
    r2 = client.get(f"/projects/{pid}")
    assert r2.status_code == 200
    r3 = client.get("/projects")
    assert r3.status_code == 200
    assert any(p["id"] == pid for p in r3.json())


def test_unauthorised_target_upload_rejected(client):
    r = client.post("/projects", json={"name": "demo", "authorized_use": False})
    pid = r.json()["id"]
    blob = (b"MZ" + b"\x00" * 0x3a + struct.pack("<I", 0x40) +
            b"PE\x00\x00" + b"\x00" * 100)
    files = {"file": ("demo.sys", blob, "application/octet-stream")}
    r2 = client.post("/targets", data={"project_id": pid, "name": "demo.sys"}, files=files)
    assert r2.status_code == 403


def test_authorised_target_upload_and_research(client):
    r = client.post("/projects", json={
        "name": "demo", "authorized_use": True, "authorization_ref": "R-1",
    })
    pid = r.json()["id"]
    blob = (b"MZ" + b"\x00" * 0x3a + struct.pack("<I", 0x40) +
            b"PE\x00\x00" + b"\x00" * 100)
    files = {"file": ("demo.sys", blob, "application/octet-stream")}
    r2 = client.post("/targets", data={"project_id": pid, "name": "demo.sys"}, files=files)
    assert r2.status_code == 201, r2.text
    tid = r2.json()["id"]
    r3 = client.post("/research/start", json={"project_id": pid, "target_id": tid})
    assert r3.status_code == 200, r3.text
    body = r3.json()
    assert body["status"] == "completed", body
    assert body["finding_ids"], body
    fid = body["finding_ids"][0]
    r4 = client.get(f"/findings/{fid}/evidence-chain")
    assert r4.status_code == 200
    chain = r4.json()
    assert any(n["type"] == "evidence" for n in chain["lineage"]["nodes"])
    r5 = client.get(f"/projects/{pid}/lineage")
    assert r5.status_code == 200
    types = {n["type"] for n in r5.json()["nodes"]}
    assert "project" in types
    assert "finding" in types
