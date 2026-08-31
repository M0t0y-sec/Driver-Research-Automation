"""End-to-end research graph smoke test."""
import asyncio
import shutil
import struct

import pytest

from dra.agents._ops import build_ops
from dra.config import SETTINGS
from dra.graph.main_graph import build_research_graph
from dra.models.common import IDPrefix, new_id
from dra.storage.filesystem import ProjectStore


@pytest.fixture
def fresh_env(tmp_path):
    SETTINGS.__dict__["data_dir"] = tmp_path / "data"
    SETTINGS.__dict__["artifacts_dir"] = tmp_path / "artefacts"
    SETTINGS.__dict__["audit_log_path"] = tmp_path / "audit.log.jsonl"
    SETTINGS.data_dir.mkdir(parents=True, exist_ok=True)
    SETTINGS.artifacts_dir.mkdir(parents=True, exist_ok=True)
    yield tmp_path
    shutil.rmtree(tmp_path, ignore_errors=True)


def test_research_graph_end_to_end(fresh_env):
    import dra.tools.tools.analyze_pe  # noqa: F401
    import dra.tools.tools.static_strings  # noqa: F401
    import dra.tools.tools.attack_surface_extract  # noqa: F401
    import dra.tools.tools.mock_lab  # noqa: F401

    blob = (b"MZ" + b"\x00" * 0x3a + struct.pack("<I", 0x40) +
            b"PE\x00\x00" + b"\x00" * 100)
    target = fresh_env / "demo.sys"
    target.write_bytes(blob)

    pid = new_id(IDPrefix.PROJECT)
    ProjectStore(SETTINGS.projects_dir).add({
        "id": pid, "name": "demo", "authorized_use": True, "authorization_ref": "R-1",
    })

    ops = build_ops()
    graph = build_research_graph(ops)
    result = asyncio.run(graph.run(
        project_id=pid, target_id="TGT-DEMO", target_path=str(target),
    ))
    assert result.get("status") == "completed"
    assert result.get("finding_ids")
    assert result.get("evidence_ids")
    assert result.get("hypothesis_ids")
    assert result.get("qa_review_ids")
