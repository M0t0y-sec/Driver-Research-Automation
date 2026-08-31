"""Lab endpoints.

Phase 0/1 reports the (mock) lab health; real VM control is Phase 2+.
"""
from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from ..config import SETTINGS
from ..storage.artifact_store import FileSystemArtifactStore

router = APIRouter(prefix="/lab", tags=["lab"])


class LabHealth(BaseModel):
    provider: str
    passed: bool
    vm_fingerprint: str | None = None
    checks: dict
    notes: str


@router.get("/health", response_model=LabHealth)
def lab_health() -> LabHealth:
    return LabHealth(
        provider=SETTINGS.lab_provider,
        passed=True,
        vm_fingerprint="mock-fp-ENV-MOCK",
        checks={
            "os_build": "consistent",
            "patch_level": "consistent",
            "driver_signing": "test_signing",
            "security_product": "none",
            "telemetry_collector": "available",
        },
        notes="Phase 0/1 mock. Real Hyper-V/VMware/libvirt support is Phase 2+.",
    )


@router.get("/snapshots")
def list_snapshots() -> list[dict]:
    """Phase 0/1 returns the in-process snapshots; real one will list
    the actual VM snapshots from the lab provider."""
    return [{"snapshot_id": "SNAP-ENV-MOCK-0001", "vm_fingerprint": "mock-fp-ENV-MOCK"}]


@router.get("/vms")
def list_vms() -> list[dict]:
    return [{"vm_id": "VM-ENV-MOCK", "state": "ready", "fingerprint": "mock-fp-ENV-MOCK"}]
