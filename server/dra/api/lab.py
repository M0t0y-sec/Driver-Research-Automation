"""Lab endpoints backed by the configured provider.

``GET /lab/health`` runs the real health check (read-only VBoxManage
queries plus kd.exe detection).  When no real backend is configured the
endpoint says ``not_available`` with remediation steps instead of
returning a synthetic success.  VM/snapshot listings return 503 with the
same explicit detail rather than an empty or fake list.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ..config import SETTINGS
from ..lab import (
    HealthCheck,
    LabError,
    get_lab_provider,
    resolve_snapshot_name,
    resolve_vm_name,
    vm_fingerprint,
)

router = APIRouter(prefix="/lab", tags=["lab"])


class LabHealth(BaseModel):
    provider: str
    passed: bool
    status: str = "ok"
    vm: str | None = None
    vm_fingerprint: str | None = None
    checks: dict = Field(default_factory=dict)
    notes: str = ""
    guidance: list[str] = Field(default_factory=list)
    failures: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def _configured_vm() -> str | None:
    return resolve_vm_name("ENV-MOCK", SETTINGS)


def _unavailable_health(provider) -> LabHealth:
    return LabHealth(
        provider=provider.name,
        passed=False,
        status="not_available",
        notes=provider.unavailable_reason,
        guidance=list(provider.guidance),
    )


def _provider_or_503():
    provider = get_lab_provider(SETTINGS)
    if not provider.available:
        raise HTTPException(
            status_code=503,
            detail={
                "status": "not_available",
                "provider": provider.name,
                "message": provider.unavailable_reason,
                "guidance": list(provider.guidance),
            },
        )
    return provider


def _vm_or_503(provider) -> str:
    vm = _configured_vm()
    if not vm:
        raise HTTPException(
            status_code=503,
            detail={
                "status": "not_available",
                "provider": provider.name,
                "message": (
                    "no lab VM configured; set DRA_LAB_VM to a registered "
                    "VirtualBox VM name or UUID"
                ),
                "guidance": [
                    "Run `VBoxManage list vms` and set DRA_LAB_VM to the "
                    "target VM name or UUID.",
                ],
            },
        )
    return vm


@router.get("/health", response_model=LabHealth)
def lab_health() -> LabHealth:
    provider = get_lab_provider(SETTINGS)
    if not provider.available:
        return _unavailable_health(provider)

    vm = _configured_vm()
    if not vm:
        result = _unavailable_health(provider)
        result.status = "not_available"
        result.notes = (
            "no lab VM configured; set DRA_LAB_VM to a registered VirtualBox "
            "VM name or UUID"
        )
        result.guidance = [
            "Run `VBoxManage list vms` and set DRA_LAB_VM to the target VM "
            "name or UUID.",
        ]
        return result

    report = HealthCheck(
        provider,
        vm=vm,
        snapshot=resolve_snapshot_name(SETTINGS),
    ).run()
    data = report.to_dict()
    if data["passed"]:
        notes = "all lab health checks passed"
    else:
        notes = "; ".join(data["failures"])
    return LabHealth(
        provider=provider.name,
        passed=data["passed"],
        status=data["status"],
        vm=vm,
        vm_fingerprint=data["vm_fingerprint"],
        checks=data["checks"],
        notes=notes,
        guidance=data["guidance"],
        failures=data["failures"],
        warnings=data["warnings"],
    )


@router.get("/snapshots")
def list_snapshots() -> list[dict]:
    provider = _provider_or_503()
    vm = _vm_or_503(provider)
    try:
        info = provider.vm_info(vm)
    except LabError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    fingerprint = vm_fingerprint(info)
    return [
        {
            "snapshot_id": name,
            "vm": info.name,
            "vm_fingerprint": fingerprint,
        }
        for name in info.snapshots
    ]


@router.get("/vms")
def list_vms() -> list[dict]:
    provider = _provider_or_503()
    try:
        vms = provider.list_vms()
    except LabError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return [
        {
            "vm_id": info.name,
            "uuid": info.uuid,
            "state": info.state,
            "ostype": info.ostype,
        }
        for info in vms
    ]
