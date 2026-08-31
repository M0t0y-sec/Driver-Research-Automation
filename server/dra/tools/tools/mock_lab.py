"""Mock Lab controller.

Phase 0/1 returns deterministic, obviously-fake results for VM/snapshot
operations. The contract is the same as the real one; swap in the
Hyper-V / VMware / libvirt driver later.
"""
from __future__ import annotations

from ..registry import tool
from ...models.common import RiskLevel


@tool(
    "lab_health_check",
    description="Mock lab health check. Returns PASS with synthetic fingerprint.",
    risk_level=RiskLevel.MEDIUM,
    parameters_schema={"environment_id": "string"},
)
def lab_health_check(environment_id: str) -> dict:
    return {
        "passed": True,
        "vm_fingerprint": f"mock-fp-{environment_id}",
        "checks": {
            "os_build": "consistent",
            "patch_level": "consistent",
            "driver_signing": "test_signing",
            "security_product": "none",
            "telemetry_collector": "available",
            "time_sync": "ok",
            "disk_free_gb": 64,
        },
    }


@tool(
    "lab_create_snapshot",
    description="Mock snapshot creation.",
    risk_level=RiskLevel.MEDIUM,
    parameters_schema={"environment_id": "string"},
)
def lab_create_snapshot(environment_id: str) -> dict:
    return {
        "snapshot_id": f"SNAP-{environment_id}-0001",
        "vm_fingerprint": f"mock-fp-{environment_id}",
    }


@tool(
    "lab_execute",
    description="Mock experiment execution. Returns a fake result with a fake artefact.",
    risk_level=RiskLevel.HIGH,
    parameters_schema={
        "environment_id": "string",
        "experiment_plan": "ExperimentPlan dict",
    },
)
def lab_execute(environment_id: str, experiment_plan: dict) -> dict:
    return {
        "execution_id": f"EXE-MOCK-{environment_id}",
        "outcome": "inconclusive",
        "trials_total": experiment_plan.get("trial_count", 1),
        "trials_with_signal": 0,
        "log": f"(mock) no real execution performed for {environment_id}",
    }
