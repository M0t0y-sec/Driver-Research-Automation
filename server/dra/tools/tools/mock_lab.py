"""Lab tools backed by the configured provider (no fabricated results).

The previous implementation always returned success with a synthetic
fingerprint (``mock-fp-...``) even though no VM existed.  That made every
downstream "experiment passed" claim meaningless.  These tools now:

* delegate to :func:`dra.lab.get_lab_provider`;
* run the real health check when a VirtualBox backend is configured;
* return an explicit ``not_available`` payload (with remediation steps)
  when no real backend or execution harness exists.

They never invent an execution id, a fingerprint, or a trial outcome.
"""

from datetime import datetime, timezone

from ..registry import tool
from ...config import SETTINGS
from ...lab import HealthCheck, LabError, get_lab_provider, resolve_vm_name, vm_fingerprint
from ...models.common import RiskLevel


def _not_available(
    provider,
    environment_id: str,
    *,
    code: str,
    message: str | None = None,
    extra_guidance: list[str] | None = None,
) -> dict:
    guidance = list(provider.guidance) if not provider.available else []
    for step in extra_guidance or []:
        if step not in guidance:
            guidance.append(step)
    return {
        "status": "not_available",
        "passed": False,
        "provider": provider.name,
        "environment_id": environment_id,
        "vm": None,
        "vm_fingerprint": None,
        "checks": {},
        "notes": message or provider.unavailable_reason,
        "guidance": guidance,
        "error": {
            "code": code,
            "message": message or provider.unavailable_reason,
        },
    }


@tool(
    "lab_health_check",
    description=(
        "Pre-experiment lab health check. Runs real VBoxManage read-only "
        "queries and kd.exe detection; reports not_available when no real "
        "backend is configured."
    ),
    risk_level=RiskLevel.MEDIUM,
    parameters_schema={"environment_id": "string (VM name, or ENV-* when DRA_LAB_VM is set)"},
)
def lab_health_check(environment_id: str) -> dict:
    provider = get_lab_provider(SETTINGS)
    if not provider.available:
        return _not_available(
            provider, environment_id, code="lab_provider_not_available"
        )

    vm = resolve_vm_name(environment_id, SETTINGS)
    if not vm:
        return _not_available(
            provider,
            environment_id,
            code="lab_vm_not_configured",
            message=(
                f"no VM could be resolved for environment {environment_id!r}; "
                "set DRA_LAB_VM to a registered VirtualBox VM"
            ),
            extra_guidance=[
                "Run `VBoxManage list vms` and set DRA_LAB_VM to the target "
                "VM name or UUID.",
            ],
        )

    report = HealthCheck(
        provider,
        vm=vm,
        snapshot=(SETTINGS.lab_snapshot or None),
    ).run()
    result = report.to_dict()
    result.update(
        {
            "tool": "lab_health_check",
            "environment_id": environment_id,
        }
    )
    return result


@tool(
    "lab_create_snapshot",
    description=(
        "Create a snapshot on the configured lab VM. Reports not_available "
        "when no real backend is configured."
    ),
    risk_level=RiskLevel.MEDIUM,
    parameters_schema={
        "environment_id": "string",
        "snapshot_name": "optional snapshot name",
    },
)
def lab_create_snapshot(environment_id: str, snapshot_name: str | None = None) -> dict:
    provider = get_lab_provider(SETTINGS)
    if not provider.available:
        result = _not_available(
            provider, environment_id, code="lab_provider_not_available"
        )
        result["snapshot_id"] = None
        return result

    vm = resolve_vm_name(environment_id, SETTINGS)
    if not vm:
        result = _not_available(
            provider,
            environment_id,
            code="lab_vm_not_configured",
            message=(
                f"no VM could be resolved for environment {environment_id!r}; "
                "set DRA_LAB_VM to a registered VirtualBox VM"
            ),
        )
        result["snapshot_id"] = None
        return result

    name = snapshot_name or (
        "SNAP-"
        + (environment_id or "LAB").replace(" ", "_")
        + "-"
        + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    )
    provider.create_snapshot(vm, name)
    info = provider.vm_info(vm)
    return {
        "status": "created",
        "provider": provider.name,
        "environment_id": environment_id,
        "vm": vm,
        "snapshot_id": name,
        "vm_fingerprint": vm_fingerprint(info),
    }


@tool(
    "lab_execute",
    description=(
        "Execute an experiment in the lab. No in-guest execution harness is "
        "implemented yet, so this reports not_available instead of inventing "
        "trial results."
    ),
    risk_level=RiskLevel.HIGH,
    parameters_schema={
        "environment_id": "string",
        "experiment_plan": "ExperimentPlan dict",
    },
)
def lab_execute(environment_id: str, experiment_plan: dict) -> dict:
    provider = get_lab_provider(SETTINGS)
    if not provider.available:
        message = (
            "no real lab backend is configured, so the experiment was not "
            "executed"
        )
        result = _not_available(
            provider,
            environment_id,
            code="lab_provider_not_available",
            message=message,
        )
    else:
        message = (
            "the VirtualBox backend can create/restore VMs, but DRA has no "
            "in-guest deploy/execute/collect harness yet; the experiment was "
            "not executed and no trial result is available"
        )
        result = {
            "status": "not_available",
            "passed": False,
            "provider": provider.name,
            "environment_id": environment_id,
            "vm": None,
            "vm_fingerprint": None,
            "notes": message,
            "guidance": [
                "Implement the guest agent (deploy PoC, run it, collect crash "
                "dump + serial debug output) before enabling lab_execute.",
            ],
            "error": {
                "code": "execution_harness_not_implemented",
                "message": message,
            },
        }

    try:
        trial_count = int(experiment_plan.get("trial_count", 1))
    except (AttributeError, TypeError, ValueError):
        trial_count = 1
    result.update(
        {
            "tool": "lab_execute",
            "execution_id": None,
            "outcome": "error",
            "trials_total": max(trial_count, 1),
            "trials_with_signal": 0,
            "log": message,
        }
    )
    return result


# ``LabError`` is re-exported so callers importing this module for its tools
# can catch provider failures without a second import.
__all__ = ["lab_health_check", "lab_create_snapshot", "lab_execute", "LabError"]
