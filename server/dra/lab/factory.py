"""Provider selection.

``DRA_LAB_PROVIDER`` decides which backend the tools use:

* ``virtualbox`` (or ``vbox``) -> :class:`VirtualBoxProvider`
* anything else / unset          -> :class:`UnavailableLabProvider`

The unavailable backend does not pretend to work.  Every operation
raises :class:`LabUnavailableError` carrying the reason and remediation
steps, so the gateway records a real failure instead of a fake success.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from ..config import SETTINGS
from .errors import LabUnavailableError
from .provider import LabProvider, SnapshotInfo, VMInfo
from .virtualbox import VirtualBoxProvider

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..config import Settings

_PLACEHOLDER_ENVIRONMENT_PREFIXES = ("ENV-", "ENV_")
_PLACEHOLDER_NAMES = {"", "mock", "none", "null", "env-mock"}


class UnavailableLabProvider(LabProvider):
    """Explicitly-unavailable backend used when no real provider is set."""

    name = "unavailable"

    def __init__(self, configured: str, reason: str | None = None) -> None:
        self.configured = configured
        self._reason = reason or (
            f"lab provider {configured!r} is a placeholder; no real VM backend "
            "is configured"
        )

    @property
    def available(self) -> bool:
        return False

    @property
    def unavailable_reason(self) -> str:
        return self._reason

    @property
    def guidance(self) -> list[str]:
        return [
            "Set DRA_LAB_PROVIDER=virtualbox to enable the VirtualBox backend.",
            "Set DRA_LAB_VM=<registered VM name or UUID> and "
            "DRA_LAB_SNAPSHOT=<golden snapshot>.",
            "If VBoxManage is not on PATH, set VBOXMANAGE or DRA_VBOXMANAGE "
            "to the full path of VBoxManage.exe.",
            "Run the lab health check again after configuring the backend.",
        ]

    def _raise(self) -> None:
        raise LabUnavailableError(self._reason, guidance=self.guidance)

    def version(self) -> str:
        self._raise()

    def list_vms(self) -> list[VMInfo]:
        self._raise()

    def vm_info(self, vm: str) -> VMInfo:
        self._raise()

    def vm_state(self, vm: str) -> str:
        self._raise()

    def list_snapshots(self, vm: str) -> list[SnapshotInfo]:
        self._raise()

    def start(self, vm: str, headless: bool = True) -> None:
        self._raise()

    def stop(self, vm: str) -> None:
        self._raise()

    def restore_snapshot(self, vm: str, snap: str) -> None:
        self._raise()

    def create_snapshot(self, vm: str, snap: str, description: str | None = None) -> None:
        self._raise()

    def set_kernel_debug_serial(self, vm: str, pipe_name: str) -> None:
        self._raise()

    def destroy_disposable(self, vm: str) -> None:
        self._raise()


def get_lab_provider(settings: "Settings | None" = None) -> LabProvider:
    """Build the provider configured by settings (default: global SETTINGS)."""
    resolved = settings or SETTINGS
    kind = (getattr(resolved, "lab_provider", "") or "").strip().lower()
    if kind in {"virtualbox", "vbox"}:
        return VirtualBoxProvider(
            exe=getattr(resolved, "lab_vboxmanage", None),
            timeout=float(getattr(resolved, "lab_timeout_seconds", 120.0)),
        )
    configured = kind or "mock"
    if configured == "mock":
        reason = (
            "lab provider 'mock' is a placeholder and no longer returns "
            "fabricated success; configure DRA_LAB_PROVIDER=virtualbox to run "
            "real VM experiments"
        )
    else:
        reason = f"lab provider {configured!r} is not supported"
    return UnavailableLabProvider(configured, reason=reason)


def resolve_vm_name(
    environment_id: str | None,
    settings: "Settings | None" = None,
) -> str | None:
    """Map an environment id to a VM name.

    ``DRA_LAB_VM`` always wins.  Otherwise an environment id that is a real
    name/UUID (not the ``ENV-MOCK`` placeholder) is used as the VM name.
    Returns ``None`` when no VM can be determined, so callers can report
    ``not_available`` with guidance instead of guessing.
    """
    resolved = settings or SETTINGS
    configured = (getattr(resolved, "lab_vm", None) or "").strip()
    if configured:
        return configured

    candidate = (environment_id or "").strip()
    if not candidate:
        return None
    if candidate.lower() in _PLACEHOLDER_NAMES:
        return None
    if any(candidate.upper().startswith(prefix) for prefix in _PLACEHOLDER_ENVIRONMENT_PREFIXES):
        return None
    return candidate


def resolve_snapshot_name(settings: "Settings | None" = None) -> str | None:
    resolved = settings or SETTINGS
    value = (getattr(resolved, "lab_snapshot", None) or "").strip()
    return value or None
