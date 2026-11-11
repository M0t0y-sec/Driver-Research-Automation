"""Lab provider abstraction.

The research pipeline must be able to drive a real VM without knowing
which hypervisor backs it.  ``LabProvider`` is the contract every backend
implements; the design doc's lifecycle (Golden Image -> Health Check ->
Disposable VM -> Execute -> Collect -> Destroy) maps onto these calls.

Implementations raise :class:`~dra.lab.errors.LabError` subclasses on
failure.  They never return an empty list to mean "the backend broke":
``[]`` means the backend answered and genuinely has no VMs.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass(frozen=True)
class VMInfo:
    """Normalised view of one VM.

    ``raw`` keeps the backend's machine-readable fields so higher layers
    (health check) can inspect UART/debug configuration without a second
    provider call.
    """

    name: str
    uuid: str | None = None
    state: str | None = None
    ostype: str | None = None
    snapshots: tuple[str, ...] = ()
    raw: dict[str, str] = field(default_factory=dict, compare=False, repr=False)


@dataclass(frozen=True)
class SnapshotInfo:
    name: str
    uuid: str | None = None


class LabProvider(ABC):
    """Contract for a VM lab backend.

    Read-only calls: :meth:`list_vms`, :meth:`vm_info`, :meth:`vm_state`,
    :meth:`list_snapshots`, :meth:`version`.
    State-changing calls: :meth:`start`, :meth:`stop`,
    :meth:`restore_snapshot`, :meth:`create_snapshot`,
    :meth:`set_kernel_debug_serial`, :meth:`destroy_disposable`.
    """

    name: str = "lab"

    @property
    @abstractmethod
    def available(self) -> bool:
        """True when the backend can actually execute commands."""

    @property
    def unavailable_reason(self) -> str:
        """Human-readable explanation when :attr:`available` is False."""
        return f"lab provider {self.name!r} is not available"

    @property
    def guidance(self) -> list[str]:
        """Actionable remediation steps for an unavailable backend."""
        return []

    # --- read-only -------------------------------------------------

    @abstractmethod
    def version(self) -> str:
        """Backend version string."""

    @abstractmethod
    def list_vms(self) -> list[VMInfo]:
        """All registered VMs.  An empty list is a genuine empty result."""

    @abstractmethod
    def vm_info(self, vm: str) -> VMInfo:
        """Full machine-readable info for one VM."""

    @abstractmethod
    def vm_state(self, vm: str) -> str:
        """Current state (``poweroff``, ``running``, ``saved``, ...)."""

    def list_snapshots(self, vm: str) -> list[SnapshotInfo]:
        """Snapshots of one VM.  Default: derive from :meth:`vm_info`."""
        return [SnapshotInfo(name=name) for name in self.vm_info(vm).snapshots]

    def find_vm(self, vm: str) -> VMInfo | None:
        """Match a VM by case-insensitive name or (brace-less) UUID."""
        wanted = vm.strip()
        wanted_uuid = wanted.strip("{}").lower()
        for info in self.list_vms():
            if info.name.strip().lower() == wanted.lower():
                return info
            if info.uuid and info.uuid.strip("{}").lower() == wanted_uuid:
                return info
        return None

    # --- state-changing -------------------------------------------

    @abstractmethod
    def start(self, vm: str, headless: bool = True) -> None:
        """Start a VM; headless by default (lab VMs need no console)."""

    @abstractmethod
    def stop(self, vm: str) -> None:
        """Force-stop a VM (deterministic for disposable experiments)."""

    @abstractmethod
    def restore_snapshot(self, vm: str, snap: str) -> None:
        """Restore a snapshot.  The VM must be powered off."""

    @abstractmethod
    def create_snapshot(self, vm: str, snap: str, description: str | None = None) -> None:
        """Take a snapshot (golden-image maintenance)."""

    @abstractmethod
    def set_kernel_debug_serial(self, vm: str, pipe_name: str) -> None:
        """Wire COM1 to a host named pipe for kernel debugging.

        The VM must be powered off.  Guest-side setup (bcdedit debug on,
        serial debugport:1) is a separate, documented step.
        """

    @abstractmethod
    def destroy_disposable(self, vm: str) -> None:
        """Power off (if needed) and delete a disposable VM and its disks."""
