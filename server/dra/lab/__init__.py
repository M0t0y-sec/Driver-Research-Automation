"""Real VM lab layer (design doc section 12).

Public surface:

* :class:`LabProvider` -- backend contract
* :class:`VirtualBoxProvider` -- VBoxManage implementation
* :class:`HealthCheck` -- pre-experiment environment validation
* :func:`experiment_fingerprint` -- replay-bundle identity
* :func:`get_lab_provider` -- settings-driven provider factory

No import in this package starts a VM or mutates host state.
"""

from .errors import LabCommandError, LabError, LabUnavailableError, VMNotFoundError
from .factory import UnavailableLabProvider, get_lab_provider, resolve_vm_name, resolve_snapshot_name
from .fingerprint import experiment_fingerprint, sha256_file
from .health import CheckResult, HealthCheck, HealthReport, KdLocator, find_kd, vm_fingerprint
from .provider import LabProvider, SnapshotInfo, VMInfo
from .virtualbox import (
    VirtualBoxProvider,
    normalize_vm_state,
    parse_machinereadable,
    parse_vm_list,
    resolve_vboxmanage,
)

__all__ = [
    "CheckResult",
    "HealthCheck",
    "HealthReport",
    "KdLocator",
    "LabCommandError",
    "LabError",
    "LabProvider",
    "LabUnavailableError",
    "SnapshotInfo",
    "UnavailableLabProvider",
    "VMInfo",
    "VMNotFoundError",
    "VirtualBoxProvider",
    "experiment_fingerprint",
    "find_kd",
    "vm_fingerprint",
    "get_lab_provider",
    "normalize_vm_state",
    "parse_machinereadable",
    "parse_vm_list",
    "resolve_snapshot_name",
    "resolve_vboxmanage",
    "resolve_vm_name",
    "sha256_file",
]
