"""Pre-experiment health check.

Design doc section 12.3 requires a health check before every experiment,
otherwise "the experiment failed" and "the environment was broken" cannot
be told apart.  This module checks what the host can actually verify:

* VBoxManage exists and reports a version;
* the target VM exists and is in a usable state;
* the configured golden snapshot exists;
* COM1 is wired to a host pipe for kernel debugging;
* ``kd.exe`` is installed for crash-stack capture.

A missing ``kd.exe`` is a failure with concrete remediation steps, not a
warning: without it a crash cannot be triaged into a root cause.
"""
from __future__ import annotations

import glob as _glob_module
import hashlib
import os
import shutil
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field

from .errors import LabError, VMNotFoundError
from .provider import LabProvider, VMInfo

READY_STATES = {"poweroff", "saved"}
ACTIVE_STATES = {"running", "paused", "restoring", "live-snapshotting", "teleported"}
BROKEN_STATES = {"aborted", "gurumeditation", "guru_meditation"}

STATUS_PASS = "pass"
STATUS_WARN = "warn"
STATUS_FAIL = "fail"

DEFAULT_KD_GLOBS = (
    r"C:\Program Files\Windows Kits\*\Debuggers\x64\kd.exe",
    r"C:\Program Files (x86)\Windows Kits\*\Debuggers\x64\kd.exe",
    r"C:\Program Files\Windows Kits\*\Debuggers\x86\kd.exe",
    r"C:\Program Files (x86)\Windows Kits\*\Debuggers\x86\kd.exe",
)


def _glob_paths(pattern: str) -> list[str]:
    return sorted(_glob_module.glob(pattern))


@dataclass
class KdLocator:
    """Locate ``kd.exe``.

    All filesystem access goes through injectable callables so the health
    check is testable without touching a real SDK installation.
    """

    explicit: str | None = None
    env: Mapping[str, str] | None = None
    which: Callable[[str], str | None] = shutil.which
    exists: Callable[[str], bool] = os.path.isfile
    glob: Callable[[str], Iterable[str]] = _glob_paths
    patterns: tuple[str, ...] = DEFAULT_KD_GLOBS
    configured_missing: str | None = field(default=None, init=False)

    def find(self) -> str | None:
        environment = os.environ if self.env is None else self.env
        configured = self.explicit or environment.get("DRA_KD_PATH")
        if configured:
            if self.exists(configured):
                return configured
            self.configured_missing = configured

        for name in ("kd", "kd.exe"):
            found = self.which(name)
            if found:
                return found

        for pattern in self.patterns:
            matches = list(self.glob(pattern))
            for match in matches:
                if self.exists(match):
                    return match
        return None

    def guidance(self) -> list[str]:
        steps: list[str] = []
        if self.configured_missing:
            steps.append(
                f"DRA_KD_PATH points to {self.configured_missing!r}, but that "
                "file does not exist."
            )
        steps.extend(
            [
                "kd.exe was not found via PATH, DRA_KD_PATH, or the Windows "
                "Kits Debuggers directories.",
                "Install 'Debugging Tools for Windows' from the Windows SDK: "
                "https://developer.microsoft.com/windows/downloads/windows-sdk/ "
                "(select 'Debugging Tools for Windows'), or run "
                "`winget install Microsoft.WinDbg`.",
                r"Default location after SDK install: "
                r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe",
                "Then set DRA_KD_PATH to the full kd.exe path (or add its "
                "folder to PATH) and re-run the health check.",
            ]
        )
        return steps


def find_kd(**kwargs) -> str | None:
    """Convenience wrapper around :class:`KdLocator`."""
    return KdLocator(**kwargs).find()


@dataclass(frozen=True)
class CheckResult:
    status: str
    detail: str
    data: dict = field(default_factory=dict)
    guidance: list[str] = field(default_factory=list)

    @property
    def failed(self) -> bool:
        return self.status == STATUS_FAIL

    def to_dict(self) -> dict:
        payload: dict = {"status": self.status, "detail": self.detail}
        if self.data:
            payload["data"] = self.data
        if self.guidance:
            payload["guidance"] = list(self.guidance)
        return payload


@dataclass(frozen=True)
class HealthReport:
    provider: str
    vm: str | None
    passed: bool
    vm_fingerprint: str | None
    checks: dict[str, CheckResult]

    @property
    def status(self) -> str:
        return "ok" if self.passed else "failed"

    @property
    def failures(self) -> list[str]:
        return [
            f"{name}: {result.detail}"
            for name, result in self.checks.items()
            if result.status == STATUS_FAIL
        ]

    @property
    def warnings(self) -> list[str]:
        return [
            f"{name}: {result.detail}"
            for name, result in self.checks.items()
            if result.status == STATUS_WARN
        ]

    def to_dict(self) -> dict:
        guidance: list[str] = []
        for result in self.checks.values():
            for step in result.guidance:
                if step not in guidance:
                    guidance.append(step)
        return {
            "provider": self.provider,
            "vm": self.vm,
            "passed": self.passed,
            "status": self.status,
            "vm_fingerprint": self.vm_fingerprint,
            "checks": {name: result.to_dict() for name, result in self.checks.items()},
            "failures": self.failures,
            "warnings": self.warnings,
            "guidance": guidance,
        }


def vm_fingerprint(info: VMInfo) -> str:
    material = "|".join(
        [info.name, info.uuid or "", info.ostype or ""]
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _serial_debug_config(raw: Mapping[str, str]) -> tuple[int, str] | None:
    """Return ``(port, raw_uartmode_value)`` for a debug-capable UART."""
    ports: list[int] = []
    for key in raw:
        prefix = "uartmode"
        if key.startswith(prefix) and key[len(prefix):].isdigit():
            ports.append(int(key[len(prefix):]))
    for port in sorted(ports):
        value = raw.get(f"uartmode{port}", "").strip()
        mode = value.split(",", 1)[0].strip().lower()
        if mode in {"server", "tcpserver"}:
            return port, value
    return None


class HealthCheck:
    """Run the pre-experiment checks against one provider/VM."""

    def __init__(
        self,
        provider: LabProvider,
        *,
        vm: str | None = None,
        snapshot: str | None = None,
        kd_locator: KdLocator | None = None,
    ) -> None:
        self.provider = provider
        self.vm = vm
        self.snapshot = snapshot
        self.kd_locator = kd_locator or KdLocator()

    def run(self) -> HealthReport:
        checks: dict[str, CheckResult] = {}

        checks["vboxmanage"] = self._check_vboxmanage()
        if self.vm:
            info = self._check_vm(checks)
        else:
            info = None
            checks["vm_exists"] = CheckResult(
                STATUS_FAIL,
                "no target VM configured",
                guidance=[
                    "Set DRA_LAB_VM to a registered VirtualBox VM name or "
                    "UUID (see `VBoxManage list vms`).",
                ],
            )
        checks["vm_state"] = self._check_state(info)
        checks["snapshot"] = self._check_snapshot(info)
        checks["kernel_debug_serial"] = self._check_serial(info)
        checks["kd_exe"] = self._check_kd()

        passed = not any(result.failed for result in checks.values())
        return HealthReport(
            provider=self.provider.name,
            vm=self.vm,
            passed=passed,
            vm_fingerprint=vm_fingerprint(info) if info else None,
            checks=checks,
        )

    # --- individual checks ----------------------------------------

    def _check_vboxmanage(self) -> CheckResult:
        if not self.provider.available:
            return CheckResult(
                STATUS_FAIL,
                self.provider.unavailable_reason,
                guidance=list(self.provider.guidance),
            )
        try:
            version = self.provider.version()
        except LabError as exc:
            return CheckResult(
                STATUS_FAIL,
                f"VBoxManage is present but not runnable: {exc}",
                guidance=list(self.provider.guidance),
            )
        return CheckResult(
            STATUS_PASS,
            f"VBoxManage {version} is available",
            data={"version": version},
        )

    def _check_vm(self, checks: dict[str, CheckResult]) -> VMInfo | None:
        assert self.vm is not None
        if not self.provider.available:
            checks["vm_exists"] = CheckResult(
                STATUS_FAIL, "not evaluated: VirtualBox provider is unavailable"
            )
            return None
        try:
            info = self.provider.vm_info(self.vm)
        except VMNotFoundError:
            checks["vm_exists"] = CheckResult(
                STATUS_FAIL,
                f"VM {self.vm!r} is not registered with VirtualBox",
                guidance=[
                    "Run `VBoxManage list vms` and set DRA_LAB_VM to a "
                    "registered VM name or UUID.",
                ],
            )
            return None
        except LabError as exc:
            checks["vm_exists"] = CheckResult(
                STATUS_FAIL,
                f"could not query VM {self.vm!r}: {exc}",
                guidance=list(self.provider.guidance),
            )
            return None
        checks["vm_exists"] = CheckResult(
            STATUS_PASS,
            f"VM {info.name!r} exists (UUID {info.uuid or 'unknown'})",
            data={"name": info.name, "uuid": info.uuid, "ostype": info.ostype},
        )
        return info

    def _check_state(self, info: VMInfo | None) -> CheckResult:
        if info is None:
            return CheckResult(
                STATUS_FAIL, "not evaluated: target VM info is unavailable"
            )
        state = info.state
        if not state:
            return CheckResult(
                STATUS_FAIL, "VBoxManage did not report a VM state"
            )
        data = {"state": state}
        if state in READY_STATES:
            return CheckResult(STATUS_PASS, f"VM state is {state!r}", data=data)
        if state in ACTIVE_STATES:
            return CheckResult(
                STATUS_WARN,
                f"VM state is {state!r}; disposable clone / snapshot restore "
                "needs the VM powered off",
                data=data,
                guidance=[
                    "Power the VM off before snapshot restore or disposable "
                    "clone (LabProvider.stop then restore_snapshot).",
                ],
            )
        if state in BROKEN_STATES:
            return CheckResult(
                STATUS_FAIL,
                f"VM state is {state!r}; a previous run crashed or the host "
                "reset the VM. Start it, shut it down cleanly, and retake the "
                "golden snapshot before trusting any experiment result.",
                data=data,
            )
        return CheckResult(
            STATUS_FAIL, f"unrecognised VM state {state!r}", data=data
        )

    def _check_snapshot(self, info: VMInfo | None) -> CheckResult:
        if not self.snapshot:
            return CheckResult(
                STATUS_WARN,
                "no golden snapshot configured; disposable-clone restores "
                "will not be reproducible",
                guidance=[
                    "Set DRA_LAB_SNAPSHOT to a snapshot name, or take one with "
                    "`VBoxManage snapshot <vm> take <name>` while the VM is "
                    "powered off.",
                ],
            )
        if info is None:
            return CheckResult(
                STATUS_FAIL,
                f"cannot verify snapshot {self.snapshot!r}: target VM info is "
                "unavailable",
            )
        if self.snapshot in info.snapshots:
            return CheckResult(
                STATUS_PASS,
                f"snapshot {self.snapshot!r} exists",
                data={"snapshot": self.snapshot, "snapshots": list(info.snapshots)},
            )
        return CheckResult(
            STATUS_FAIL,
            f"snapshot {self.snapshot!r} was not found on VM {info.name!r} "
            f"(available: {list(info.snapshots) or 'none'})",
            data={"snapshot": self.snapshot, "snapshots": list(info.snapshots)},
            guidance=[
                f'Take it first: VBoxManage snapshot "{info.name}" take '
                f'"{self.snapshot}" (VM powered off).',
            ],
        )

    def _check_serial(self, info: VMInfo | None) -> CheckResult:
        if info is None:
            return CheckResult(
                STATUS_FAIL,
                "not evaluated: target VM info is unavailable",
            )
        config = _serial_debug_config(info.raw)
        if config is not None:
            port, value = config
            return CheckResult(
                STATUS_PASS,
                f"COM{port} is wired for kernel debugging ({value})",
                data={"port": port, "uartmode": value},
            )
        pipe = rf"\\.\pipe\kd_{info.name}"
        return CheckResult(
            STATUS_FAIL,
            "no UART is configured as a debug transport (uartmodeN is not "
            "'server' or 'tcpserver'); crash stacks cannot be captured",
            guidance=[
                "Power the VM off, then wire COM1 to a host named pipe: "
                f'VBoxManage modifyvm "{info.name}" --uart1 0x3F8 4 '
                f'--uartmode1 server "{pipe}"',
                "In the guest, enable kernel debugging and reboot: "
                "bcdedit /debug on /dbgsettings serial debugport:1 "
                "baudrate:115200",
                "On the host, attach the debugger: "
                f'kd.exe -k com:pipe,port="{pipe}",resets=0,reconnect',
            ],
        )

    def _check_kd(self) -> CheckResult:
        path = self.kd_locator.find()
        if path:
            return CheckResult(
                STATUS_PASS,
                f"kd.exe found at {path}",
                data={"path": path},
            )
        return CheckResult(
            STATUS_FAIL,
            "kd.exe was not found; crash dumps cannot be triaged into a "
            "root cause",
            guidance=self.kd_locator.guidance(),
        )
