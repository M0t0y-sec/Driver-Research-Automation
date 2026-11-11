"""VirtualBox lab backend.

Drives ``VBoxManage`` via subprocess and parses ``--machinereadable``
output.  The backend is deliberately strict:

* a non-zero exit raises :class:`LabCommandError` carrying stderr;
* a missing executable raises :class:`LabUnavailableError` with install
  guidance;
* an unregistered VM raises :class:`VMNotFoundError`;
* an empty machine-readable reply raises instead of returning ``[]``.

Tests inject a ``runner`` callable, so no real VBoxManage is ever started
by the test suite.
"""

import os
import re
import shutil
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from .errors import LabCommandError, LabError, LabUnavailableError, VMNotFoundError
from .provider import LabProvider, SnapshotInfo, VMInfo

#: A runner receives the full argv (including the executable) and returns a
#: ``subprocess.CompletedProcess``.  The default implementation shells out.
Runner = Callable[[list[str]], "subprocess.CompletedProcess[str]"]

DEFAULT_VBOXMANAGE_PATHS = (
    r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe",
    r"C:\Program Files (x86)\Oracle\VirtualBox\VBoxManage.exe",
    "/usr/bin/VBoxManage",
    "/usr/local/bin/VBoxManage",
    "/opt/VirtualBox/VBoxManage",
)

#: States that must be powered off before ``unregistervm --delete``.
_DESTRUCTIVE_STOP_STATES = {
    "running",
    "paused",
    "restoring",
    "live-snapshotting",
    "teleported",
}


class ExeResolution:
    """Where VBoxManage came from (or why it could not be found)."""

    __slots__ = ("path", "source", "tried")

    def __init__(self, path: str | None, source: str, tried: Sequence[str]) -> None:
        self.path = path
        self.source = source
        self.tried = tuple(tried)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"ExeResolution(path={self.path!r}, source={self.source!r})"


def resolve_vboxmanage(
    exe: str | None = None,
    *,
    env: Mapping[str, str] | None = None,
    which: Callable[[str], str | None] = shutil.which,
    exists: Callable[[str], bool] = os.path.isfile,
) -> ExeResolution:
    """Resolve the VBoxManage executable.

    An explicitly configured path (argument, ``DRA_VBOXMANAGE`` or
    ``VBOXMANAGE``) is authoritative: if it does not exist we report that
    instead of silently falling back to a different installation.
    """
    environment = os.environ if env is None else env
    tried: list[str] = []
    for label, candidate in (
        ("argument", exe),
        ("DRA_VBOXMANAGE", environment.get("DRA_VBOXMANAGE")),
        ("VBOXMANAGE", environment.get("VBOXMANAGE")),
    ):
        if candidate:
            tried.append(candidate)
            if exists(candidate):
                return ExeResolution(candidate, label, tried)
            return ExeResolution(None, label, tried)

    for name in ("VBoxManage", "VBoxManage.exe"):
        found = which(name)
        if found:
            return ExeResolution(found, f"PATH:{name}", tried)
        tried.append(name)

    for candidate in DEFAULT_VBOXMANAGE_PATHS:
        tried.append(candidate)
        if exists(candidate):
            return ExeResolution(candidate, "default-path", tried)

    return ExeResolution(None, "not_found", tried)


def _unquote(raw: str) -> str:
    value = raw.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        value = value[1:-1].replace('""', '"')
    return value


def parse_machinereadable(text: str) -> dict[str, str]:
    """Parse ``VBoxManage ... --machinereadable`` output.

    Handles both forms VBoxManage emits::

        "win10_rev"="{uuid}"        # list vms
        name="win10_rev"            # showvminfo
        uartmode1="server,\\\\.\\\\pipe\\\\kd"

    Keys and values are unquoted; doubled quotes inside values are
    unescaped.  Malformed lines (no ``=``) are ignored because
    ``showvminfo`` also emits a few free-form ``Value:`` lines in some
    versions.
    """
    parsed: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or "=" not in line:
            continue
        key, _, value = line.partition("=")
        parsed[_unquote(key)] = _unquote(value)
    return parsed


_VM_LIST_PLAIN_RE = re.compile(
    r'^\s*"((?:[^"]|"")*)"\s+\{([0-9a-fA-F-]+)\}\s*$'
)


def parse_vm_list(text: str) -> dict[str, str]:
    """Parse ``VBoxManage list vms`` / ``list runningvms`` output.

    VirtualBox 7.2 rejects ``list vms --machinereadable`` (exit code 2,
    "Unknown option"), so the backend uses the plain form::

        "win10_rev" {acc2ff2b-4437-4cce-918b-9bdb931d455a}

    Older builds and other call sites may emit ``name="uuid"`` lines; both
    forms are accepted.  Empty output is a genuine "no VMs" result.
    """
    parsed: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = _VM_LIST_PLAIN_RE.match(line)
        if match:
            name = match.group(1).replace('""', '"')
            parsed[name] = match.group(2)
            continue
        if "=" in line:
            parsed.update(parse_machinereadable(line))
    return parsed


_STATE_ALIASES = {
    "powered off": "poweroff",
    "poweredoff": "poweroff",
    "power off": "poweroff",
    "power-off": "poweroff",
    "powered on": "running",
    "poweredon": "running",
    "power on": "running",
    "power-on": "running",
}


def normalize_vm_state(value: str | None) -> str | None:
    """Normalise VBoxManage's state spelling to ``poweroff``/``running``/..."""
    if not value:
        return None
    state = value.strip().lower()
    return _STATE_ALIASES.get(state, state)


def _collect_snapshots(raw: Mapping[str, str]) -> tuple[str, ...]:
    names: list[str] = []
    seen: set[str] = set()
    keys = ["CurrentSnapshotName", "SnapshotName"]
    keys += sorted(
        (k for k in raw if k.startswith("SnapshotName-")),
        key=lambda k: int(k.rsplit("-", 1)[-1]) if k.rsplit("-", 1)[-1].isdigit() else 0,
    )
    for key in keys:
        value = raw.get(key)
        if value and value not in seen:
            seen.add(value)
            names.append(value)
    return tuple(names)


class VirtualBoxProvider(LabProvider):
    """VirtualBox implementation of :class:`LabProvider`."""

    name = "virtualbox"

    def __init__(
        self,
        exe: str | None = None,
        *,
        runner: Runner | None = None,
        timeout: float = 120.0,
        env: Mapping[str, str] | None = None,
        which: Callable[[str], str | None] = shutil.which,
        exists: Callable[[str], bool] = os.path.isfile,
    ) -> None:
        self._environment = dict(os.environ if env is None else env)
        self._which = which
        self._exists = exists
        self._runner = runner
        self._timeout = float(timeout)
        self._resolution = resolve_vboxmanage(
            exe,
            env=self._environment,
            which=which,
            exists=exists,
        )
        if runner is not None:
            # An injected runner defines the command channel; an explicit
            # exe string may not exist on this host (that is the point of
            # the fake in tests).
            self._exe = self._resolution.path or exe or "VBoxManage"
            self._available = True
        else:
            self._exe = self._resolution.path
            self._available = self._resolution.path is not None

    # --- availability ---------------------------------------------

    @property
    def available(self) -> bool:
        return self._available

    @property
    def executable(self) -> str | None:
        return self._exe

    @property
    def unavailable_reason(self) -> str:
        if self._available:
            return ""
        if self._resolution.source != "not_found" and self._resolution.tried:
            configured = self._resolution.tried[-1]
            return (
                f"VBoxManage was configured via {self._resolution.source} "
                f"but was not found at {configured!r}."
            )
        return (
            "VBoxManage was not found on PATH or in the default VirtualBox "
            "install locations."
        )

    @property
    def guidance(self) -> list[str]:
        return [
            "Install Oracle VirtualBox 7.x: https://www.virtualbox.org/wiki/Downloads",
            r"Default install path: C:\Program Files\Oracle\VirtualBox\VBoxManage.exe",
            "Or set VBOXMANAGE / DRA_VBOXMANAGE to the full path of "
            "VBoxManage.exe, or add its directory to PATH.",
            "Re-run the lab health check after installing or configuring it.",
        ]

    # --- command channel ------------------------------------------

    def _default_runner(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            argv,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=self._timeout,
        )

    def _run(self, *args: str) -> str:
        if not self._available or not self._exe:
            raise LabUnavailableError(self.unavailable_reason, guidance=self.guidance)
        argv = [self._exe, *args]
        runner = self._runner or self._default_runner
        try:
            completed = runner(argv)
        except subprocess.TimeoutExpired as exc:
            raise LabCommandError(
                argv,
                -1,
                _as_text(exc.stdout),
                _as_text(exc.stderr),
                message=(
                    f"VBoxManage timed out after {self._timeout:g}s: "
                    f"{' '.join(argv)}"
                ),
            ) from exc
        except OSError as exc:
            raise LabUnavailableError(
                f"could not execute VBoxManage at {self._exe!r}: {exc}",
                guidance=self.guidance,
            ) from exc

        stdout = _as_text(getattr(completed, "stdout", ""))
        stderr = _as_text(getattr(completed, "stderr", ""))
        returncode = completed.returncode
        if returncode != 0:
            raise LabCommandError(argv, returncode, stdout, stderr)
        return stdout

    # --- read-only ------------------------------------------------

    def version(self) -> str:
        text = self._run("--version").strip()
        if not text:
            raise LabError("VBoxManage --version returned no output")
        return text.splitlines()[0].strip()

    def list_vms(self) -> list[VMInfo]:
        registered = parse_vm_list(self._run("list", "vms"))
        running = parse_vm_list(self._run("list", "runningvms"))
        vms: list[VMInfo] = []
        for name, uuid in registered.items():
            vms.append(
                VMInfo(
                    name=name,
                    uuid=uuid or None,
                    state="running" if name in running else None,
                )
            )
        # Defensive: a VM can be reported running but missing from `list vms`
        # only if it was unregistered mid-call; surface it rather than hide it.
        known = {info.name for info in vms}
        for name, uuid in running.items():
            if name not in known:
                vms.append(VMInfo(name=name, uuid=uuid or None, state="running"))
        return vms

    def vm_info(self, vm: str) -> VMInfo:
        try:
            text = self._run("showvminfo", vm, "--machinereadable")
        except LabCommandError as exc:
            haystack = f"{exc.stderr}\n{exc.stdout}".lower()
            if "could not find a registered machine" in haystack or (
                "machine" in haystack and "not registered" in haystack
            ):
                raise VMNotFoundError(vm, stderr=exc.stderr) from exc
            raise
        raw = parse_machinereadable(text)
        if not raw:
            raise LabError(
                f"VBoxManage showvminfo returned no machine-readable fields "
                f"for {vm!r}; refusing to report an empty VM record"
            )
        return VMInfo(
            name=raw.get("name") or vm,
            uuid=raw.get("UUID") or None,
            state=normalize_vm_state(raw.get("VMState") or raw.get("SessionState")),
            ostype=raw.get("ostype") or None,
            snapshots=_collect_snapshots(raw),
            raw=raw,
        )

    def vm_state(self, vm: str) -> str:
        state = self.vm_info(vm).state
        if not state:
            raise LabError(
                f"VBoxManage did not report a state for VM {vm!r} "
                "(no VMState field in --machinereadable output)"
            )
        return state

    def list_snapshots(self, vm: str) -> list[SnapshotInfo]:
        raw = self.vm_info(vm).raw
        snapshots: list[SnapshotInfo] = []
        for name in _collect_snapshots(raw):
            uuid = None
            if raw.get("SnapshotName") == name:
                uuid = raw.get("SnapshotUUID") or None
            else:
                for key, value in raw.items():
                    if key.startswith("SnapshotUUID-") and raw.get(f"SnapshotName-{key.rsplit('-', 1)[-1]}") == name:
                        uuid = value or None
                        break
            snapshots.append(SnapshotInfo(name=name, uuid=uuid))
        return snapshots

    # --- state-changing -------------------------------------------

    def start(self, vm: str, headless: bool = True) -> None:
        self._require(vm, "vm")
        vm_type = "headless" if headless else "gui"
        self._run("startvm", vm, "--type", vm_type)

    def stop(self, vm: str) -> None:
        self._require(vm, "vm")
        self._run("controlvm", vm, "poweroff")

    def restore_snapshot(self, vm: str, snap: str) -> None:
        self._require(vm, "vm")
        self._require(snap, "snapshot")
        self._run("snapshot", vm, "restore", snap)

    def create_snapshot(
        self, vm: str, snap: str, description: str | None = None
    ) -> None:
        self._require(vm, "vm")
        self._require(snap, "snapshot")
        args = ["snapshot", vm, "take", snap]
        if description:
            args += ["--description", description]
        self._run(*args)

    def set_kernel_debug_serial(self, vm: str, pipe_name: str) -> None:
        self._require(vm, "vm")
        self._require(pipe_name, "pipe_name")
        if "\r" in pipe_name or "\n" in pipe_name:
            raise ValueError("pipe_name must not contain newlines")
        # COM1 at the standard 0x3F8/IRQ4, exposed as a host named pipe.
        # The VM must be powered off for modifyvm.
        self._run(
            "modifyvm",
            vm,
            "--uart1",
            "0x3F8",
            "4",
            "--uartmode1",
            "server",
            pipe_name,
        )

    def destroy_disposable(self, vm: str) -> None:
        self._require(vm, "vm")
        info = self.vm_info(vm)
        if info.state in _DESTRUCTIVE_STOP_STATES:
            self._run("controlvm", vm, "poweroff")
        self._run("unregistervm", vm, "--delete")

    @staticmethod
    def _require(value: str, label: str) -> None:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{label} must be a non-empty string")


def _as_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)
