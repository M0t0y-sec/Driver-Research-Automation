"""Explicit errors for lab operations.

The lab layer never turns a failed VBoxManage call into an empty list or a
fabricated success.  Every failure carries what the operator needs to act
on: the command that failed, its exit code, and VBoxManage's stderr.
"""
from __future__ import annotations

from collections.abc import Sequence


class LabError(Exception):
    """Base class for every lab-layer failure."""


class LabUnavailableError(LabError):
    """The configured backend (or a required tool) is not available.

    ``guidance`` holds concrete remediation steps.  Callers that build a
    report (health check, API) surface this list instead of swallowing it.
    """

    def __init__(self, message: str, *, guidance: Sequence[str] = ()) -> None:
        self.guidance = list(guidance)
        super().__init__(message)


class LabCommandError(LabError):
    """A backend command exited non-zero (or timed out).

    Attributes mirror ``subprocess.CompletedProcess`` so callers can log
    the exact stderr rather than a generic message.
    """

    def __init__(
        self,
        argv: Sequence[str],
        returncode: int,
        stdout: str = "",
        stderr: str = "",
        *,
        message: str | None = None,
    ) -> None:
        self.argv = list(argv)
        self.returncode = returncode
        self.stdout = stdout or ""
        self.stderr = stderr or ""
        detail = (self.stderr or self.stdout).strip()
        if message is None:
            message = (
                f"VBoxManage failed with exit code {returncode}: "
                f"{' '.join(self.argv)}"
            )
            if detail:
                message += f"\n{detail}"
        super().__init__(message)


class VMNotFoundError(LabError):
    """The VM is not registered with the backend.

    ``stderr`` keeps VBoxManage's original message so callers can show the
    backend's own wording (and not just our paraphrase).
    """

    def __init__(self, vm: str, *, stderr: str = "") -> None:
        self.vm = vm
        self.stderr = stderr or ""
        message = (
            f"VM {vm!r} is not registered with VirtualBox. "
            "Run `VBoxManage list vms` to see the available names/UUIDs."
        )
        detail = self.stderr.strip()
        if detail:
            message += f"\n{detail}"
        super().__init__(message)
