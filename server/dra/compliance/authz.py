"""Project-scoped authorization checks.

Phase 0/1 uses a local flag (`authorized_use`) on the Project record.
The full OIDC flow is Phase 2+. The shape of `require_*` functions is
stable so the call sites do not change when we wire in real auth.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class AuthzError(PermissionError):
    """Raised when an action is not allowed for the current project/user."""


class ProjectLike(Protocol):
    authorized_use: bool
    authorization_ref: str | None
    id: str


@dataclass
class AuthzService:
    """Local authz. Replace with OIDC-backed implementation later."""

    strict: bool = True

    def require_project_authorized(self, project: ProjectLike) -> None:
        if not getattr(project, "authorized_use", False):
            if self.strict:
                raise AuthzError(
                    f"project {project.id} is not marked authorized_use=true; "
                    f"set the flag or provide a valid authorization_ref."
                )

    def require_authorization_ref(self, project: ProjectLike) -> str:
        ref = getattr(project, "authorization_ref", None)
        if not ref:
            raise AuthzError(
                f"project {project.id} requires a non-empty authorization_ref"
            )
        return ref

    def is_high_risk_allowed(self, project: ProjectLike) -> bool:
        # HIGH risk only allowed with explicit authorization_ref
        return bool(getattr(project, "authorized_use", False)) and bool(
            getattr(project, "authorization_ref", None)
        )
