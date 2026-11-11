
from typing import Literal

from pydantic import BaseModel, Field

AttackActor = Literal[
    "unprivileged_local_user",
    "sandboxed_process",
    "service_account",
    "local_administrator",
    "remote_attacker",
    "physical",
    "unknown",
]


class Reachability(BaseModel):
    required_privilege: str
    access_conditions: list[str] = Field(default_factory=list)
    interface_exposure: str | None = None
    namespace: str | None = None
    acl: str | None = None
    # No privilege level may be assumed from the presence of an IOCTL
    # interface alone; callers must set this from evidence or leave it
    # unknown.
    attack_actor: AttackActor = "unknown"


class AttackSurfaceItem(BaseModel):
    id: str
    target_id: str
    project_id: str
    kind: str  # "ioctl", "device", "registry", "file", "network", "callback", "export"
    name: str
    address_or_offset: str | None = None
    parameters: dict = Field(default_factory=dict)
    reachability: Reachability
    evidence_ids: list[str] = Field(default_factory=list)
    notes: str | None = None


class AttackSurface(BaseModel):
    id: str
    target_id: str
    project_id: str
    items: list[AttackSurfaceItem] = Field(default_factory=list)
    summary: str | None = None
