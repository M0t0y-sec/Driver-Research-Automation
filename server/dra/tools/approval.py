"""Approval service: tracks human approvals for HIGH/EXTREME tool calls."""
from __future__ import annotations

from typing import Iterable

from ..models.approval import Approval
from ..models.common import IDPrefix, new_id, utc_now
from ..storage.filesystem import ApprovalStore


class ApprovalService:
    def __init__(self, store: ApprovalStore) -> None:
        self.store = store

    def request(
        self,
        *,
        project_id: str,
        requester: str,
        tool: str,
        risk_level,
        justification: str,
        parameters: dict,
        tool_run_id: str | None = None,
    ) -> Approval:
        a = Approval(
            id=new_id(IDPrefix.APPROVAL),
            project_id=project_id,
            requester=requester,
            tool_run_id=tool_run_id,
            tool=tool,
            risk_level=risk_level,
            justification=justification,
            parameters=parameters,
        )
        self.store.add(a)
        return a

    def decide(self, approval_id: str, *, decision: str, decided_by: str, notes: str | None = None) -> Approval:
        a = self.store.get(approval_id)
        if a is None:
            raise KeyError(approval_id)
        # Pydantic copy with update
        updated = a.model_copy(
            update={
                "decision": decision,
                "decided_by": decided_by,
                "decided_at": utc_now().isoformat(),
                "notes": notes,
            }
        )
        self.store.add(updated)
        return updated

    def pending(self, project_id: str | None = None) -> list[Approval]:
        items = self.store.list()
        if project_id is not None:
            items = [a for a in items if a.project_id == project_id]
        return [a for a in items if a.decision == "pending"]
