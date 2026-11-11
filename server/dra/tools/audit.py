"""Audit service: typed wrapper around the AuditLog JSONL sink."""

from ..storage.filesystem import AuditLog


class AuditService:
    def __init__(self, audit: AuditLog) -> None:
        self.audit = audit

    def record(self, kind: str, **payload) -> None:
        self.audit.record(kind, payload)

    def tail(self, n: int = 200) -> list[dict]:
        return self.audit.tail(n)
