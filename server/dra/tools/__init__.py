"""Tool Gateway package.

The gateway is the *only* path through which an Agent touches the
real world. It owns:

- the tool registry (Python callables registered by name)
- policy decisions (LOW/MEDIUM/HIGH/EXTREME)
- approval gating (HIGH/EXTREME -> human in the loop)
- async job lifecycle (queued/running/succeeded/...)
- idempotency (idempotency_key collapses duplicate requests)
- artefact hashing (sha256 + path)
- audit logging (append-only JSONL)
"""
from .registry import ToolRegistry, ToolSpec, tool
from .policy import PolicyEngine, PolicyDecision
from .approval import ApprovalService
from .artifact import ArtefactRef
from .audit import AuditService
from .gateway import ToolGateway, ToolRequest, ToolResult, submit_tool

__all__ = [
    "ToolRegistry",
    "ToolSpec",
    "tool",
    "PolicyEngine",
    "PolicyDecision",
    "ApprovalService",
    "ArtefactRef",
    "AuditService",
    "ToolGateway",
    "ToolRequest",
    "ToolResult",
    "submit_tool",
]
