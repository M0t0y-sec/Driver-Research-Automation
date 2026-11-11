"""Tool Gateway: async, idempotent, audit-logged, policy-aware tool runner.

Phase 0/1 runs the tool synchronously in-process (Python `concurrent.futures`
or simply the calling thread). The async interface is preserved so the
implementation can be swapped for a queue/worker model without
touching callers.
"""

import hashlib
import json
import traceback
from concurrent.futures import Future
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..config import SETTINGS
from ..models.common import (
    IDPrefix,
    RiskLevel,
    ToolRunStatus,
    new_id,
)
from ..models.tool_run import ToolRun
from ..storage.artifact_store import FileSystemArtifactStore
from ..storage.filesystem import (
    AuditLog,
    ProjectStore,
    ToolRunStore,
)
from .approval import ApprovalService
from .artifact import ArtefactRef
from .audit import AuditService
from .policy import PolicyContext, PolicyDecision, PolicyEngine
from .registry import ToolRegistry, ToolSpec
from ..storage.filesystem import ApprovalStore as _ApprovalStore

# A module-level default registry. Tools register themselves via
# `@tool(...)` on import. Tests can build their own gateway with a
# private registry.
_default_registry = ToolRegistry()


def _ensure_builtin_tools() -> None:
    """Import the built-in tool package so its ``@tool`` registrations run.

    Registration is an import side effect. Any caller that imports this
    module directly (agents, CLI, scripts, tests) never touches
    ``dra.tools.tools``, so without this the registry stays empty and every
    call fails with "unknown tool" — which agents used to swallow silently,
    turning a broken pipeline into a plausible-looking empty result.
    """
    from . import tools as _builtin_tools  # noqa: F401


def get_default_registry() -> ToolRegistry:
    _ensure_builtin_tools()
    return _default_registry


@dataclass
class ToolRequest:
    project_id: str
    target_id: str | None
    tool: str
    parameters: dict
    requester: str  # agent name or user id
    idempotency_key: str | None = None
    timeout_seconds: int = 3600
    priority: str = "normal"
    approval_id: str | None = None
    request_id: str | None = None

    def key(self) -> str:
        if self.idempotency_key:
            return self.idempotency_key
        h = hashlib.sha256(
            json.dumps(
                {
                    "project": self.project_id,
                    "target": self.target_id,
                    "tool": self.tool,
                    "params": self.parameters,
                },
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        return h


@dataclass
class ToolResult:
    run_id: str
    status: ToolRunStatus
    result: Any = None
    error: str | None = None
    artefacts: list[ArtefactRef] = field(default_factory=list)


class ToolGateway:
    def __init__(
        self,
        *,
        registry: ToolRegistry | None = None,
        policy: PolicyEngine | None = None,
        approvals: ApprovalService | None = None,
        tool_runs: ToolRunStore | None = None,
        projects: ProjectStore | None = None,
        audit: AuditService | None = None,
        artefact_store: FileSystemArtifactStore | None = None,
    ) -> None:
        self.registry = registry or get_default_registry()
        self.policy = policy or PolicyEngine()
        self.audit = audit or AuditService(AuditLog(SETTINGS.audit_log_path))
        self.tool_runs = tool_runs or ToolRunStore(SETTINGS.tool_runs_dir)
        self.projects = projects or ProjectStore(SETTINGS.projects_dir)
        self.approvals = approvals or ApprovalService(
            _ApprovalStore(SETTINGS.approvals_dir)
        )
        self.artefact_store = artefact_store or FileSystemArtifactStore(SETTINGS.artefact_root)

    # --- public API ---

    def submit(self, req: ToolRequest) -> ToolResult:
        # Idempotency: collapse duplicate submissions.
        existing = self._find_idempotent(req)
        if existing is not None:
            self.audit.record("tool.idempotent_hit", run_id=existing.id, key=req.key())
            return ToolResult(
                run_id=existing.id,
                status=existing.status,
                result=existing.result,
                error=existing.error,
                artefacts=[ArtefactRef(**a) for a in existing.artifact_refs],
            )

        # Project authorization context
        project = self.projects.get(req.project_id)
        authorized = bool(project and project.get("authorized_use", False))
        authz_ref = project.get("authorization_ref") if project else None
        ctx = PolicyContext(project_authorized=authorized, authorization_ref=authz_ref)

        # Resolve tool
        try:
            spec, fn = self.registry.get(req.tool)
        except KeyError as e:
            return self._failed_run(req, f"unknown tool: {e}", ToolRunStatus.FAILED)

        # Policy decision
        decision = self.policy.decide(req.tool, spec.risk_level, ctx)
        if decision == PolicyDecision.BLOCKED:
            return self._failed_run(
                req,
                f"tool {req.tool!r} is blocked by policy (risk={spec.risk_level})",
                ToolRunStatus.BLOCKED_BY_POLICY,
            )
        if decision == PolicyDecision.NEEDS_APPROVAL and not req.approval_id:
            # Persist a ToolRun in NEEDS_APPROVAL state + an Approval request
            run = self._new_run(req, spec)
            run.status = ToolRunStatus.NEEDS_APPROVAL
            self.tool_runs.add(run)
            approval = self.approvals.request(
                project_id=req.project_id,
                requester=req.requester,
                tool=req.tool,
                risk_level=spec.risk_level,
                justification=f"Requested by {req.requester} for project {req.project_id}",
                parameters=req.parameters,
                tool_run_id=run.id,
            )
            self.audit.record(
                "tool.needs_approval",
                run_id=run.id,
                approval_id=approval.id,
                tool=req.tool,
                risk=spec.risk_level.value,
            )
            return ToolResult(run_id=run.id, status=run.status, error="awaiting approval")

        # Run
        run = self._new_run(req, spec)
        run.status = ToolRunStatus.RUNNING
        run.started_at = _now_iso()
        self.tool_runs.add(run)
        self.audit.record("tool.started", run_id=run.id, tool=req.tool)

        try:
            raw_result = self._invoke(fn, req.parameters, req.timeout_seconds)
            artefacts = self._collect_artefacts(raw_result)
            run.status = ToolRunStatus.SUCCEEDED
            run.result = _scrub_for_storage(raw_result)
            run.artifact_refs = [a.to_dict() for a in artefacts]
            run.finished_at = _now_iso()
            self.tool_runs.add(run)
            self.audit.record("tool.succeeded", run_id=run.id, n_artefacts=len(artefacts))
            return ToolResult(
                run_id=run.id,
                status=run.status,
                result=run.result,
                artefacts=artefacts,
            )
        except TimeoutError as e:
            run.status = ToolRunStatus.TIMEOUT
            run.error = str(e)
            run.finished_at = _now_iso()
            self.tool_runs.add(run)
            self.audit.record("tool.timeout", run_id=run.id)
            return ToolResult(run_id=run.id, status=run.status, error=run.error)
        except Exception as e:  # noqa: BLE001 - tool failures are heterogeneous
            run.status = ToolRunStatus.FAILED
            run.error = f"{e}\n{traceback.format_exc(limit=4)}"
            run.finished_at = _now_iso()
            self.tool_runs.add(run)
            self.audit.record("tool.failed", run_id=run.id, error=str(e))
            return ToolResult(run_id=run.id, status=run.status, error=run.error)

    def get_run(self, run_id: str) -> ToolRun | None:
        return self.tool_runs.get(run_id)

    def list_runs(self, project_id: str | None = None) -> list[ToolRun]:
        items = self.tool_runs.list()
        if project_id is not None:
            items = [r for r in items if r.project_id == project_id]
        return items

    # --- internals ---

    def _find_idempotent(self, req: ToolRequest) -> ToolRun | None:
        for r in self.tool_runs.list(project_id=req.project_id):
            if r.tool != req.tool:
                continue
            if r.parameters_hash and r.parameters_hash == req.key():
                return r
            if r.idempotency_key and r.idempotency_key == req.key():
                return r
        return None

    def _new_run(self, req: ToolRequest, spec: ToolSpec) -> ToolRun:
        params_hash = hashlib.sha256(
            json.dumps(req.parameters, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
        return ToolRun(
            id=new_id(IDPrefix.TOOL_RUN),
            request_id=req.request_id or new_id("REQ"),
            idempotency_key=req.key(),
            project_id=req.project_id,
            target_id=req.target_id,
            tool=req.tool,
            parameters=req.parameters,
            policy_context={"risk_level": spec.risk_level.value},
            risk_level=spec.risk_level,
            approval_id=req.approval_id,
            timeout_seconds=req.timeout_seconds,
            priority=req.priority,
            tool_version=None,
            parameters_hash=params_hash,
        )

    def _failed_run(self, req: ToolRequest, error: str, status: ToolRunStatus) -> ToolResult:
        run = self._new_run(req, ToolSpec(name=req.tool, description=""))
        run.status = status
        run.error = error
        run.finished_at = _now_iso()
        self.tool_runs.add(run)
        self.audit.record("tool.rejected", run_id=run.id, reason=error, status=status.value)
        return ToolResult(run_id=run.id, status=status, error=error)

    def _invoke(self, fn, parameters: dict, timeout: int):
        # Synchronous path; future: dispatch to a worker pool.
        if timeout <= 0:
            raise TimeoutError("timeout_seconds must be > 0")
        return fn(**parameters)

    def _collect_artefacts(self, raw_result: Any) -> list[ArtefactRef]:
        """Pick up `ArtefactRef` objects or `bytes` from a tool result."""
        artefacts: list[ArtefactRef] = []
        if raw_result is None:
            return artefacts
        # Single artefact
        if isinstance(raw_result, ArtefactRef):
            artefacts.append(raw_result)
            return artefacts
        if isinstance(raw_result, bytes):
            sha = self.artefact_store.put(raw_result)
            artefacts.append(
                ArtefactRef(sha256=sha, kind="binary", size=len(raw_result), location=f"fs://{sha}")
            )
            return artefacts
        # Dict with artefacts key
        if isinstance(raw_result, dict):
            listed = raw_result.get("artefacts")
            if isinstance(listed, list):
                for item in listed:
                    if isinstance(item, ArtefactRef):
                        artefacts.append(item)
            # Auto-store any raw bytes the tool returned
            for key, val in raw_result.items():
                if isinstance(val, bytes):
                    sha = self.artefact_store.put(val, content_type="application/octet-stream")
                    artefacts.append(
                        ArtefactRef(
                            sha256=sha,
                            kind=key,
                            size=len(val),
                            location=f"fs://{sha}",
                        )
                    )
        return artefacts


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _scrub_for_storage(result: Any) -> Any:
    """Replace bytes inside a result dict with hashes before persisting."""
    if isinstance(result, dict):
        out = {}
        for k, v in result.items():
            if isinstance(v, bytes):
                h = hashlib.sha256(v).hexdigest()
                out[k] = {"_kind": "bytes", "sha256": h, "size": len(v)}
            elif isinstance(v, dict):
                out[k] = _scrub_for_storage(v)
            elif isinstance(v, list):
                out[k] = [_scrub_for_storage(x) if isinstance(x, dict) else x for x in v]
            else:
                out[k] = v
        return out
    return result


# Module-level convenience: use a default gateway for ad-hoc calls.
_default_gateway: ToolGateway | None = None


def get_default_gateway() -> ToolGateway:
    global _default_gateway
    if _default_gateway is None:
        _default_gateway = ToolGateway()
    return _default_gateway


def submit_tool(req: ToolRequest) -> ToolResult:
    return get_default_gateway().submit(req)
