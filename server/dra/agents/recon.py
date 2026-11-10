"""Recon Agent.

Runs the static analysis tools (analyze_pe, static_strings,
attack_surface_extract) and writes Observations to the Observation
Store.
"""
from __future__ import annotations

from ..agents._ops import AgentOps
from ..config import SETTINGS
from ..graph.state import ResearchState
from ..models.common import IDPrefix, new_id
from ..models.observation import Observation
from ..tools.gateway import ToolRequest
from ..untrusted.wrapper import untrusted_wrap


RECON_PROMPT = """You are the Recon agent of DRA. Given the static analysis
output and the extracted strings, list any feature that should be
turned into a structured Observation. Emit a JSON object with
`observations: [...]` where each item has `category`, `location`,
`description`, and a 0..1 `confidence`.
"""


def _require_success(result, tool: str) -> None:
    """Fail loudly instead of continuing on an empty tool result.

    A failed tool used to degrade into ``result or {}`` — no observations,
    no evidence, but a graph that still reported "completed". That turns a
    broken pipeline into a report that looks like a clean negative finding.
    """
    from ..models.common import ToolRunStatus

    if result.status != ToolRunStatus.SUCCEEDED:
        raise RuntimeError(
            f"recon tool {tool!r} did not succeed: status={result.status.value} "
            f"run_id={result.run_id} error={result.error}"
        )


def _tool_request(state: ResearchState, target_id: str, tool: str, parameters: dict, requester: str) -> ToolRequest:
    return ToolRequest(
        project_id=state["project_id"],
        target_id=target_id,
        tool=tool,
        parameters=parameters,
        requester=requester,
    )


async def recon_node(state: ResearchState, ops: AgentOps) -> dict:
    from ..llm.base import LLMMessage, LLMTask
    target_id = state.get("target_id")
    if not target_id:
        raise ValueError("recon requires target_id in state")

    target_path = state.get("target_path")
    if not target_path:
        return {
            "recon_summary_id": None,
            "observation_ids": [],
            "current_phase": "static_summary",
            "current_node": "recon",
        }

    pe_res = ops.tools.submit(
        _tool_request(state, target_id, "analyze_pe", {"path": target_path}, "recon")
    )
    _require_success(pe_res, "analyze_pe")
    pe = pe_res.result or {}

    str_res = ops.tools.submit(
        _tool_request(state, target_id, "static_strings", {"path": target_path, "min_length": 6}, "recon")
    )
    _require_success(str_res, "static_strings")
    strings = (str_res.result or {}).get("strings", [])

    as_res = ops.tools.submit(
        _tool_request(
            state,
            target_id,
            "attack_surface_extract",
            {"pe": pe, "strings": {"strings": strings, "count": len(strings)}},
            "recon",
        )
    )
    _require_success(as_res, "attack_surface_extract")
    as_payload = as_res.result or {}
    attack_surface_items = as_payload.get("items", [])

    pe_untrusted = untrusted_wrap(pe, source="analyze_pe:report")
    str_untrusted = untrusted_wrap({"strings": strings[:64]}, source="static_strings:report")
    user_prompt = (
        "PE report (untrusted):\n" + pe_untrusted["payload"][:2000] +
        "\n\nStrings (untrusted, truncated):\n" + str_untrusted["payload"][:2000] +
        "\n\nAttack surface items: " + str(attack_surface_items) +
        "\n\nReturn JSON {\"observations\": [...]}."
    )
    llm = ops.llm.complete(
        [LLMMessage(role="user", content=RECON_PROMPT), LLMMessage(role="user", content=user_prompt)],
        task=LLMTask.STATIC_SUMMARY,
    )
    structured = llm.structured or {}
    _ = structured  # mock does not return observations; we synthesise below

    observations: list[Observation] = []
    sha = pe.get("sha256", "")

    def _obs(category: str, location: str, description: str, tool: str, method: str, confidence: str) -> None:
        observations.append(
            Observation(
                id=new_id(IDPrefix.OBSERVATION),
                target_id=target_id,
                project_id=state["project_id"],
                category=category,
                location=location,
                description=description,
                source="static",
                source_tool=tool,
                source_method=method,
                tool_version="0.1.0",
                confidence=confidence,
            )
        )

    # 1) Real IOCTL facts from ioctl_extract. These carry an actual
    #    CTL_CODE decode and a handler RVA — the only observations solid
    #    enough to build a defensible finding on.
    for it in attack_surface_items:
        kind = it.get("kind")
        params = it.get("parameters") or {}
        if kind == "ioctl" and params.get("code") is not None:
            ctl = params.get("ctl_code") or {}
            _obs(
                "ioctl_code",
                it.get("name") or f"IOCTL {params.get('code_hex')}",
                (
                    f"IOCTL {params.get('code_hex')} compared in the "
                    f"IRP_MJ_DEVICE_CONTROL handler (handler_rva="
                    f"{params.get('handler_rva')}); decoded as "
                    f"device_type={ctl.get('device_type')} "
                    f"access={ctl.get('access')} function={ctl.get('function')} "
                    f"method={ctl.get('method')}."
                ),
                "ioctl_extract",
                "dispatch_comparison",
                "medium",
            )
        elif kind == "dispatch":
            _obs(
                "ioctl_dispatch",
                it.get("address_or_offset") or f"rva={params.get('handler_rva')}",
                (
                    f"DriverEntry writes MajorFunction[IRP_MJ_DEVICE_CONTROL] "
                    f"(handler_rva={params.get('handler_rva')}, "
                    f"ioctl_count={params.get('ioctl_code_count')})."
                ),
                "ioctl_extract",
                "major_function_store",
                "medium",
            )
        elif kind == "device":
            _obs(
                "device_exposure",
                it.get("name") or "unknown",
                "Device/symlink name recovered from a UTF-16LE literal; ACL not analysed.",
                "ioctl_extract",
                "device_name_scan",
                "low",
            )

    # 2) Notable imports across the whole table (not just the first few —
    #    the interesting primitives are rarely the first eight entries).
    import_hints = {
        "IoCreateDevice": "ioctl_dispatch",
        "IoDeviceIoControl": "ioctl_dispatch",
        "RtlCopyMemory": "memory_copy",
        "memcpy": "memory_copy",
        "memmove": "memory_copy",
        "ProbeForWrite": "memory_copy",
        "ProbeForRead": "memory_copy",
    }
    seen_imports: set[str] = set()
    for name in pe.get("imports", []) or []:
        if name in seen_imports:
            continue
        category = import_hints.get(name)
        if category is None:
            continue
        seen_imports.add(name)
        _obs(
            category,
            name,
            f"Driver imports {name} (potential IOCTL dispatch or memory primitive).",
            "analyze_pe",
            "imports",
            "low",
        )

    if not observations and (pe.get("file_type") or "").startswith("pe"):
        _obs(
            "ioctl_dispatch",
            "unknown",
            "PE parsed but no IOCTL dispatch, device name or notable import was found.",
            "analyze_pe",
            "header_check",
            "low",
        )
    for o in observations:
        ops.observations.add(o)

    from ..models.attack_surface import AttackSurface, AttackSurfaceItem, Reachability
    as_obj = AttackSurface(
        id=new_id(IDPrefix.ATTACK_SURFACE),
        target_id=target_id,
        project_id=state["project_id"],
        items=[
            AttackSurfaceItem(
                id=new_id(IDPrefix.ATTACK_SURFACE),
                target_id=target_id,
                project_id=state["project_id"],
                kind=it.get("kind", "unknown"),
                name=it.get("name", ""),
                reachability=Reachability(
                    required_privilege=it.get("reachability", "unprivileged_user")
                ),
            )
            for it in attack_surface_items
        ],
        summary=f"{len(attack_surface_items)} items (mock heuristic).",
    )
    ops.attack_surfaces.add(as_obj)

    return {
        "recon_summary_id": None,
        "observation_ids": [o.id for o in observations],
        "attack_surface_id": as_obj.id,
        "pe_report_sha": sha,
        "current_phase": "static_summary",
        "current_node": "recon",
    }
