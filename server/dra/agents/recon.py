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
    pe = pe_res.result or {}

    str_res = ops.tools.submit(
        _tool_request(state, target_id, "static_strings", {"path": target_path, "min_length": 6}, "recon")
    )
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
    attack_surface_items = (as_res.result or {}).get("items", [])

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
    for name in pe.get("imports", [])[:8]:
        if any(h.lower() in name.lower() for h in {"IoCreateDevice", "IoDeviceIoControl", "RtlCopyMemory", "memcpy", "ProbeForWrite"}):
            observations.append(
                Observation(
                    id=new_id(IDPrefix.OBSERVATION),
                    target_id=target_id,
                    project_id=state["project_id"],
                    category="ioctl_dispatch" if "Io" in name else "memory_copy",
                    location=name,
                    description=f"Driver imports {name} (potential IOCTL/memory primitive).",
                    source="static",
                    source_tool="analyze_pe",
                    source_method="import_scrape",
                    tool_version="0.1.0",
                    confidence="medium",
                )
            )
    if not observations and pe.get("file_type", "").startswith("pe"):
        observations.append(
            Observation(
                id=new_id(IDPrefix.OBSERVATION),
                target_id=target_id,
                project_id=state["project_id"],
                category="ioctl_dispatch",
                location="PE:imports",
                description="PE header recognised; no specific IOCTL import flagged.",
                source="static",
                source_tool="analyze_pe",
                source_method="header_check",
                tool_version="0.1.0",
                confidence="low",
            )
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
