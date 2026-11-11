"""Live smoke test for the real Anthropic provider path.

Run it once a key exists::

    cd server
    export DRA_ANTHROPIC_API_KEY=...      # bash
    # $env:DRA_ANTHROPIC_API_KEY="..."    # PowerShell
    D:/every/python/python313/python.exe scripts/smoke_live_llm.py

It performs two *real* model calls against the file named by ``--path``
(default: ``C:\\Windows\\System32\\drivers\\beep.sys``):

1. the reverse dataflow agent over the real capstone listing;
2. the hypothesis agent over observations derived from ``ioctl_extract``.

Nothing is executed and the key is only read from the environment; no
key is written to disk. Store data goes to a temporary directory.

Exit codes: 0 = ran, 2 = missing key / target, 1 = provider or model
output failure.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import tempfile
from pathlib import Path

_SERVER_ROOT = Path(__file__).resolve().parents[1]
if str(_SERVER_ROOT) not in sys.path:  # allow `python scripts/smoke_live_llm.py`
    sys.path.insert(0, str(_SERVER_ROOT))

DEFAULT_TARGET = r"C:\Windows\System32\drivers\beep.sys"

_MISSING_KEY_MESSAGE = """\
DRA_ANTHROPIC_API_KEY is not set (and ANTHROPIC_API_KEY is empty).

This script makes real Claude API calls, so it needs a key in the
environment. Nothing is written to disk.

  bash:        export DRA_ANTHROPIC_API_KEY="sk-ant-..."
  PowerShell:  $env:DRA_ANTHROPIC_API_KEY = "sk-ant-..."
  cmd.exe:     set DRA_ANTHROPIC_API_KEY=sk-ant-...

Then re-run:  python scripts/smoke_live_llm.py
"""


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the real Claude provider over a driver and print hypotheses."
    )
    parser.add_argument("--path", default=DEFAULT_TARGET, help="driver path to analyse")
    parser.add_argument(
        "--max-tokens", type=int, default=16000, help="max_tokens per model call"
    )
    parser.add_argument(
        "--model",
        default=None,
        help="override the large-tier model id (default: claude-opus-5-5)",
    )
    return parser.parse_args(argv)


def _print_json(label: str, value: object) -> None:
    print(f"\n=== {label} ===")
    print(json.dumps(value, indent=2, ensure_ascii=False, default=str))


def _build_observations(facts: dict, target_id: str, project_id: str):
    """Mirror the recon agent's ioctl-derived observations."""
    from dra.models.common import IDPrefix, new_id
    from dra.models.observation import Observation

    observations: list[Observation] = []

    def add(category: str, location: str, description: str, confidence: str) -> None:
        observations.append(
            Observation(
                id=new_id(IDPrefix.OBSERVATION),
                target_id=target_id,
                project_id=project_id,
                category=category,
                location=location,
                description=description,
                source="static",
                source_tool="ioctl_extract",
                source_method="smoke_live_llm",
                tool_version="0.1.0",
                confidence=confidence,
            )
        )

    for code in facts.get("ioctl_codes") or []:
        if not code.get("plausible"):
            continue
        ctl = code.get("ctl_code") or {}
        add(
            "ioctl_code",
            f"IOCTL {code.get('code_hex')}",
            (
                f"IOCTL {code.get('code_hex')} compared in the "
                f"IRP_MJ_DEVICE_CONTROL handler (handler_rva="
                f"{facts.get('device_control_handler_rva')}); decoded as "
                f"device_type={ctl.get('device_type')} access={ctl.get('access')} "
                f"function={ctl.get('function')} method={ctl.get('method')}."
            ),
            "medium",
        )
    handler = facts.get("device_control_handler_rva")
    if handler is not None:
        add(
            "ioctl_dispatch",
            f"rva=0x{int(handler):X}",
            (
                "DriverEntry writes MajorFunction[IRP_MJ_DEVICE_CONTROL] "
                f"(handler_rva={handler}, "
                f"ioctl_count={len(facts.get('ioctl_codes') or [])})."
            ),
            "medium",
        )
    for name in facts.get("device_names") or []:
        add(
            "device_exposure",
            name,
            "Device/symlink name recovered from a UTF-16LE literal; ACL not analysed.",
            "low",
        )
    for imp in facts.get("imports_of_interest") or []:
        name = imp.get("name") or ""
        if not name:
            continue
        category = "memory_copy" if name.lower() in {
            "rtlcopymemory", "memcpy", "memmove", "rtlmovememory",
            "probeforread", "probeforwrite",
        } else "ioctl_dispatch"
        add(
            category,
            f"rva=0x{int(imp['iat_rva']):X}" if imp.get("iat_rva") else name,
            f"Driver imports {name}; call path and caller privileges not analysed.",
            "low",
        )
    return observations


def _build_attack_surface(facts: dict, pe: dict, target_id: str, project_id: str):
    from dra.models.attack_surface import AttackSurface, AttackSurfaceItem, Reachability
    from dra.models.common import IDPrefix, new_id
    from dra.tools.tools.attack_surface_extract import attack_surface_extract

    payload = attack_surface_extract(pe=pe, strings={"strings": []}, ioctl=facts)
    return AttackSurface(
        id=new_id(IDPrefix.ATTACK_SURFACE),
        target_id=target_id,
        project_id=project_id,
        items=[
            AttackSurfaceItem(
                id=new_id(IDPrefix.ATTACK_SURFACE),
                target_id=target_id,
                project_id=project_id,
                kind=item.get("kind", "unknown"),
                name=item.get("name", ""),
                reachability=Reachability(
                    required_privilege=item.get("reachability", "unknown")
                ),
            )
            for item in payload.get("items", [])
        ],
        summary=f"{payload.get('count', 0)} items from ioctl_extract facts.",
    )


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    api_key = os.environ.get("DRA_ANTHROPIC_API_KEY") or os.environ.get(
        "ANTHROPIC_API_KEY"
    )
    if not api_key:
        print(_MISSING_KEY_MESSAGE, file=sys.stderr)
        return 2

    target = Path(args.path)
    if not target.is_file():
        print(
            f"target not found: {target}\n"
            "Pass --path <absolute path to a Windows driver>.",
            file=sys.stderr,
        )
        return 2

    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    with tempfile.TemporaryDirectory(prefix="dra-smoke-") as tmp:
        # These must be set before dra.config is imported.
        os.environ["DRA_DATA_DIR"] = str(Path(tmp) / "data")
        os.environ["DRA_ARTIFACTS_DIR"] = str(Path(tmp) / "artefacts")
        os.environ["DRA_LLM_PROVIDER"] = "anthropic"

        from dra.agents._ops import build_ops
        from dra.agents.hypothesis import hypothesis_node
        from dra.agents.reverse import reverse_node
        from dra.llm.anthropic_client import AnthropicLLMClient
        from dra.llm.base import ModelTier
        from dra.llm.errors import LLMError
        from dra.llm.router import LLMRouter
        from dra.models.common import IDPrefix, new_id
        from dra.tools.tools.analyze_pe import analyze_pe
        from dra.tools.tools.ioctl_extract import ioctl_extract

        print(f"target: {target}")
        facts = ioctl_extract(str(target))
        pe = analyze_pe(str(target))

        project_id = new_id(IDPrefix.PROJECT)
        target_id = f"TGT-SMOKE-{(facts.get('sha256') or '')[:12] or 'UNKNOWN'}"
        research_id = f"RES-SMOKE-{target_id[-12:]}"

        models = {}
        if args.model:
            models[ModelTier.LARGE] = args.model
        client = AnthropicLLMClient(
            api_key=api_key,
            models=models or None,
            max_tokens=args.max_tokens,
        )
        ops = build_ops(llm=LLMRouter(client))
        ops.projects.add(
            {
                "id": project_id,
                "name": "smoke-live-llm",
                "authorized_use": True,
                "authorization_ref": "local-static-analysis-only",
            }
        )

        observations = _build_observations(facts, target_id, project_id)
        for observation in observations:
            ops.observations.add(observation)
        attack_surface = _build_attack_surface(facts, pe, target_id, project_id)
        ops.attack_surfaces.add(attack_surface)

        print(
            f"ioctl_extract: status={facts.get('analysis_status')} "
            f"handler_rva={facts.get('device_control_handler_rva')} "
            f"ioctl_codes={[c.get('code_hex') for c in facts.get('ioctl_codes') or []]} "
            f"device_names={facts.get('device_names')}"
        )
        print(f"observations: {len(observations)}")

        state = {
            "project_id": project_id,
            "research_id": research_id,
            "target_id": target_id,
            "target_path": str(target),
            "observation_ids": [o.id for o in observations],
            "attack_surface_id": attack_surface.id,
            "reverse_findings": {},
            "reverse_analysis_status": "not_run",
            "reverse_analysis_notes": [],
        }

        try:
            reverse_update = asyncio.run(reverse_node(state, ops))
            state.update(reverse_update)
            print(
                f"\nreverse: status={state['reverse_analysis_status']} "
                f"{state['reverse_summary_text'] or ''}"
            )
            _print_json("REVERSE FINDINGS", state["reverse_findings"])
            if state["reverse_analysis_notes"]:
                _print_json("REVERSE NOTES", state["reverse_analysis_notes"])

            hypothesis_update = asyncio.run(hypothesis_node(state, ops))
            state.update(hypothesis_update)
        except LLMError as exc:
            print(f"\nLLM call failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1

        reasoning = state.get("hypothesis_reasoning") or ""
        hypothesis_ids = state.get("hypothesis_ids") or []
        hypotheses = [
            ops.hypotheses.get(hid) for hid in hypothesis_ids if ops.hypotheses.get(hid)
        ]

        print(
            f"\nhypotheses: {len(hypotheses)} "
            f"(rejected drafts: {len(state.get('hypothesis_rejected') or [])})"
        )
        if reasoning:
            print(f"reasoning: {reasoning}")
        _print_json(
            "HYPOTHESES",
            [
                {
                    "id": h.id,
                    "category": h.category,
                    "location": h.location,
                    "description": h.description,
                    "observation_ids": h.observation_ids,
                    "falsification": h.falsification,
                    "priority": h.priority,
                }
                for h in hypotheses
            ],
        )
        if state.get("hypothesis_rejected"):
            _print_json("REJECTED DRAFTS", state["hypothesis_rejected"])

        print("\nSMOKE RESULT: real provider calls completed.")
        if not hypotheses:
            print(
                "The model returned ZERO hypotheses. This is a valid outcome: "
                "attack surface alone is not a vulnerability."
            )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
