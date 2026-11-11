"""Reverse Engineering Agent: disassembly-grounded dataflow analysis.

The agent no longer asks the model for a prose summary. It:

1. asks the ``ioctl_extract`` tool for the dispatch handler RVA, IOCTL
   codes, jump tables and security-relevant imports;
2. disassembles the handler (plus jump-table targets and directly called
   helpers) with capstone, annotating RIP-relative calls with the import
   they resolve to;
3. asks the model for structured ``functions`` / ``dataflow`` findings;
4. **grounds** the answer: a claimed call symbol must have been resolved
   in the listing, and an instruction RVA must appear in the listing.
   Ungrounded claims are dropped and recorded in
   ``reverse_analysis_notes``.

The model may return no findings at all. An IOCTL code or a handler
entry is not a sink, and the prompt says so.
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP

from ..agents._ops import AgentOps
from ..graph.state import ResearchState
from ..llm.base import LLMTask
from ..models.common import ToolRunStatus
from ..prompts import build_reverse_messages
from ..tools.gateway import ToolRequest

logger = logging.getLogger("dra.agents.reverse")

# Instruction budget per listing. Kept small enough that the whole
# untrusted block stays below the wrapper's 16 KB truncation point.
_MAX_HANDLER_INSTRUCTIONS = 220
_MAX_BLOCK_INSTRUCTIONS = 256
_MAX_EXTRA_ROOT_INSTRUCTIONS = 80
_MAX_CALLEE_INSTRUCTIONS = 120
_MAX_CALLEES = 3
_MAX_EXTRA_ROOTS = 4

# Imports that matter as sinks when they appear as resolved calls.
_SINK_IMPORTS = {
    "rtlcopymemory", "rtlmovememory", "memcpy", "memmove", "memcpys",
    "mmcopyvirtualmemory", "rtlzeromemory", "memset", "rtlfillmemory",
    "zwreadvirtualmemory", "zwwritevirtualmemory",
}
# Imports that count as a user/kernel boundary guard.
_GUARD_IMPORTS = {
    "probeforread", "probeforwrite", "mmprobeandlockpages",
    "mmgetsystemaddressformdlsafe", "mmsecurevirtualmemory",
}

_TERMINATORS = {"ret", "retf", "iret", "iretq", "int3", "ud2", "hlt"}


@dataclass
class _Insn:
    rva: int
    text: str
    annotation: str | None = None
    call_target: str | None = None
    call_kind: str | None = None  # "import" | "internal" | "indirect"


class _ImageView:
    """Minimal PE accessor: RVA -> bytes, executable-section check."""

    def __init__(self, pe: pefile.PE, data: bytes) -> None:
        self.pe = pe
        self.data = data
        self.image_base = int(pe.OPTIONAL_HEADER.ImageBase)
        self.size_image = int(pe.OPTIONAL_HEADER.SizeOfImage)
        self.is_64 = int(pe.OPTIONAL_HEADER.Magic) == 0x20B

    def read_rva(self, rva: int, size: int) -> bytes:
        if rva < 0:
            return b""
        try:
            offset = self.pe.get_offset_from_rva(rva)
        except Exception:  # noqa: BLE001 - unmapped RVA
            return b""
        if offset is None or offset < 0 or offset >= len(self.data):
            return b""
        return self.data[offset : offset + size]

    def section_for_rva(self, rva: int):
        if rva < 0:
            return None
        for section in self.pe.sections:
            va = section.VirtualAddress
            size = max(section.Misc_VirtualSize, section.SizeOfRawData)
            if va <= rva < va + size:
                return section
        return None

    def is_executable(self, rva: int) -> bool:
        section = self.section_for_rva(rva)
        if section is None:
            return False
        return bool(section.Characteristics & 0x20000000)  # IMAGE_SCN_MEM_EXECUTE


def _iat_names(pe: pefile.PE, image_base: int) -> dict[int, str]:
    """Map IAT slot RVA -> imported symbol name."""
    names: dict[int, str] = {}
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        for imp in entry.imports:
            if imp.name:
                name = imp.name.decode("ascii", errors="replace")
            else:
                name = f"ordinal_{getattr(imp, 'ordinal', '?')}"
            address = getattr(imp, "address", None)
            if not isinstance(address, int) or not address:
                continue
            rva = address - image_base if address >= image_base else address
            names[rva] = name
    return names


def _annotate(
    insn, view: _ImageView, iat: dict[int, str]
) -> tuple[str | None, str | None, str | None]:
    """Return ``(annotation, call_target, call_kind)`` for one instruction."""
    notes: list[str] = []
    call_target: str | None = None
    call_kind: str | None = None
    is_control = insn.mnemonic in ("call", "jmp")
    op = insn.operands[0] if len(insn.operands) == 1 else None

    if is_control and op is not None:
        if op.type == X86_OP_IMM:
            target_rva = op.imm - view.image_base
            if 0 <= target_rva < view.size_image:
                if insn.mnemonic == "jmp":
                    notes.append(f"target rva 0x{target_rva:X}")
                else:
                    call_target = f"sub_0x{target_rva:X}"
                    call_kind = "internal"
                    notes.append(f"calls {call_target}")
        elif op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
            target_rva = (insn.address + insn.size + op.mem.disp) - view.image_base
            name = iat.get(target_rva)
            if name:
                call_target = name
                call_kind = "import"
                notes.append(f"import {name}")
            else:
                call_target = f"rva_0x{target_rva:X}" if target_rva >= 0 else None
                call_kind = "indirect"
                notes.append(f"indirect via rva 0x{target_rva:X}")
        elif op.type == X86_OP_REG:
            call_kind = "indirect"
            notes.append(f"indirect {insn.mnemonic} {insn.reg_name(op.reg)}")

    if insn.mnemonic.startswith("j") and insn.mnemonic != "jmp" and op is not None:
        if op.type == X86_OP_IMM:
            target_rva = op.imm - view.image_base
            if 0 <= target_rva < view.size_image:
                notes.append(f"target rva 0x{target_rva:X}")

    if not is_control:
        for operand in insn.operands:
            if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                target_rva = (insn.address + insn.size + operand.mem.disp) - view.image_base
                if 0 <= target_rva < view.size_image:
                    notes.append(f"data rva 0x{target_rva:X}")

    return ("; ".join(notes) or None), call_target, call_kind


def _walk(
    view: _ImageView,
    md: Cs,
    iat: dict[int, str],
    roots: list[int],
    seen_blocks: set[int],
    budget: int,
) -> list[_Insn]:
    """Recursive-descent disassembly of bounded blocks."""
    work = list(roots)
    out: list[_Insn] = []
    while work and len(out) < budget:
        block_rva = work.pop()
        if block_rva in seen_blocks:
            continue
        seen_blocks.add(block_rva)
        if not view.is_executable(block_rva):
            continue
        pc = block_rva
        block_count = 0
        while len(out) < budget and block_count < _MAX_BLOCK_INSTRUCTIONS:
            code = view.read_rva(pc, 16)
            if not code:
                break
            try:
                insn = next(md.disasm(code, view.image_base + pc, count=1), None)
            except Exception:  # noqa: BLE001 - capstone is strict about bad bytes
                break
            if insn is None:
                break
            block_count += 1
            annotation, call_target, call_kind = _annotate(insn, view, iat)
            out.append(
                _Insn(
                    rva=pc,
                    text=f"{insn.mnemonic} {insn.op_str}".strip(),
                    annotation=annotation,
                    call_target=call_target,
                    call_kind=call_kind,
                )
            )
            next_rva = pc + insn.size
            mnemonic = insn.mnemonic
            if mnemonic.startswith("j") and mnemonic != "jmp":
                if insn.operands and insn.operands[0].type == X86_OP_IMM:
                    target_rva = insn.operands[0].imm - view.image_base
                    if view.is_executable(target_rva):
                        work.append(target_rva)
                pc = next_rva
                continue
            if mnemonic == "jmp":
                if insn.operands and insn.operands[0].type == X86_OP_IMM:
                    target_rva = insn.operands[0].imm - view.image_base
                    if view.is_executable(target_rva):
                        work.append(target_rva)
                break
            if mnemonic in _TERMINATORS:
                break
            pc = next_rva
    return out


def _rva_from_sub(target: str | None) -> int | None:
    if not target or not target.startswith("sub_0x"):
        return None
    try:
        return int(target[6:], 16)
    except ValueError:
        return None


def _serialize(insns: list[_Insn]) -> list[dict]:
    return [
        {
            "rva": insn.rva,
            "text": insn.text,
            "annotation": insn.annotation,
            "call_target": insn.call_target,
            "call_kind": insn.call_kind,
        }
        for insn in insns
    ]


def _collect_disassembly(target_path: str, facts: dict | None) -> dict[str, Any]:
    """Disassemble the dispatch handler and its immediate context.

    Returns a JSON-serialisable dict::

        {
          "handler_rva": int | None,
          "snippets": [{"label", "start_rva", "instructions": [...], "truncated"}],
          "calls": [{"rva", "target", "kind", "class"}],
          "instruction_count": int,
          "instruction_rvas": [int],
          "imports": [str],   # symbols resolved in this listing
          "notes": [str],
        }
    """
    data = Path(target_path).read_bytes()
    result: dict[str, Any] = {
        "handler_rva": None,
        "snippets": [],
        "calls": [],
        "instruction_count": 0,
        "instruction_rvas": [],
        "imports": [],
        "notes": [],
    }
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except Exception as exc:  # noqa: BLE001 - untrusted input
        result["notes"].append(f"PE parse failed: {type(exc).__name__}: {exc}")
        return result

    try:
        view = _ImageView(pe, data)
        iat = _iat_names(pe, view.image_base)
        md = Cs(CS_ARCH_X86, CS_MODE_64 if view.is_64 else CS_MODE_32)
        md.detail = True

        handler_rva = (facts or {}).get("device_control_handler_rva")
        roots: list[int] = []
        if handler_rva is not None:
            roots.append(int(handler_rva))
        for table in (facts or {}).get("jump_tables") or []:
            for target in (table.get("target_rvas") or [])[:_MAX_EXTRA_ROOTS]:
                if int(target) not in roots:
                    roots.append(int(target))
        if not roots:
            result["notes"].append(
                "no device-control handler RVA available; nothing to disassemble"
            )
            return result
        result["handler_rva"] = int(handler_rva) if handler_rva is not None else None

        seen: set[int] = set()
        handler_insns = _walk(
            view, md, iat, [roots[0]], seen, _MAX_HANDLER_INSTRUCTIONS
        )
        if handler_insns:
            result["snippets"].append(
                {
                    "label": "handler",
                    "start_rva": roots[0],
                    "instructions": _serialize(handler_insns),
                    "truncated": len(handler_insns) >= _MAX_HANDLER_INSTRUCTIONS,
                }
            )
        for root in roots[1 : 1 + _MAX_EXTRA_ROOTS]:
            extra = _walk(
                view, md, iat, [root], seen, _MAX_EXTRA_ROOT_INSTRUCTIONS
            )
            if extra:
                result["snippets"].append(
                    {
                        "label": "jump_table_target",
                        "start_rva": root,
                        "instructions": _serialize(extra),
                        "truncated": len(extra) >= _MAX_EXTRA_ROOT_INSTRUCTIONS,
                    }
                )

        # Follow direct calls made from the handler (helpers often hold the
        # actual IOCTL switch and sinks).
        direct_targets: list[int] = []
        for insn in handler_insns:
            if insn.call_kind != "internal":
                continue
            target_rva = _rva_from_sub(insn.call_target)
            if target_rva is not None and target_rva not in direct_targets:
                direct_targets.append(target_rva)
        for target_rva in direct_targets[:_MAX_CALLEES]:
            callee = _walk(
                view, md, iat, [target_rva], seen, _MAX_CALLEE_INSTRUCTIONS
            )
            if callee:
                result["snippets"].append(
                    {
                        "label": f"callee rva=0x{target_rva:X}",
                        "start_rva": target_rva,
                        "instructions": _serialize(callee),
                        "truncated": len(callee) >= _MAX_CALLEE_INSTRUCTIONS,
                    }
                )

        all_insns = [
            insn for snippet in result["snippets"] for insn in snippet["instructions"]
        ]
        result["instruction_count"] = len(all_insns)
        result["instruction_rvas"] = sorted({int(insn["rva"]) for insn in all_insns})
        calls: list[dict] = []
        seen_calls: set[tuple[int, str]] = set()
        imports: set[str] = set()
        for insn in all_insns:
            target = insn.get("call_target")
            if not target:
                continue
            rva = int(insn["rva"])
            key = (rva, str(target))
            if key in seen_calls:
                continue
            seen_calls.add(key)
            kind = str(insn.get("call_kind") or "indirect")
            call_class = "other"
            if kind == "import":
                imports.add(str(target))
                lowered = str(target).lower()
                if lowered in _SINK_IMPORTS:
                    call_class = "sink"
                elif lowered in _GUARD_IMPORTS:
                    call_class = "guard"
            calls.append(
                {"rva": rva, "target": str(target), "kind": kind, "class": call_class}
            )
        result["calls"] = calls
        result["imports"] = sorted(imports)
        return result
    finally:
        try:
            pe.close()
        except Exception:  # noqa: BLE001 - defensive
            pass


def _load_facts(
    state: ResearchState, ops: AgentOps, target_path: str
) -> tuple[dict | None, list[str]]:
    """Run ``ioctl_extract`` through the tool gateway (audited, idempotent)."""
    request = ToolRequest(
        project_id=state["project_id"],
        target_id=state.get("target_id"),
        tool="ioctl_extract",
        parameters={"path": target_path},
        requester="reverse",
    )
    result = ops.tools.submit(request)
    if result.status != ToolRunStatus.SUCCEEDED or not isinstance(result.result, dict):
        return None, [
            f"ioctl_extract did not succeed: status={result.status.value} "
            f"run_id={result.run_id} error={result.error}"
        ]
    return result.result, list((result.result or {}).get("notes") or [])[:6]


def _normalize_reverse_payload(
    payload: dict,
    *,
    allowed_symbols: set[str],
    instruction_rvas: set[int],
) -> tuple[dict, list[str]]:
    """Ground the model's answer against the listing.

    A call sink is kept only when its symbol was resolved in the listing;
    an instruction RVA is kept only when it exists in the listing.
    """
    notes: list[str] = []
    normalized: dict[str, Any] = {
        "functions": [],
        "dataflow": [],
        "not_analyzed": [],
    }
    if not isinstance(payload, dict):
        return normalized, ["model payload was not a JSON object"]

    allowed_lower = {symbol.lower(): symbol for symbol in allowed_symbols}

    for function in (payload.get("functions") or [])[:8]:
        if not isinstance(function, dict):
            continue
        sinks: list[dict] = []
        for sink in (function.get("sinks") or [])[:12]:
            if not isinstance(sink, dict):
                continue
            kind = str(sink.get("kind") or "other")
            symbol = sink.get("symbol")
            symbol_text = str(symbol) if symbol else None
            if kind == "call":
                if not symbol_text or symbol_text.lower() not in allowed_lower:
                    notes.append(
                        f"dropped call sink {symbol_text!r}: symbol was not "
                        "resolved in the disassembly listing"
                    )
                    continue
                symbol_text = allowed_lower[symbol_text.lower()]
            rva = sink.get("instruction_rva")
            try:
                rva = int(rva) if rva is not None else None
            except (TypeError, ValueError):
                rva = None
            if rva is not None and rva not in instruction_rvas:
                notes.append(
                    f"cleared instruction_rva 0x{rva:X} for {symbol_text or kind}: "
                    "not present in the listing"
                )
                rva = None
            destination = str(sink.get("destination") or "unknown")
            if destination not in {"stack_buffer", "user_buffer", "kernel_pool", "unknown"}:
                destination = "unknown"
            length_source = str(sink.get("length_source") or "unknown")
            if length_source not in {"user_controlled", "constant", "unknown"}:
                length_source = "unknown"
            probe_read = str(sink.get("probe_for_read") or "unknown")
            if probe_read not in {"present", "absent", "unknown"}:
                probe_read = "unknown"
            probe_write = str(sink.get("probe_for_write") or "unknown")
            if probe_write not in {"present", "absent", "unknown"}:
                probe_write = "unknown"
            confidence = str(sink.get("confidence") or "low")
            if confidence not in {"low", "medium", "high"}:
                confidence = "low"
            input_derived = sink.get("input_derived")
            if not isinstance(input_derived, bool):
                input_derived = None
            sinks.append(
                {
                    "kind": kind if kind in {"call", "pointer_write", "other"} else "other",
                    "symbol": symbol_text,
                    "instruction_rva": rva,
                    "instruction": str(sink.get("instruction") or "")[:300],
                    "length_source": length_source,
                    "destination": destination,
                    "probe_for_read": probe_read,
                    "probe_for_write": probe_write,
                    "input_derived": input_derived,
                    "guard": str(sink.get("guard") or "")[:300],
                    "confidence": confidence,
                }
            )
        function_rva = function.get("function_rva")
        try:
            function_rva = int(function_rva) if function_rva is not None else None
        except (TypeError, ValueError):
            function_rva = None
        if function_rva is not None and function_rva not in instruction_rvas:
            notes.append(f"cleared function_rva 0x{function_rva:X}: not in the listing")
            function_rva = None
        if not sinks and not str(function.get("summary") or "").strip():
            continue
        normalized["functions"].append(
            {
                "function_rva": function_rva,
                "role": str(function.get("role") or "unknown"),
                "summary": str(function.get("summary") or "")[:500],
                "sinks": sinks,
            }
        )

    for chain in (payload.get("dataflow") or [])[:24]:
        if not isinstance(chain, dict):
            continue
        rvas: list[int] = []
        for value in chain.get("instruction_rvas") or []:
            try:
                rva = int(value)
            except (TypeError, ValueError):
                continue
            if rva in instruction_rvas:
                rvas.append(rva)
        if not str(chain.get("summary") or "").strip() and not rvas:
            continue
        normalized["dataflow"].append(
            {
                "source": str(chain.get("source") or "")[:300],
                "sink": str(chain.get("sink") or "")[:300],
                "guard": str(chain.get("guard") or "unknown"),
                "instruction_rvas": rvas,
                "summary": str(chain.get("summary") or "")[:500],
            }
        )

    normalized["not_analyzed"] = [
        str(item)[:300] for item in (payload.get("not_analyzed") or [])[:16]
    ]
    return normalized, notes


def _finding_summary(findings: dict) -> str:
    sink_count = sum(len(function["sinks"]) for function in findings["functions"])
    return (
        f"reverse analysis: {len(findings['functions'])} function(s), "
        f"{sink_count} sink candidate(s), "
        f"{len(findings['dataflow'])} dataflow chain(s)"
    )


async def reverse_node(state: ResearchState, ops: AgentOps) -> dict:
    observation_ids: list[str] = state.get("observation_ids", [])
    target_path = state.get("target_path")
    base: dict[str, Any] = {
        "reverse_summary_id": f"REV-{state['research_id']}",
        "reverse_summary_text": "",
        "reverse_findings": {},
        "reverse_analysis_status": "not_run",
        "reverse_analysis_notes": [],
        "current_phase": "hypothesis",
        "current_node": "reverse",
    }

    if not observation_ids:
        base["reverse_analysis_status"] = "skipped_no_observations"
        return base
    if not target_path:
        base["reverse_analysis_status"] = "skipped_no_target"
        return base

    facts, fact_notes = _load_facts(state, ops, target_path)
    try:
        snippets = _collect_disassembly(target_path, facts)
    except Exception as exc:  # noqa: BLE001 - a bad binary must not crash the graph
        base["reverse_analysis_status"] = "disassembly_failed"
        base["reverse_analysis_notes"] = fact_notes + [
            f"disassembly failed: {type(exc).__name__}: {exc}"
        ]
        return base

    if not snippets.get("instruction_count"):
        base["reverse_analysis_status"] = "no_disassembly"
        base["reverse_analysis_notes"] = fact_notes + list(snippets.get("notes") or [])
        return base

    target_name = Path(target_path).name
    sha = str(facts.get("sha256") or "") if facts else ""
    if not sha:
        try:
            sha = hashlib.sha256(Path(target_path).read_bytes()).hexdigest()
        except OSError:
            sha = ""

    messages = build_reverse_messages(
        target_name=target_name,
        target_sha256=sha,
        facts=facts,
        snippets=snippets,
    )
    resp = ops.llm.complete(messages, task=LLMTask.CROSS_FN_REASON)
    findings, grounding_notes = _normalize_reverse_payload(
        resp.structured or {},
        allowed_symbols=set(snippets.get("imports") or []),
        instruction_rvas=set(snippets.get("instruction_rvas") or []),
    )
    if getattr(resp, "model", "") == "mock":
        grounding_notes.append(
            "LLM provider is the deterministic mock; this reverse answer is not "
            "real analysis. Set DRA_LLM_PROVIDER=anthropic."
        )
    has_findings = bool(findings["functions"] or findings["dataflow"])
    logger.info(
        "reverse node: %d instruction(s), %d function(s), %d dataflow chain(s), "
        "%d grounding note(s)",
        snippets["instruction_count"],
        len(findings["functions"]),
        len(findings["dataflow"]),
        len(grounding_notes),
    )
    base.update(
        {
            "reverse_summary_text": _finding_summary(findings),
            "reverse_findings": findings,
            "reverse_analysis_status": "ok" if has_findings else "no_findings",
            "reverse_analysis_notes": fact_notes + grounding_notes,
        }
    )
    return base
