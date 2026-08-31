"""Reporter Agent."""
from __future__ import annotations

from datetime import datetime, timezone

from ..agents._ops import AgentOps
from ..graph.state import ResearchState
from ..llm.base import LLMMessage, LLMTask


async def reporter_node(state: ResearchState, ops: AgentOps) -> dict:
    finding_ids = state.get("finding_ids", [])
    findings = [ops.findings.get(i) for i in finding_ids if i]
    findings = [f for f in findings if f is not None]

    user_prompt = (
        "Produce a static research report (JSON) for the following "
        "candidate findings.\n"
        + "\n".join(
            f"- {f.title} (class={f.vulnerability_class}, qa={f.qa_status})"
            for f in findings
        )
    )
    resp = ops.llm.complete(
        [LLMMessage(role="user", content=user_prompt)],
        task=LLMTask.REPORT_GEN,
    )
    structured = resp.structured or {}

    report_id = f"RPT-{state['research_id']}"
    report = {
        "id": report_id,
        "research_id": state["research_id"],
        "title": structured.get("title", "Static Research Report"),
        "executive_summary": structured.get("executive_summary", ""),
        "sections": structured.get("sections", []),
        "finding_ids": finding_ids,
        "limitations": [
            "Phase 0/1: Static only; no Lab execution; no Ghidra/IDA; no detection evaluation.",
        ],
    }
    research = ops.research.get(state["research_id"]) or {
        "id": state["research_id"],
        "project_id": state["project_id"],
    }
    research.update(
        {
            "status": "completed",
            "current_phase": "report",
            "current_node": "reporter",
            "report": report,
            "finding_ids": list(finding_ids),
            "evidence_ids": list(state.get("evidence_ids", [])),
            "hypothesis_ids": list(state.get("hypothesis_ids", [])),
            "qa_review_ids": list(state.get("qa_review_ids", [])),
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }
    )
    ops.research.add(research)
    return {
        "report_id": report_id,
        "report_payload": report,
        "current_phase": "report",
        "current_node": "reporter",
        "status": "completed",
    }
