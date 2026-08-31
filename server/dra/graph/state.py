"""Reference-typed ResearchState.

Only IDs + summaries + status + routing fields live in the state.
Large Pydantic models are fetched from storage by the agents.
"""
from __future__ import annotations

from typing import TypedDict


class ResearchState(TypedDict, total=False):
    # --- identity ---
    project_id: str
    research_id: str
    target_id: str
    target_path: str
    environment_id: str

    # --- lifecycle ---
    status: str
    current_phase: str
    current_node: str
    failure_class: str | None
    retry_count: int

    # --- plan ---
    plan_id: str | None
    plan_payload: dict

    # --- recon / static ---
    recon_summary_id: str | None
    pe_report_sha: str | None
    static_analysis_summary_id: str | None
    attack_surface_id: str | None

    # --- reverse ---
    reverse_summary_id: str | None
    reverse_summary_text: str

    # --- hypothesis / ranking ---
    hypothesis_ids: list[str]
    selected_hypothesis_ids: list[str]

    # --- input generation ---
    test_case_set_ids: list[str]

    # --- experiment / execution / crash / telemetry ---
    experiment_ids: list[str]
    execution_ids: list[str]
    crash_ids: list[str]
    telemetry_batch_ids: list[str]

    # --- triage / rca / impact / exploit ---
    root_cause_ids: list[str]
    impact_ids: list[str]
    exploitability_ids: list[str]

    # --- evidence / qa / finding ---
    observation_ids: list[str]
    evidence_ids: list[str]
    qa_review_ids: list[str]
    finding_ids: list[str]

    # --- detection ---
    visibility_result_id: str | None
    detection_result_ids: list[str]
    robustness_result_id: str | None

    # --- approvals / errors ---
    pending_approvals: list[str]
    error_ids: list[str]

    # --- report ---
    report_id: str | None
    report_payload: dict


EMPTY_STATE: ResearchState = {
    "status": "idle",
    "current_phase": "init",
    "current_node": "init",
    "retry_count": 0,
    "hypothesis_ids": [],
    "selected_hypothesis_ids": [],
    "test_case_set_ids": [],
    "experiment_ids": [],
    "execution_ids": [],
    "crash_ids": [],
    "telemetry_batch_ids": [],
    "root_cause_ids": [],
    "impact_ids": [],
    "exploitability_ids": [],
    "observation_ids": [],
    "evidence_ids": [],
    "qa_review_ids": [],
    "finding_ids": [],
    "detection_result_ids": [],
    "pending_approvals": [],
    "error_ids": [],
}
