"""Triage / Root Cause / Impact / Exploitability agents.

The four nodes form one pipeline over ``state["crash_ids"]``:

``triage_node``
    Load the recorded WinDbg ``!analyze -v`` text, parse it, classify the
    defect, attribute it to a component, and update the Crash record.
    Registers a defect-level ``crash`` evidence anchored at the faulting
    instruction.

``root_cause_node``
    Produce a :class:`~dra.models.root_cause.RootCause` with category,
    function, instruction region, attribution, trigger condition and
    reproducibility.

``impact_node``
    Produce a :class:`~dra.models.impact.SecurityImpact`, using the linked
    hypothesis' threat actor for privilege/vector and the exploitability
    assessment for confidentiality/integrity.

``exploitability_node``
    Produce a :class:`~dra.models.exploitability.ExploitabilityAssessment`
    (theoretical / plausible / demonstrated; never ``weaponized``).

Everything is deterministic and local: no LLM call, no lab call, no
network.  A crash without a readable analysis yields explicit ``unknown``
records rather than a fabricated root cause.
"""

import re
from pathlib import Path

from ..agents._ops import AgentOps
from ..evidence.strength import is_real_location
from ..graph.state import ResearchState
from ..models.common import IDPrefix, new_id
from ..models.crash import Crash
from ..models.evidence import Evidence
from ..models.exploitability import ExploitabilityAssessment
from ..models.hypothesis import Hypothesis
from ..models.impact import SecurityImpact
from ..models.root_cause import RootCause
from ..triage import (
    UNKNOWN,
    DefectClassification,
    WinDbgAnalysis,
    assess_controllability,
    assess_exploitability,
    assess_impact,
    classify_defect,
    crash_classification,
    extract_poc_values,
    parse_windbg_analysis,
    target_module_from_path,
)
from ..triage.windbg import CORE_FIELDS

_ROOT_CAUSE_CATEGORIES = frozenset(
    {
        "null_deref",
        "use_after_free",
        "out_of_bound",
        "pool_corruption",
        "race",
        "input_validation",
        "toctou",
        "uninit_memory",
        "integer_overflow",
        "format_string",
        "invalid_memory_access",
        "stack_overflow",
        "control_flow",
        "logic",
        "unknown",
    }
)
_ATTRIBUTIONS = frozenset(
    {"target_driver", "third_party_driver", "os_component", "environment", "unknown"}
)
_REPRO_VALUES = frozenset({"always", "intermittent", "once"})

_ANALYSIS_MISSING_TRIGGER = (
    "unknown (no parsable WinDbg !analyze -v output was available for this crash)"
)


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _merge_ids(*groups: list[str]) -> list[str]:
    out: list[str] = []
    for group in groups:
        for item in group:
            if item and item not in out:
                out.append(item)
    return out


def _load_analysis_text(crash: Crash, ops: AgentOps) -> tuple[str | None, str | None]:
    """Return ``(text, error)`` for a crash's recorded analysis."""
    if crash.analysis_text:
        return crash.analysis_text, None
    ref = crash.analysis_ref or crash.dump_ref
    if not ref:
        return None, "no analysis_ref / dump_ref / analysis_text on the crash record"
    ref = str(ref)
    if re.fullmatch(r"[0-9a-fA-F]{64}", ref):
        blob = ops.evidence.artefacts.get(ref.lower())
        if blob is None:
            return None, f"analysis artifact {ref} was not found"
        return blob.decode("utf-8", errors="replace"), None
    path = Path(ref)
    try:
        if path.is_file():
            return path.read_text(encoding="utf-8", errors="replace"), None
    except OSError as exc:  # pragma: no cover - platform dependent
        return None, f"could not read analysis reference {ref}: {exc}"
    return None, f"analysis reference not found: {ref}"


def _analysis_from_crash(crash: Crash, ops: AgentOps) -> WinDbgAnalysis | None:
    """Reconstruct the parsed analysis, preferring the stored snapshot."""
    if crash.parsed_analysis:
        try:
            parsed = WinDbgAnalysis.from_dict(crash.parsed_analysis)
        except (TypeError, ValueError):
            parsed = None
        if parsed is not None and (parsed.has_bugcheck or parsed.stack):
            return parsed
    text, _error = _load_analysis_text(crash, ops)
    if text:
        return parse_windbg_analysis(text)
    return None


def _derive_reproducibility(crash: Crash) -> str:
    explicit = (crash.reproducibility or "").strip().lower()
    if explicit in _REPRO_VALUES:
        return explicit
    if crash.reproduced_trials is not None and crash.trial_count:
        try:
            total = int(crash.trial_count)
            reproduced = int(crash.reproduced_trials)
        except (TypeError, ValueError):
            total, reproduced = 0, 0
        if total > 0 and reproduced >= total:
            return "always"
        if reproduced > 0:
            return "intermittent"
        return "once"
    if crash.reproducible:
        # "reproducible" is weaker than "always": the crash reproduced at
        # least once, but no trial counts were recorded.
        return "reproducible"
    return "unknown"


def _crash_category(crash: Crash) -> str:
    if crash.classification in _ROOT_CAUSE_CATEGORIES:
        return crash.classification
    return "unknown"


def _crash_attribution(crash: Crash) -> str:
    if crash.attribution in _ATTRIBUTIONS:
        return crash.attribution
    return "unknown"


def _classification_from_crash(
    crash: Crash,
    parsed: WinDbgAnalysis | None,
    target_module: str | None,
) -> DefectClassification:
    if parsed is not None:
        return classify_defect(parsed, target_module=target_module)
    return DefectClassification(
        category=_crash_category(crash),
        attribution=_crash_attribution(crash),
        confidence="low",
        faulting_frame=None,
        faulting_module=crash.faulting_module,
        faulting_function=crash.faulting_function or UNKNOWN,
        responsible_frame=None,
        instruction_region=crash.faulting_function or UNKNOWN,
        trigger_condition=_ANALYSIS_MISSING_TRIGGER,
        third_party_modules=tuple(crash.third_party_modules),
        reasons=(
            "no parsable WinDbg !analyze -v output was available; category and "
            "attribution cannot be derived from the dump",
        ),
        unknown_fields=tuple(crash.unknown_fields) or CORE_FIELDS,
    )


def _hypothesis_for_crash(
    crash: Crash, state: ResearchState, ops: AgentOps
) -> Hypothesis | None:
    if crash.hypothesis_id:
        h = ops.hypotheses.get(crash.hypothesis_id)
        if h is not None:
            return h
    # Only fall back to the run's single selected hypothesis when the
    # crash is explicitly marked as related; otherwise an unrelated crash
    # would inherit an optimistic threat actor.
    selected = list(state.get("selected_hypothesis_ids") or [])
    if crash.related_to_hypothesis and len(selected) == 1:
        return ops.hypotheses.get(selected[0])
    return None


def _evidence_location(classification: DefectClassification) -> str | None:
    region = classification.instruction_region
    if region and region != UNKNOWN and is_real_location(region):
        return region
    return None


def _upsert_crash_evidence(
    ops: AgentOps,
    *,
    project_id: str,
    target_id: str | None,
    crash: Crash,
    classification: DefectClassification | None,
    text: str | None,
    summary: str,
) -> Evidence:
    """Register or refresh the defect-level ``crash`` evidence."""
    artifact_hash: str | None = None
    if text:
        artifact_hash = ops.evidence.artefacts.put(
            text.encode("utf-8"), content_type="text/plain; charset=utf-8"
        )
    location = _evidence_location(classification) if classification else None
    confidence = classification.confidence if classification else "low"

    if crash.analysis_evidence_id:
        existing = ops.evidence.get(crash.analysis_evidence_id)
        if existing is not None and (
            artifact_hash is None or existing.source_artifact_hash == artifact_hash
        ):
            updated = existing.model_copy(
                update={
                    "summary": summary,
                    "location": location,
                    "confidence": confidence,
                    "related_hypothesis_id": crash.hypothesis_id,
                }
            )
            ops.evidence.store.add(updated)
            return updated

    return ops.evidence.register(
        project_id=project_id,
        evidence_type="crash",
        producer_agent="triage",
        target_id=target_id,
        source_artifact_hash=artifact_hash,
        tool_version="windbg-parser/1.0",
        confidence=confidence,
        location=location,
        dynamic=True,
        reproducible=bool(
            crash.reproducible or _derive_reproducibility(crash) in {"always", "intermittent"}
        ),
        related_hypothesis_id=crash.hypothesis_id,
        related_crash_id=crash.id,
        summary=summary,
        lineage_ids=_merge_ids(
            [crash.id], [crash.hypothesis_id] if crash.hypothesis_id else []
        ),
    )


def _upsert_linked_evidence(
    ops: AgentOps,
    *,
    existing_ids: list[str],
    evidence_type: str,
    project_id: str,
    target_id: str | None,
    crash: Crash,
    location: str | None,
    summary: str,
) -> Evidence:
    """Reuse a matching evidence for this crash, or register a new one."""
    for evidence_id in existing_ids:
        existing = ops.evidence.get(evidence_id)
        if (
            existing is not None
            and existing.evidence_type == evidence_type
            and existing.related_crash_id == crash.id
        ):
            updated = existing.model_copy(
                update={"summary": summary, "location": location}
            )
            ops.evidence.store.add(updated)
            return updated
    return ops.evidence.register(
        project_id=project_id,
        evidence_type=evidence_type,
        producer_agent="triage",
        target_id=target_id,
        tool_version="crash-triage/1.0",
        location=location,
        dynamic=True,
        reproducible=bool(
            crash.reproducible or _derive_reproducibility(crash) in {"always", "intermittent"}
        ),
        related_hypothesis_id=crash.hypothesis_id,
        related_crash_id=crash.id,
        summary=summary,
        lineage_ids=_merge_ids(
            [crash.id],
            [crash.root_cause_id] if crash.root_cause_id else [],
            [crash.hypothesis_id] if crash.hypothesis_id else [],
        ),
    )


def _crash_summary(
    classification: DefectClassification, parsed: WinDbgAnalysis
) -> str:
    label = parsed.bugcheck_label if parsed.has_bugcheck else UNKNOWN
    owner = {
        "target_driver": "target driver",
        "third_party_driver": "third-party module",
        "os_component": "OS component",
        "environment": "environment",
        "unknown": "unknown component",
    }.get(classification.attribution, classification.attribution)
    location = classification.instruction_region
    if (
        classification.faulting_function
        and classification.faulting_function != UNKNOWN
        and classification.faulting_function != location
    ):
        location = f"{location} (fault fired in {classification.faulting_function})"
    return (
        f"{label}; root cause {location}; "
        f"category {classification.category}; attribution {owner}"
    )[:500]


def _missing_summary(crash: Crash, reason: str | None) -> str:
    detail = f" ({reason})" if reason else ""
    return (
        "Crash recorded without a parsable WinDbg !analyze -v output"
        f"{detail}; root cause, attribution and impact are unknown."
    )[:500]


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


async def triage_node(state: ResearchState, ops: AgentOps) -> dict:
    project_id = state["project_id"]
    target_id = state.get("target_id")
    target_module = target_module_from_path(state.get("target_path"))
    crash_ids = list(dict.fromkeys(state.get("crash_ids", [])))
    notes = list(state.get("crash_analysis_notes", []))
    evidence_ids = list(state.get("evidence_ids", []))

    summary = {
        "crashes": len(crash_ids),
        "analyzed": 0,
        "partial": 0,
        "missing_analysis": 0,
        "third_party": 0,
        "unattributed": 0,
    }

    if not crash_ids:
        summary["note"] = "no crash records supplied; nothing to triage"
        return {
            "crash_ids": [],
            "evidence_ids": evidence_ids,
            "triage_done": True,
            "triage_summary": summary,
            "crash_analysis_notes": notes,
            "current_phase": "evidence",
            "current_node": "triage",
        }

    new_evidence_ids: list[str] = []
    for crash_id in crash_ids:
        crash = ops.crashes.get(crash_id)
        if crash is None:
            notes.append(f"triage: crash {crash_id} is not in the crash store")
            continue

        text, read_error = _load_analysis_text(crash, ops)
        if text is None:
            # No analysis: record the absence, never substitute a guess.
            crash.analysis_status = (
                "missing_analysis" if not (crash.analysis_ref or crash.dump_ref) else "unreadable"
            )
            crash.bugcheck_code = None
            crash.bugcheck_name = None
            crash.process_name = None
            crash.failure_bucket_id = None
            crash.faulting_module = None
            crash.faulting_function = None
            crash.faulting_offset = None
            crash.target_frame = None
            crash.attribution = "unknown"
            crash.classification = "unknown"
            crash.unknown_fields = list(CORE_FIELDS)
            crash.third_party_modules = []
            crash.parse_warnings = []
            crash.parsed_analysis = {}
            if crash.reproducibility is None:
                derived = _derive_reproducibility(crash)
                crash.reproducibility = derived if derived != "unknown" else None
            crash.related_to_hypothesis = bool(crash.hypothesis_id) or crash.related_to_hypothesis
            crash.summary = _missing_summary(crash, read_error)
            summary["missing_analysis"] += 1
            summary["unattributed"] += 1

            evidence = _upsert_crash_evidence(
                ops,
                project_id=project_id,
                target_id=target_id,
                crash=crash,
                classification=None,
                text=None,
                summary=crash.summary,
            )
            crash.analysis_evidence_id = evidence.id
            new_evidence_ids.append(evidence.id)
            ops.crashes.add(crash)
            notes.append(
                f"triage: crash {crash.id} has no readable analysis ({read_error}); "
                "all derived fields are unknown"
            )
            continue

        parsed = parse_windbg_analysis(text)
        classification = classify_defect(parsed, target_module=target_module)

        crash.bugcheck_code = (
            f"0x{parsed.bugcheck_code:X}" if parsed.bugcheck_code is not None else None
        )
        crash.bugcheck_name = parsed.bugcheck_name
        crash.process_name = parsed.process_name
        crash.failure_bucket_id = parsed.failure_bucket_id
        fault = parsed.faulting_frame
        crash.faulting_module = fault.module if fault is not None else None
        crash.faulting_function = fault.location if fault is not None else None
        crash.faulting_offset = (
            f"0x{fault.offset:x}" if fault is not None and fault.offset is not None else None
        )
        first_target = classification.first_target_frame
        crash.target_frame = first_target.location if first_target is not None else None
        crash.attribution = classification.attribution
        crash.classification = crash_classification(classification)  # type: ignore[assignment]
        crash.unknown_fields = list(classification.unknown_fields)
        crash.third_party_modules = list(classification.third_party_modules)
        crash.parse_warnings = list(parsed.parse_warnings)
        crash.parsed_analysis = parsed.to_dict()
        if crash.reproducibility is None:
            derived = _derive_reproducibility(crash)
            crash.reproducibility = derived if derived != "unknown" else None
        crash.related_to_hypothesis = bool(crash.hypothesis_id) or crash.related_to_hypothesis
        crash.analysis_status = (
            "parsed"
            if parsed.is_parsed and fault is not None
            else "partial"
        )
        crash.summary = _crash_summary(classification, parsed)

        if crash.analysis_status == "parsed":
            summary["analyzed"] += 1
        else:
            summary["partial"] += 1
        if classification.attribution == "third_party_driver":
            summary["third_party"] += 1
        if classification.attribution == "unknown":
            summary["unattributed"] += 1

        evidence = _upsert_crash_evidence(
            ops,
            project_id=project_id,
            target_id=target_id,
            crash=crash,
            classification=classification,
            text=text,
            summary=crash.summary,
        )
        crash.analysis_evidence_id = evidence.id
        new_evidence_ids.append(evidence.id)
        ops.crashes.add(crash)

    return {
        "crash_ids": crash_ids,
        "evidence_ids": _merge_ids(evidence_ids, new_evidence_ids),
        "triage_done": True,
        "triage_summary": summary,
        "crash_analysis_notes": notes,
        "current_phase": "evidence",
        "current_node": "triage",
    }


async def root_cause_node(state: ResearchState, ops: AgentOps) -> dict:
    project_id = state["project_id"]
    target_id = state.get("target_id")
    target_module = target_module_from_path(state.get("target_path"))
    crash_ids = list(dict.fromkeys(state.get("crash_ids", [])))
    notes = list(state.get("crash_analysis_notes", []))
    existing_ids = list(state.get("root_cause_ids", []))
    evidence_ids = list(state.get("evidence_ids", []))
    produced: list[str] = []
    new_evidence_ids: list[str] = []

    for crash_id in crash_ids:
        crash = ops.crashes.get(crash_id)
        if crash is None:
            notes.append(f"root_cause: crash {crash_id} is not in the crash store")
            continue

        parsed = _analysis_from_crash(crash, ops)
        classification = _classification_from_crash(crash, parsed, target_module)
        reproducibility = _derive_reproducibility(crash)
        poc_values = extract_poc_values(crash.poc_input)
        control = assess_controllability(parsed, poc_values=poc_values)
        input_field = control.matches[0] if control.matches else None

        existing = ops.root_causes.get(crash.root_cause_id) if crash.root_cause_id else None
        existing_evidence_ids = list(existing.evidence_ids) if existing else []
        location = _evidence_location(classification)
        evidence = _upsert_linked_evidence(
            ops,
            existing_ids=existing_evidence_ids,
            evidence_type="root_cause",
            project_id=project_id,
            target_id=target_id,
            crash=crash,
            location=location,
            summary=(
                f"root cause {classification.category} attributed to "
                f"{classification.attribution} at {classification.instruction_region}"
            ),
        )
        new_evidence_ids.append(evidence.id)

        root_notes = list(classification.reasons)
        if crash.hypothesis_id is None:
            root_notes.append(
                "no hypothesis is linked to this crash record; "
                "related_hypothesis_id is unknown"
            )
        fields = {
            "project_id": project_id,
            "crash_id": crash.id,
            "category": classification.category,
            "function": classification.root_cause_function,
            "instruction_region": classification.instruction_region,
            "input_field": input_field,
            "trigger_condition": classification.trigger_condition,
            "reproducibility": reproducibility,
            "related_hypothesis_id": crash.hypothesis_id,
            "attribution": classification.attribution,
            "confidence": classification.confidence,
            "bugcheck_code": crash.bugcheck_code,
            "failure_bucket_id": crash.failure_bucket_id,
            "faulting_module": classification.faulting_module,
            "notes": root_notes,
            "unknown_fields": list(classification.unknown_fields),
            "evidence_ids": _merge_ids(existing_evidence_ids, [evidence.id]),
        }
        if existing is not None:
            record = existing.model_copy(update=fields)
        else:
            record = RootCause(
                id=new_id(IDPrefix.ROOT_CAUSE),
                **fields,  # type: ignore[arg-type]
            )
        ops.root_causes.add(record)
        produced.append(record.id)
        crash.root_cause_id = record.id
        ops.crashes.add(crash)

    return {
        "root_cause_ids": _merge_ids(existing_ids, produced),
        "evidence_ids": _merge_ids(evidence_ids, new_evidence_ids),
        "crash_analysis_notes": notes,
        "current_phase": "evidence",
        "current_node": "root_cause",
    }


async def impact_node(state: ResearchState, ops: AgentOps) -> dict:
    project_id = state["project_id"]
    target_id = state.get("target_id")
    target_module = target_module_from_path(state.get("target_path"))
    crash_ids = list(dict.fromkeys(state.get("crash_ids", [])))
    notes = list(state.get("crash_analysis_notes", []))
    existing_ids = list(state.get("impact_ids", []))
    evidence_ids = list(state.get("evidence_ids", []))
    produced: list[str] = []
    new_evidence_ids: list[str] = []

    for crash_id in crash_ids:
        crash = ops.crashes.get(crash_id)
        if crash is None:
            notes.append(f"impact: crash {crash_id} is not in the crash store")
            continue

        parsed = _analysis_from_crash(crash, ops)
        classification = _classification_from_crash(crash, parsed, target_module)
        reproducibility = _derive_reproducibility(crash)
        exploitability = assess_exploitability(
            parsed,
            classification,
            reproducibility=reproducibility,
            poc_values=extract_poc_values(crash.poc_input),
        )
        hypothesis = _hypothesis_for_crash(crash, state, ops)
        impact = assess_impact(classification, exploitability, hypothesis=hypothesis)

        existing = ops.impacts.get(crash.impact_id) if crash.impact_id else None
        existing_evidence_ids = list(existing.evidence_ids) if existing else []
        location = _evidence_location(classification)
        evidence = _upsert_linked_evidence(
            ops,
            existing_ids=existing_evidence_ids,
            evidence_type="impact",
            project_id=project_id,
            target_id=target_id,
            crash=crash,
            location=location,
            summary=(
                f"impact {impact.impact_type}; boundary_crossed="
                f"{impact.privilege_boundary_crossed}; attribution={classification.attribution}"
            ),
        )
        new_evidence_ids.append(evidence.id)

        fields = {
            "project_id": project_id,
            "impact_type": impact.impact_type,
            "privilege_boundary_crossed": impact.privilege_boundary_crossed,
            "confidentiality": impact.confidentiality,
            "integrity": impact.integrity,
            "availability": impact.availability,
            "attack_vector": impact.attack_vector,
            "required_privilege": impact.required_privilege,
            "user_interaction": impact.user_interaction,
            "notes": impact.notes,
            "evidence_ids": _merge_ids(existing_evidence_ids, [evidence.id]),
            "crash_id": crash.id,
            "root_cause_id": crash.root_cause_id,
            "related_hypothesis_id": crash.hypothesis_id,
            "attribution": classification.attribution,
            "confidence": impact.confidence,
        }
        if existing is not None:
            record = existing.model_copy(update=fields)
        else:
            record = SecurityImpact(
                id=new_id(IDPrefix.IMPACT),
                **fields,  # type: ignore[arg-type]
            )
        ops.impacts.add(record)
        produced.append(record.id)
        crash.impact_id = record.id
        ops.crashes.add(crash)

    return {
        "impact_ids": _merge_ids(existing_ids, produced),
        "evidence_ids": _merge_ids(evidence_ids, new_evidence_ids),
        "crash_analysis_notes": notes,
        "current_phase": "evidence",
        "current_node": "impact",
    }


async def exploitability_node(state: ResearchState, ops: AgentOps) -> dict:
    project_id = state["project_id"]
    target_id = state.get("target_id")
    target_module = target_module_from_path(state.get("target_path"))
    crash_ids = list(dict.fromkeys(state.get("crash_ids", [])))
    notes = list(state.get("crash_analysis_notes", []))
    existing_ids = list(state.get("exploitability_ids", []))
    evidence_ids = list(state.get("evidence_ids", []))
    produced: list[str] = []
    new_evidence_ids: list[str] = []

    for crash_id in crash_ids:
        crash = ops.crashes.get(crash_id)
        if crash is None:
            notes.append(f"exploitability: crash {crash_id} is not in the crash store")
            continue

        parsed = _analysis_from_crash(crash, ops)
        classification = _classification_from_crash(crash, parsed, target_module)
        reproducibility = _derive_reproducibility(crash)
        assessment = assess_exploitability(
            parsed,
            classification,
            reproducibility=reproducibility,
            poc_values=extract_poc_values(crash.poc_input),
        )

        existing = (
            ops.exploitabilities.get(crash.exploitability_id)
            if crash.exploitability_id
            else None
        )
        existing_evidence_ids = list(existing.evidence_ids) if existing else []
        location = _evidence_location(classification)
        evidence = _upsert_linked_evidence(
            ops,
            existing_ids=existing_evidence_ids,
            evidence_type="exploitability",
            project_id=project_id,
            target_id=target_id,
            crash=crash,
            location=location,
            summary=(
                f"exploitability {assessment.level}; controllability "
                f"{assessment.controllability}; reliability {assessment.reliability}"
            ),
        )
        new_evidence_ids.append(evidence.id)

        fields = {
            "project_id": project_id,
            "exploitability_level": assessment.level,
            "controllability": assessment.controllability,
            "reliability": assessment.reliability,
            "constraints": list(assessment.constraints),
            "mitigations_observed": list(assessment.mitigations_observed),
            "evidence_ids": _merge_ids(existing_evidence_ids, [evidence.id]),
            "notes": assessment.notes,
            "crash_id": crash.id,
            "root_cause_id": crash.root_cause_id,
            "controlled_values": list(assessment.controlled_values),
        }
        if existing is not None:
            record = existing.model_copy(update=fields)
        else:
            record = ExploitabilityAssessment(
                id=new_id(IDPrefix.EXPLOITABILITY),
                **fields,  # type: ignore[arg-type]
            )
        ops.exploitabilities.add(record)
        produced.append(record.id)
        crash.exploitability_id = record.id
        ops.crashes.add(crash)

    return {
        "exploitability_ids": _merge_ids(existing_ids, produced),
        "evidence_ids": _merge_ids(evidence_ids, new_evidence_ids),
        "crash_analysis_notes": notes,
        "current_phase": "evidence",
        "current_node": "exploitability",
    }
