"""Detection / Visibility / Robustness (Phase 0/1 stubs)."""

from ..agents._ops import AgentOps
from ..config import SETTINGS
from ..graph.state import ResearchState
from ..models.common import DetectionStage, DetectionVerdict, IDPrefix, new_id
from ..models.detection import DetectionResult
from ..models.visibility import VisibilityResult
from ..storage.filesystem import DetectionStore, VisibilityStore


async def visibility_node(state: ResearchState, ops: AgentOps) -> dict:
    v = VisibilityResult(
        id=new_id(IDPrefix.VISIBILITY),
        project_id=state["project_id"],
        execution_id="(skipped)",
        process_event_visible=False,
        image_load_visible=False,
        driver_load_visible=False,
        file_event_visible=False,
        registry_event_visible=False,
        network_event_visible=False,
        kernel_callback_visible=False,
        etw_available=False,
        security_product_logs_available=False,
        event_complete=False,
        timestamp_aligned=False,
        passed=False,
        reasons=["Phase 0/1: no live execution performed; visibility not assessed."],
    )
    VisibilityStore(SETTINGS.data_dir / "visibility").add(v)
    return {
        "visibility_result_id": v.id,
        "current_phase": "detection",
        "current_node": "visibility",
    }


async def detection_node(state: ResearchState, ops: AgentOps) -> dict:
    d = DetectionResult(
        id=new_id(IDPrefix.DETECTION),
        project_id=state["project_id"],
        execution_id="(skipped)",
        behavior_confirmed=False,
        telemetry_collected=False,
        detection_stage=DetectionStage.NONE,
        verdict=DetectionVerdict.INCONCLUSIVE,
        detection_confidence="low",
        inconclusive_reason="Phase 0/1: no live execution.",
        trials_total=0,
    )
    DetectionStore(SETTINGS.data_dir / "detection").add(d)
    return {
        "detection_result_ids": (state.get("detection_result_ids", []) + [d.id]),
        "current_phase": "detection",
        "current_node": "detection",
    }


async def robustness_node(state: ResearchState, ops: AgentOps) -> dict:
    return {
        "current_phase": "qa",
        "current_node": "robustness",
    }
