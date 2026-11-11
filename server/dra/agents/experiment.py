"""Experiment Planner Agent."""

from ..agents._ops import AgentOps
from ..config import SETTINGS
from ..graph.state import ResearchState
from ..models.common import ExperimentStatus, IDPrefix, new_id
from ..models.experiment import ExperimentPlan
from ..storage.filesystem import ExperimentStore


async def experiment_planner_node(state: ResearchState, ops: AgentOps) -> dict:
    selected: list[str] = state.get("selected_hypothesis_ids", [])
    if not selected:
        return {
            "experiment_ids": [],
            "current_phase": "evidence",
            "current_node": "experiment_planner",
        }
    top = selected[0]
    plan = ExperimentPlan(
        id=new_id(IDPrefix.EXPERIMENT),
        hypothesis_id=top,
        project_id=state["project_id"],
        environment_id=state.get("environment_id", "ENV-MOCK"),
        setup=["mock_lab:health_check"],
        observation_points=["event_log", "etw"],
        success_criteria=["telemetry_collected=true"],
        failure_criteria=["env_anomaly_rate>0.2"],
        safety_constraints=["isolated_vm_only"],
        expected_telemetry=["process", "image_load", "driver"],
        timeout_seconds=300,
        trial_count=3,
        status=ExperimentStatus.DRAFT,
        risk_level="low",
    )
    ExperimentStore(SETTINGS.data_dir / "experiments").add(plan)
    return {
        "experiment_ids": [plan.id],
        "current_phase": "evidence",
        "current_node": "experiment_planner",
    }
