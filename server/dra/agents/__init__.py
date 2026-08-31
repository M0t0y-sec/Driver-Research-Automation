"""Agents package.

Each agent is a thin async function that takes the current
`ResearchState` and a `GraphContext`, and returns a partial state
update. Agents NEVER touch storage directly; they call helper
functions in `dra.agents._ops` which own the storage / LLM / tool
gateway interactions.
"""
from .planner import planner_node
from .recon import recon_node
from .reverse import reverse_node
from .hypothesis import hypothesis_node, hypothesis_ranking_node
from .input_generation import input_generation_node
from .experiment import experiment_planner_node
from .validation import validation_node
from .triage import triage_node, root_cause_node, impact_node, exploitability_node
from .telemetry import telemetry_node
from .detection import (
    visibility_node,
    detection_node,
    robustness_node,
)
from .evidence_registrar import evidence_registrar_node
from .qa_auditor import qa_auditor_node
from .reporter import reporter_node
from ._ops import AgentOps, build_ops

__all__ = [
    "planner_node",
    "recon_node",
    "reverse_node",
    "hypothesis_node",
    "hypothesis_ranking_node",
    "input_generation_node",
    "experiment_planner_node",
    "validation_node",
    "triage_node",
    "root_cause_node",
    "impact_node",
    "exploitability_node",
    "telemetry_node",
    "visibility_node",
    "detection_node",
    "robustness_node",
    "evidence_registrar_node",
    "qa_auditor_node",
    "reporter_node",
    "AgentOps",
    "build_ops",
]
