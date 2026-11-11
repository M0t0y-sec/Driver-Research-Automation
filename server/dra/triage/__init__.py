"""Crash triage: WinDbg parsing, defect classification, impact and exploitability.

The four public stages mirror the research graph nodes:

``parse_windbg_analysis`` -> :class:`WinDbgAnalysis`
``classify_defect``       -> :class:`DefectClassification`
``assess_impact``         -> :class:`ImpactResult`
``assess_exploitability`` -> :class:`ExploitabilityResult`

Only :func:`classify_defect` is stateful in the sense that it needs the
target module name; nothing here touches storage, the LLM, or the lab.
"""
from .classify import (
    MEMORY_CORRUPTION_CATEGORIES,
    DefectClassification,
    classify_defect,
    crash_classification,
    is_os_module,
    target_module_from_path,
)
from .exploitability import (
    ControlEvidence,
    ExploitabilityResult,
    assess_controllability,
    assess_exploitability,
    extract_poc_values,
)
from .impact import ImpactResult, assess_impact
from .windbg import (
    UNKNOWN,
    StackFrame,
    WinDbgAnalysis,
    parse_windbg_analysis,
)

__all__ = [
    "UNKNOWN",
    "StackFrame",
    "WinDbgAnalysis",
    "parse_windbg_analysis",
    "DefectClassification",
    "classify_defect",
    "crash_classification",
    "target_module_from_path",
    "is_os_module",
    "MEMORY_CORRUPTION_CATEGORIES",
    "ControlEvidence",
    "ExploitabilityResult",
    "assess_controllability",
    "assess_exploitability",
    "extract_poc_values",
    "ImpactResult",
    "assess_impact",
]
