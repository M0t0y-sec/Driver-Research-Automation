"""Classify evidence by *what it proves*: attack surface or concrete defect.

Strength (E0-E7, see :mod:`dra.evidence.strength`) answers "how well is
this fact established?".  It does not answer "what does this fact
establish?".  A real IOCTL constant compared in a real dispatch handler
at a real RVA is a well-established fact *about the attack surface*; it
is not evidence that a defect exists.  Conflating the two produced false
positives: "Potential issue in ioctl_code at IOCTL 0x00010000" reached
``qa_pass`` because its location happened to be real.

The QA gate therefore requires at least one evidence of a defect-level
kind:

=================  =====================================================
kind               what the evidence establishes
=================  =====================================================
``surface``        the interface exists: device / symlink name, IOCTL
                   constant, MajorFunction store, imported primitive
``sink``           a concrete dangerous operation whose arguments are
                   attacker-influenced (copy sink, unchecked index)
``control_flow``   a concrete path or missing check (no ProbeForRead /
                   ProbeForWrite, absent bounds check, overflow
                   expression, tainted index)
``crash``          a real crash stack / bugcheck tied to attacker input
``root_cause``     the defect's cause is identified
``impact``         security impact is confirmed
=================  =====================================================

Only ``sink`` / ``control_flow`` / ``crash`` can support a *passing*
finding (:data:`DEFECT_KINDS`).  ``root_cause`` and ``impact`` are
valuable but presuppose a defect mechanism; they do not establish one on
their own.

Classification reads structured fields of the evidence record only -
``evidence_type`` and ``related_crash_id`` - never free-text summaries,
so the result is deterministic and cheap to audit.  Canonical defect
type names include ``memory_copy_sink``, ``missing_probe``,
``taint_path``, ``bounds_violation``, ``integer_overflow`` and
``crash``.  A type carrying no recognised marker is classified
``surface``: the conservative default, because an unrecognised fact
cannot be assumed to prove a defect.
"""
from __future__ import annotations

from enum import Enum


class EvidenceKind(str, Enum):
    """What an evidence object proves, independent of its E-grade."""

    SURFACE = "surface"
    SINK = "sink"
    CONTROL_FLOW = "control_flow"
    CRASH = "crash"
    ROOT_CAUSE = "root_cause"
    IMPACT = "impact"


#: Kinds that can support a finding on their own: each names a concrete
#: defect mechanism, not merely the existence of an attack surface.
DEFECT_KINDS: frozenset[EvidenceKind] = frozenset(
    {EvidenceKind.SINK, EvidenceKind.CONTROL_FLOW, EvidenceKind.CRASH}
)

# Markers are matched against the *structured* evidence_type, never the
# summary.  Order mirrors the strength derivation: the strongest claim a
# type can carry wins.
_IMPACT_MARKERS = ("impact", "exploit")
_ROOT_CAUSE_MARKERS = ("root_cause",)
_CRASH_MARKERS = ("crash", "dump", "bugcheck")
_CONTROL_FLOW_MARKERS = (
    "control_flow",
    "dataflow",
    "taint",
    "missing_probe",
    "probe_absence",
    "missing_check",
    "check_absence",
    "bounds",
    "out_of_bounds",
    "integer_overflow",
    "overflow",
)
_SINK_MARKERS = ("sink",)


def _normalise(evidence_type: str | None) -> str:
    return (evidence_type or "").strip().lower().replace("-", "_")


def derive_evidence_kind(
    *,
    evidence_type: str = "",
    related_crash_id: str | None = None,
) -> EvidenceKind:
    """Derive the evidence kind from structured record fields.

    ``related_crash_id`` is a structured link to a crash record, so it
    promotes otherwise-untyped evidence to :attr:`EvidenceKind.CRASH`.
    """
    etype = _normalise(evidence_type)
    if any(marker in etype for marker in _IMPACT_MARKERS):
        return EvidenceKind.IMPACT
    if any(marker in etype for marker in _ROOT_CAUSE_MARKERS):
        return EvidenceKind.ROOT_CAUSE
    if related_crash_id or any(marker in etype for marker in _CRASH_MARKERS):
        return EvidenceKind.CRASH
    if any(marker in etype for marker in _CONTROL_FLOW_MARKERS):
        return EvidenceKind.CONTROL_FLOW
    if any(marker in etype for marker in _SINK_MARKERS):
        return EvidenceKind.SINK
    return EvidenceKind.SURFACE


def is_defect_kind(value: EvidenceKind | str) -> bool:
    """True when the kind can establish a defect on its own."""
    try:
        return EvidenceKind(value) in DEFECT_KINDS
    except ValueError:
        return False
