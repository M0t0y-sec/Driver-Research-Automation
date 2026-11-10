"""Deterministic evidence-strength derivation (E0-E7).

Strength is a property of *facts* - what was observed, where, and whether
it can be reproduced - not of what the caller claims. `EvidenceRegistrar`
uses :func:`derive_evidence_strength` to clamp caller-supplied grades, and
the QA gate re-derives the effective grade from the stored evidence at
review time (defence in depth against old / hand-written records).

Semantics (design doc section 7.11.1):

    E0  LLM opinion (not evidence)
    E1  Static observation
    E2  Dynamic observation
    E3  Reproducible signal
    E4  Crash / dump
    E5  Root cause linked
    E6  Security impact confirmed
    E7  QA passed

Downgrade rules (required by the QA gate design):

* No ``source_artifact_hash`` -> one level down.
* No usable ``location`` (empty / unknown / null) -> one level down.
* Import-table-only material can never exceed E1.
"""
from __future__ import annotations

import re

from ..models.common import EvidenceStrength
from ..models.evidence import Evidence

# Ordered from weakest to strongest; index == rank.
_ORDER: tuple[EvidenceStrength, ...] = (
    EvidenceStrength.E0,
    EvidenceStrength.E1,
    EvidenceStrength.E2,
    EvidenceStrength.E3,
    EvidenceStrength.E4,
    EvidenceStrength.E5,
    EvidenceStrength.E6,
    EvidenceStrength.E7,
)

_PLACEHOLDER_RE = re.compile(
    r"(?i)\b(?:unknown|null|none|nil|tbd|todo|unset|undefined|n/?a)\b"
)
_PLACEHOLDER_VALUES = {"", "-", "?", "??", "n/a", "na"}

# A real code location contains an address, an RVA/offset, a section, or a
# module-qualified symbol. Bare identifiers ("ZwCreateFile") are import /
# symbol *names*, not locations.
_LOCATION_RE = re.compile(
    r"(?i)("
    r"0x[0-9a-f]{2,}"
    r"|\brva\b|\bva\b|\boffset\b|\bimage_?base\b|\bsection\s*:"
    r"|\b(?:func|function|symbol)\s*:"
    r"|[A-Za-z0-9_.\-]+![A-Za-z_][A-Za-z0-9_@?$]*"
    r")"
)
_BARE_IDENTIFIER_RE = re.compile(r"[A-Za-z_~?][A-Za-z0-9_@?$~]*")
_IMPORT_LOCATION_RE = re.compile(
    r"(?i)(^|[:/_.\s\-])(imports?|iat|import[_\- ]?table|import[_\- ]?directory)([:/_.\s\-]|$)"
)
_IMPORT_SUMMARY_RE = re.compile(r"(?i)\b(?:imports?|imported|import[_\- ]?table|iat)\b")

# Evidence that is merely an LLM opinion - never stronger than E0.
_MODEL_PRODUCERS = {"hypothesis", "qa_auditor", "qa", "reporter", "llm", "model"}
_MODEL_TYPE_MARKERS = (
    "model_opinion",
    "llm_opinion",
    "hypothesis_rule_signal",
    "hypothesis_signal",
    "hypothesis",
    "opinion",
)

_DYNAMIC_TYPE_MARKERS = ("dynamic", "telemetry", "execution", "lab", "runtime")
_REPRO_TYPE_MARKERS = ("repro", "repeatable")
_CRASH_TYPE_MARKERS = ("crash", "dump", "bugcheck")
_ROOT_CAUSE_TYPE_MARKERS = ("root_cause", "root-cause")
_IMPACT_TYPE_MARKERS = ("impact", "exploitability", "exploit_confirmed")


def strength_rank(value: EvidenceStrength | str) -> int:
    """Rank of an evidence strength, E0=0 .. E7=7."""
    return _ORDER.index(EvidenceStrength(value))


def downgrade_strength(
    value: EvidenceStrength | str, levels: int = 1
) -> EvidenceStrength:
    """Move a strength down by ``levels`` (floored at E0)."""
    idx = max(0, strength_rank(value) - max(0, levels))
    return _ORDER[idx]


def lower_strength(
    a: EvidenceStrength | str, b: EvidenceStrength | str
) -> EvidenceStrength:
    """The weaker of two strengths."""
    return EvidenceStrength(a) if strength_rank(a) <= strength_rank(b) else EvidenceStrength(b)


def is_placeholder_location(value: str | None) -> bool:
    """True when a location is empty or an explicit unknown/null marker."""
    if value is None:
        return True
    text = str(value).strip()
    if text.lower() in _PLACEHOLDER_VALUES:
        return True
    return bool(_PLACEHOLDER_RE.search(text))


def is_import_location(value: str | None) -> bool:
    """True when a location names the import table / IAT."""
    if value is None:
        return False
    text = str(value).strip()
    if not text:
        return False
    return bool(_IMPORT_LOCATION_RE.search(text))


def is_real_location(value: str | None) -> bool:
    """True when a location carries an address-like anchor.

    Accepted forms include ``0x140001000``, ``rva:0x1234``,
    ``section:.text+0x40``, ``func:DriverEntry`` and
    ``driver.sys!DriverEntry``. The strings ``unknown`` / ``null`` / empty
    and bare symbol names (``IoCreateDevice``) are rejected: a name alone
    identifies *what*, not *where*.
    """
    if value is None:
        return False
    text = str(value).strip()
    if not text or is_placeholder_location(text):
        return False
    if is_import_location(text):
        return False
    if _BARE_IDENTIFIER_RE.fullmatch(text):
        return False
    return bool(_LOCATION_RE.search(text))


def extract_location(text: str | None) -> str | None:
    """Best-effort: pull the first address-like token out of free text."""
    if not text:
        return None
    m = _LOCATION_RE.search(text)
    return m.group(0) if m else None


def evidence_is_import_only(ev: Evidence, location: str | None = None) -> bool:
    """True when the evidence rests solely on import-table material."""
    etype = (ev.evidence_type or "").lower()
    if "import" in etype:
        return True
    loc = location if location is not None else getattr(ev, "location", None)
    if loc:
        if is_import_location(loc):
            return True
        if is_real_location(loc):
            return False
    # Dynamic / crash material is not import-only even if the word appears
    # in its summary.
    if any(m in etype for m in _DYNAMIC_TYPE_MARKERS + _REPRO_TYPE_MARKERS
           + _CRASH_TYPE_MARKERS + _ROOT_CAUSE_TYPE_MARKERS):
        return False
    summary = ev.summary or ""
    return bool(_IMPORT_SUMMARY_RE.search(summary)) and not _LOCATION_RE.search(summary)


def _is_model_opinion(
    *,
    evidence_type: str,
    producer_agent: str,
    model_version: str | None,
    tool_version: str | None,
    dynamic: bool,
) -> bool:
    etype = (evidence_type or "").lower()
    producer = (producer_agent or "").lower()
    if producer in _MODEL_PRODUCERS:
        return True
    if any(marker in etype for marker in _MODEL_TYPE_MARKERS):
        return True
    # A model-authored "observation" with no tool behind it is an opinion.
    if model_version and not tool_version and not dynamic:
        return True
    return False


def derive_evidence_strength(
    *,
    evidence_type: str = "",
    producer_agent: str = "",
    source_artifact_hash: str | None = None,
    location: str | None = None,
    summary: str = "",
    model_version: str | None = None,
    tool_version: str | None = None,
    dynamic: bool = False,
    reproducible: bool = False,
) -> EvidenceStrength:
    """Derive evidence strength from facts alone.

    Callers do not get to choose their own grade: the registrar takes the
    weaker of this derived grade and any claimed grade.
    """
    etype = (evidence_type or "").lower()
    loc = location if location is not None else extract_location(summary)

    model_opinion = _is_model_opinion(
        evidence_type=evidence_type,
        producer_agent=producer_agent,
        model_version=model_version,
        tool_version=tool_version,
        dynamic=dynamic,
    )
    is_dynamic = dynamic or any(m in etype for m in _DYNAMIC_TYPE_MARKERS)
    is_repro = reproducible or any(m in etype for m in _REPRO_TYPE_MARKERS)
    has_location = bool(loc) and not is_placeholder_location(loc)

    if model_opinion:
        base = EvidenceStrength.E0
    elif any(m in etype for m in _IMPACT_TYPE_MARKERS):
        base = EvidenceStrength.E6
    elif any(m in etype for m in _ROOT_CAUSE_TYPE_MARKERS):
        base = EvidenceStrength.E5
    elif any(m in etype for m in _CRASH_TYPE_MARKERS):
        base = EvidenceStrength.E4
    elif is_dynamic or is_repro:
        # Reproducible *and* anchored to a real location -> E3.
        base = EvidenceStrength.E3 if (is_repro and has_location) else EvidenceStrength.E2
    else:
        # Static observation / import name / tool output.
        base = EvidenceStrength.E1

    # Import-table-only material never exceeds E1.
    import_only = (
        "import" in etype
        or (bool(loc) and is_import_location(loc))
        or (
            not (is_dynamic or is_repro)
            and bool(_IMPORT_SUMMARY_RE.search(summary or ""))
            and not _LOCATION_RE.search(summary or "")
        )
    )
    if import_only:
        base = lower_strength(base, EvidenceStrength.E1)

    # Downgrade for missing provenance or missing location.
    if not source_artifact_hash:
        base = downgrade_strength(base)
    if not has_location:
        base = downgrade_strength(base)

    return base


def effective_evidence_strength(
    ev: Evidence, location: str | None = None
) -> EvidenceStrength:
    """Strength as it may be used by QA *now*.

    Re-derives the grade from the stored facts and takes the weaker of that
    and the stored value, so a hand-written record cannot smuggle an E3 past
    the gate without a hash / location / reproducible signal.
    """
    loc = location if location is not None else getattr(ev, "location", None)
    derived = derive_evidence_strength(
        evidence_type=ev.evidence_type,
        producer_agent=ev.producer_agent,
        source_artifact_hash=ev.source_artifact_hash,
        location=loc,
        summary=ev.summary,
        model_version=ev.model_version,
        dynamic=any(m in (ev.evidence_type or "").lower() for m in _DYNAMIC_TYPE_MARKERS),
    )
    return lower_strength(ev.evidence_strength, derived)
