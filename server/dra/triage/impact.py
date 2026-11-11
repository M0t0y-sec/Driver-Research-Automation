"""Security-impact assessment for a classified crash.

Impact is derived from the defect category, the faulting component's
ownership, and the threat-model actor linked to the crash's hypothesis.
It is deliberately conservative:

* a third-party or OS-component fault has **no** target-driver privilege
  boundary crossing, even when the target driver called into it;
* confidentiality/integrity impact is only claimed when the recorded dump
  shows attacker-controlled fault state; a crash alone is availability
  impact;
* privilege and attack vector come from the hypothesis' threat actor.  If
  the crash is not linked to a hypothesis, both are ``unknown`` rather
  than an optimistic "unprivileged local user".
"""
from __future__ import annotations

from dataclasses import dataclass

from ..compliance.threat_model import attack_actor
from ..models.hypothesis import Hypothesis
from .classify import MEMORY_CORRUPTION_CATEGORIES, DefectClassification
from .exploitability import ExploitabilityResult

#: Threat actor -> (required privilege, attack vector, crosses user/kernel
#: boundary when it reaches a kernel defect).
_ACTOR_PROFILE: dict[str, tuple[str, str, bool]] = {
    "unprivileged_local_user": ("unprivileged", "local", True),
    "sandboxed_process": ("unprivileged", "local", True),
    "service_account": ("service", "local", True),
    "local_administrator": ("administrator", "local", True),
    "remote_attacker": ("unprivileged", "network", True),
    "physical": ("physical", "physical", True),
    "unknown": ("unknown", "unknown", False),
}


@dataclass(frozen=True)
class ImpactResult:
    impact_type: str
    privilege_boundary_crossed: bool
    confidentiality: str
    integrity: str
    availability: str
    attack_vector: str
    required_privilege: str
    user_interaction: str
    confidence: str
    notes: str


def _actor_profile(hypothesis: Hypothesis | None) -> tuple[str, str, str, bool]:
    if hypothesis is None:
        return "unknown", "unknown", "unknown", False
    actor = attack_actor(hypothesis.related_attack_actor)
    privilege, vector, boundary = _ACTOR_PROFILE.get(
        actor, ("unknown", "unknown", False)
    )
    return actor, privilege, vector, boundary


def assess_impact(
    classification: DefectClassification,
    exploitability: ExploitabilityResult,
    *,
    hypothesis: Hypothesis | None = None,
) -> ImpactResult:
    """Build a structured impact judgement."""
    actor, privilege, vector, boundary_possible = _actor_profile(hypothesis)
    attribution = classification.attribution
    category = classification.category
    controllability = exploitability.controllability

    notes: list[str] = []
    if hypothesis is None:
        notes.append(
            "No hypothesis is linked to this crash; required privilege and attack "
            "vector are recorded as unknown rather than assumed."
        )
    else:
        notes.append(
            "Privilege and attack vector are derived from the linked hypothesis' "
            f"threat actor ({actor})."
        )

    if attribution == "third_party_driver":
        return ImpactResult(
            impact_type="third_party_component_failure",
            privilege_boundary_crossed=False,
            confidentiality="none",
            integrity="none",
            availability="high",
            attack_vector=vector,
            required_privilege=privilege,
            user_interaction="none",
            confidence="high" if classification.confidence == "high" else "medium",
            notes=(
                "The faulting component is a third-party module, not the target "
                "driver. A bugcheck is an availability event for the machine, but "
                "the target driver's security boundary is not crossed. "
                + " ".join(notes)
            ),
        )

    if attribution == "os_component":
        return ImpactResult(
            impact_type="os_component_failure",
            privilege_boundary_crossed=False,
            confidentiality="none",
            integrity="none",
            availability="high",
            attack_vector=vector,
            required_privilege=privilege,
            user_interaction="none",
            confidence="medium",
            notes=(
                "The faulting component is an OS routine and no target-driver "
                "caller is visible; this is not attributable to the target. "
                + " ".join(notes)
            ),
        )

    if attribution == "environment":
        return ImpactResult(
            impact_type="environment_failure",
            privilege_boundary_crossed=False,
            confidentiality="none",
            integrity="none",
            availability="high",
            attack_vector=vector,
            required_privilege=privilege,
            user_interaction="none",
            confidence="medium",
            notes=(
                "The bugcheck is hardware/environment class; it is not a target "
                "driver vulnerability on the recorded evidence. " + " ".join(notes)
            ),
        )

    if attribution == "unknown":
        return ImpactResult(
            impact_type="unknown",
            privilege_boundary_crossed=False,
            confidentiality="none",
            integrity="none",
            availability="high",
            attack_vector=vector,
            required_privilege=privilege,
            user_interaction="none",
            confidence="low",
            notes=(
                "The dump does not establish which component faulted, so no "
                "target-driver security impact can be claimed. " + " ".join(notes)
            ),
        )

    # -- target driver ---------------------------------------------------
    if category == "null_deref":
        notes.append(
            "A null-page dereference is normally a denial-of-service defect; it "
            "does not by itself establish a privilege boundary crossing."
        )
        return ImpactResult(
            impact_type="denial_of_service",
            privilege_boundary_crossed=False,
            confidentiality="none",
            integrity="none",
            availability="high",
            attack_vector=vector,
            required_privilege=privilege,
            user_interaction="none",
            confidence=classification.confidence,
            notes=" ".join(notes),
        )

    if category in MEMORY_CORRUPTION_CATEGORIES or category == "control_flow":
        impact_type = (
            "potential_privilege_escalation"
            if category == "control_flow" or controllability in {"full", "partial"}
            else "kernel_memory_corruption"
        )
        if controllability == "full":
            confidentiality, integrity = "high", "high"
            notes.append(
                "The dump shows attacker-controlled fault state consistent with a "
                "kernel read/write primitive; confidentiality and integrity impact "
                "are rated high as a potential, not as a demonstrated exploit."
            )
        elif controllability == "partial":
            confidentiality, integrity = "low", "low"
            notes.append(
                "Attacker influence over the fault is partial; confidentiality and "
                "integrity impact are rated low."
            )
        else:
            confidentiality, integrity = "none", "low"
            notes.append(
                "Attacker control of the fault is not established; only generic "
                "kernel memory-corruption impact is claimed."
            )
        return ImpactResult(
            impact_type=impact_type,
            privilege_boundary_crossed=boundary_possible,
            confidentiality=confidentiality,
            integrity=integrity,
            availability="high",
            attack_vector=vector,
            required_privilege=privilege,
            user_interaction="none",
            confidence=classification.confidence,
            notes=" ".join(notes),
        )

    if category in {"race", "toctou"}:
        return ImpactResult(
            impact_type="race_condition",
            privilege_boundary_crossed=boundary_possible,
            confidentiality="none",
            integrity="low",
            availability="high",
            attack_vector=vector,
            required_privilege=privilege,
            user_interaction="none",
            confidence=classification.confidence,
            notes=(
                "Race-condition defects are rated for integrity/availability impact; "
                "no confidentiality impact is claimed without evidence. "
                + " ".join(notes)
            ),
        )

    if category == "uninit_memory":
        return ImpactResult(
            impact_type="information_disclosure",
            privilege_boundary_crossed=boundary_possible,
            confidentiality="low",
            integrity="none",
            availability="high",
            attack_vector=vector,
            required_privilege=privilege,
            user_interaction="none",
            confidence=classification.confidence,
            notes=(
                "Uninitialized memory can disclose kernel data only if it reaches a "
                "user-visible output; that path is not established by this dump. "
                + " ".join(notes)
            ),
        )

    if category == "input_validation":
        return ImpactResult(
            impact_type="input_validation",
            privilege_boundary_crossed=boundary_possible,
            confidentiality="none",
            integrity="none",
            availability="high",
            attack_vector=vector,
            required_privilege=privilege,
            user_interaction="none",
            confidence=classification.confidence,
            notes=(
                "Input-validation defects are rated for availability impact unless "
                "the dump shows memory corruption. " + " ".join(notes)
            ),
        )

    if category == "logic":
        return ImpactResult(
            impact_type="logic_defect",
            privilege_boundary_crossed=boundary_possible,
            confidentiality="none",
            integrity="low",
            availability="high",
            attack_vector=vector,
            required_privilege=privilege,
            user_interaction="none",
            confidence=classification.confidence,
            notes=(
                "Logic defects are rated for their observed effect only; no "
                "memory-corruption or information-disclosure impact is claimed. "
                + " ".join(notes)
            ),
        )

    return ImpactResult(
        impact_type="unknown",
        privilege_boundary_crossed=False,
        confidentiality="none",
        integrity="none",
        availability="high",
        attack_vector=vector,
        required_privilege=privilege,
        user_interaction="none",
        confidence="low",
        notes=(
            f"Defect category {category!r} has no impact mapping; only the "
            "observed system crash (availability) is claimed. " + " ".join(notes)
        ),
    )
