"""Variant Generation Policy.

Controls what kinds of sample variants the platform may produce, and
what the Detection Evaluator may emit. See integration plan section
7.10.3.
"""

from dataclasses import dataclass
from enum import Enum


class VariantAction(str, Enum):
    ALLOW = "allow"
    POLICY_CHECK = "policy_check"
    HIGH_APPROVAL = "high_approval"
    DUAL_APPROVAL = "dual_approval"
    DENY = "deny"
    REDACT = "redact"


@dataclass(frozen=True)
class VariantPolicy:
    """One row in the variant policy table.

    `action` is what the system is permitted to do with this kind of
    output. `requires_pair` indicates the action needs a second human
    approver (EXTREME).
    """

    name: str
    action: VariantAction
    description: str = ""


# Static policy table per the integrated design (see plan §7.10.3).
_TABLE: list[VariantPolicy] = [
    VariantPolicy("generate_behavior_summary", VariantAction.ALLOW,
                  "Generate behavior summary; allowed by default."),
    VariantPolicy("generate_detection_gap_report", VariantAction.ALLOW,
                  "Generate detection gap report; allowed by default."),
    VariantPolicy("low_risk_variant", VariantAction.POLICY_CHECK,
                  "Generate low-risk experimental variant; subject to policy check."),
    VariantPolicy("evasive_variant", VariantAction.HIGH_APPROVAL,
                  "Variant that may evade detection; requires HIGH human approval."),
    VariantPolicy("full_bypass_sample", VariantAction.DUAL_APPROVAL,
                  "Full bypass sample; dual-approval + audit."),
    VariantPolicy("publish_bypass_steps", VariantAction.REDACT,
                  "Publish replicable bypass steps; redact by default."),
    VariantPolicy("export_attack_payload", VariantAction.DENY,
                  "Export attack payload; denied by default."),
]


def variant_policy_for(name: str) -> VariantPolicy:
    for row in _TABLE:
        if row.name == name:
            return row
    return VariantPolicy(name=name, action=VariantAction.POLICY_CHECK,
                         description="Unknown variant; default to policy check.")
