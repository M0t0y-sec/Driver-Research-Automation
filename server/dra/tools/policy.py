"""Policy engine: maps (tool, parameters) -> PolicyDecision.

Decisions are: ALLOW, NEEDS_APPROVAL, BLOCKED. The default policy is
risk-level based: LOW/MEDIUM allow, HIGH needs approval, EXTREME
needs dual approval. Per-tool overrides can be added without touching
this file.
"""

from dataclasses import dataclass
from enum import Enum

from ..models.common import RiskLevel


class PolicyDecision(str, Enum):
    ALLOW = "allow"
    NEEDS_APPROVAL = "needs_approval"
    BLOCKED = "blocked"


@dataclass
class PolicyContext:
    project_authorized: bool = False
    authorization_ref: str | None = None
    variant_generation: str | None = None  # name of variant policy row


class PolicyEngine:
    """Risk-level policy with tool-specific overrides.

    Overrides map `tool_name` -> RiskLevel. The gateway first consults
    the override, then the tool's declared risk.
    """

    def __init__(self) -> None:
        self._overrides: dict[str, RiskLevel] = {}

    def override(self, tool_name: str, risk: RiskLevel) -> None:
        self._overrides[tool_name] = risk

    def decide(
        self, tool: str, declared_risk: RiskLevel, ctx: PolicyContext
    ) -> PolicyDecision:
        effective = self._overrides.get(tool, declared_risk)
        # High risk without authorization is always blocked.
        if effective in {RiskLevel.HIGH, RiskLevel.EXTREME} and not ctx.project_authorized:
            return PolicyDecision.BLOCKED
        if effective == RiskLevel.LOW or effective == RiskLevel.MEDIUM:
            return PolicyDecision.ALLOW
        if effective == RiskLevel.HIGH:
            return PolicyDecision.NEEDS_APPROVAL
        if effective == RiskLevel.EXTREME:
            return PolicyDecision.NEEDS_APPROVAL
        return PolicyDecision.ALLOW
