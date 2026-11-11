"""Agent operations layer.

The graph nodes (`dra.agents.*`) call into this module instead of
touching storage / LLM / Tool Gateway directly. This is the single
place that translates "the agent wants X" into "fetch / put / call".

In Phase 0/1, every function here is a thin pass-through. Phase 2+
will add schema validation, retries, and metrics.
"""

from dataclasses import dataclass

from ..compliance.authz import AuthzService
from ..evidence.registrar import EvidenceRegistrar
from ..llm.base import LLMMessage
from ..llm.router import LLMRouter
from ..qa.auditor import QAAuditor
from ..storage.filesystem import (
    AttackSurfaceStore,
    CrashStore,
    EvidenceStore,
    ExploitabilityStore,
    FindingStore,
    HypothesisStore,
    ImpactStore,
    ObservationStore,
    ProjectStore,
    QAReviewStore,
    ResearchStore,
    RootCauseStore,
)
from ..tools.gateway import ToolGateway


@dataclass
class AgentOps:
    """Bag of dependencies passed into each node.

    Every node function in `dra.agents` should take an `AgentOps` and
    a `ResearchState`, and return a `dict` (LangGraph state update).
    """
    llm: LLMRouter
    tools: ToolGateway
    evidence: EvidenceRegistrar
    qa: QAAuditor
    authz: AuthzService
    projects: ProjectStore
    research: ResearchStore
    observations: ObservationStore
    attack_surfaces: AttackSurfaceStore
    hypotheses: HypothesisStore
    findings: FindingStore
    evidence_store: EvidenceStore
    qa_reviews: QAReviewStore
    crashes: CrashStore
    root_causes: RootCauseStore
    impacts: ImpactStore
    exploitabilities: ExploitabilityStore


def build_ops(
    *,
    llm: LLMRouter | None = None,
    tools: ToolGateway | None = None,
    authz: AuthzService | None = None,
) -> AgentOps:
    from ..llm.factory import build_llm_router

    llm = llm or build_llm_router()
    tools = tools or ToolGateway()
    authz = authz or AuthzService()
    from ..config import SETTINGS

    return AgentOps(
        llm=llm,
        tools=tools,
        evidence=EvidenceRegistrar(),
        qa=QAAuditor(llm),
        authz=authz,
        projects=ProjectStore(SETTINGS.projects_dir),
        research=ResearchStore(SETTINGS.research_dir),
        observations=ObservationStore(SETTINGS.data_dir / "observations"),
        attack_surfaces=AttackSurfaceStore(SETTINGS.data_dir / "attack_surfaces"),
        hypotheses=HypothesisStore(SETTINGS.data_dir / "hypotheses"),
        findings=FindingStore(SETTINGS.findings_dir),
        evidence_store=EvidenceStore(SETTINGS.evidence_dir),
        qa_reviews=QAReviewStore(SETTINGS.data_dir / "qa_reviews"),
        crashes=CrashStore(SETTINGS.data_dir / "crashes"),
        root_causes=RootCauseStore(SETTINGS.data_dir / "root_causes"),
        impacts=ImpactStore(SETTINGS.data_dir / "impacts"),
        exploitabilities=ExploitabilityStore(SETTINGS.data_dir / "exploitability"),
    )


def make_user_msg(content: str) -> LLMMessage:
    return LLMMessage(role="user", content=content)


def make_system_msg(content: str) -> LLMMessage:
    return LLMMessage(role="system", content=content)
