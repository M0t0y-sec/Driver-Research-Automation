"""Research Lineage builder.

Builds the canonical chain:

    target -> observation -> hypothesis -> experiment -> execution
           -> crash -> root_cause -> impact -> exploitability
           -> evidence -> finding -> qa_review

Phase 0/1 builds the chain as a list of `{id, type, label, ref}`
records, plus a single `ids` list. Phase 2+ will materialise this
into the dedicated `lineage` table in Postgres.
"""

from dataclasses import dataclass, field

from ..models.evidence import Evidence
from ..models.finding import Finding


@dataclass
class LineageNode:
    id: str
    type: str
    label: str = ""

    def to_dict(self) -> dict:
        return {"id": self.id, "type": self.type, "label": self.label}


class LineageBuilder:
    def __init__(self) -> None:
        self._nodes: list[LineageNode] = []
        self._ids: list[str] = []

    def add(self, obj_id: str, type_: str, label: str = "") -> "LineageBuilder":
        if obj_id in self._ids:
            return self
        self._ids.append(obj_id)
        self._nodes.append(LineageNode(id=obj_id, type=type_, label=label))
        return self

    def extend_ids(self, ids: list[str]) -> "LineageBuilder":
        for i in ids or []:
            if i and i not in self._ids:
                self._ids.append(i)
        return self

    def build(self) -> dict:
        return {
            "ids": list(self._ids),
            "nodes": [n.to_dict() for n in self._nodes],
        }

    @staticmethod
    def from_finding(finding: Finding, evidences: list[Evidence]) -> dict:
        b = LineageBuilder()
        if finding.target_id:
            b.add(finding.target_id, "target", "target")
        for eid in finding.evidence_ids:
            b.add(eid, "evidence", "evidence")
        for cid in finding.crash_ids:
            b.add(cid, "crash", "crash")
        for xid in finding.experiment_ids:
            b.add(xid, "experiment", "experiment")
        for eid in finding.execution_ids:
            b.add(eid, "execution", "execution")
        for tid in finding.telemetry_ids:
            b.add(tid, "telemetry", "telemetry")
        if finding.qa_review_id:
            b.add(finding.qa_review_id, "qa_review", "qa_review")
        b.add(finding.id, "finding", finding.title or "finding")
        return b.build()
