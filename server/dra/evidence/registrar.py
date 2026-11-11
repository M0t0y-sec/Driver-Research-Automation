"""Evidence Registrar.

The single point of write for Evidence objects. `QA Auditor` is *not*
allowed to call this directly in production code (see the call graph
in the design doc); it can read but not write.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from ..config import SETTINGS
from ..models.common import EvidenceStrength, IDPrefix, new_id
from ..models.evidence import Evidence
from ..storage.artifact_store import FileSystemArtifactStore
from ..storage.filesystem import EvidenceStore
from .strength import derive_evidence_strength, lower_strength


class EvidenceRegistrar:
    def __init__(
        self,
        store: EvidenceStore | None = None,
        artefact_store: FileSystemArtifactStore | None = None,
    ) -> None:
        self.store = store or EvidenceStore(SETTINGS.evidence_dir)
        self.artefacts = artefact_store or FileSystemArtifactStore(SETTINGS.artefact_root)

    def register(
        self,
        *,
        project_id: str,
        evidence_type: str,
        producer_agent: str,
        target_id: str | None = None,
        source_artifact_hash: str | None = None,
        source_bytes: bytes | None = None,
        environment_snapshot_id: str | None = None,
        tool_version: str | None = None,
        model_version: str | None = None,
        confidence: str = "medium",
        evidence_strength: EvidenceStrength | None = None,
        location: str | None = None,
        dynamic: bool = False,
        reproducible: bool = False,
        related_hypothesis_id: str | None = None,
        related_experiment_id: str | None = None,
        related_crash_id: str | None = None,
        summary: str = "",
        lineage_ids: list[str] | None = None,
    ) -> Evidence:
        """Register one piece of evidence.

        `source_artifact_hash` is required; if not provided, we hash
        `source_bytes` (or the JSON of the summary if neither is set).

        `evidence_strength` is only a *ceiling*: the stored grade is
        derived from facts (`evidence_type`, producer, location, dynamic /
        reproducible signals, provenance) and clamped to the weaker value.
        Callers cannot self-award E3 for a model guess.
        """
        if source_artifact_hash is None:
            if source_bytes is not None:
                source_artifact_hash = self.artefacts.put(source_bytes)
            else:
                source_artifact_hash = hashlib.sha256(
                    json.dumps(summary, sort_keys=True).encode("utf-8")
                ).hexdigest()
        derived = derive_evidence_strength(
            evidence_type=evidence_type,
            producer_agent=producer_agent,
            source_artifact_hash=source_artifact_hash,
            location=location,
            summary=summary,
            model_version=model_version,
            tool_version=tool_version,
            dynamic=dynamic,
            reproducible=reproducible,
            related_crash_id=related_crash_id,
        )
        final_strength = derived if evidence_strength is None else lower_strength(evidence_strength, derived)
        ev = Evidence(
            id=new_id(IDPrefix.EVIDENCE),
            project_id=project_id,
            target_id=target_id,
            evidence_type=evidence_type,
            producer_agent=producer_agent,
            source_artifact_hash=source_artifact_hash,
            environment_snapshot_id=environment_snapshot_id,
            tool_version=tool_version,
            model_version=model_version,
            confidence=confidence,
            evidence_strength=final_strength,
            related_hypothesis_id=related_hypothesis_id,
            related_experiment_id=related_experiment_id,
            related_crash_id=related_crash_id,
            location=location,
            summary=summary,
            lineage_ids=list(lineage_ids or []),
        )
        self.store.add(ev)
        return ev

    def get(self, evidence_id: str) -> Evidence | None:
        return self.store.get(evidence_id)

    def list_for_project(self, project_id: str) -> list[Evidence]:
        return self.store.list(project_id=project_id)

    def update_qa_status(self, evidence_id: str, status: str) -> Evidence:
        ev = self.store.get(evidence_id)
        if ev is None:
            raise KeyError(evidence_id)
        updated = ev.model_copy(update={"qa_status": status})
        self.store.add(updated)
        return updated
