"""Artefact reference returned by tool calls.

A tool produces zero or more artefacts (file dumps, logs, reports).
Each artefact is hash-addressed through the ArtifactStore.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ArtefactRef:
    sha256: str
    kind: str  # "log", "dump", "trace", "binary", "report", "json"
    size: int
    location: str  # human-readable, e.g. "minio://bucket/key" or "fs://path"
    content_type: str | None = None

    def to_dict(self) -> dict:
        return {
            "sha256": self.sha256,
            "kind": self.kind,
            "size": self.size,
            "location": self.location,
            "content_type": self.content_type,
        }
