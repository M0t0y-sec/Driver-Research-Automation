"""Concrete tool implementations.

All tools are registered on import via `@tool(...)`. They are
intentionally lightweight in Phase 0/1: enough to produce real
observations without a real `pefile` or Ghidra. The same registration
contract will host the real tools in Phase 2+.

Every tool returns a dict with two top-level shapes:

  { ..., "artefacts": [ArtefactRef, ...] }

or:

  { ..., "report": <dict>, "raw_log": b"..." }
"""
