"""In-memory checkpointer for Phase 0/1.

Production swaps this for a Postgres-backed saver without changing
call sites.
"""

from langgraph.checkpoint.memory import MemorySaver


def build_checkpointer() -> MemorySaver:
    return MemorySaver()
