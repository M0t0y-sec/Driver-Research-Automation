"""Untrusted Input Handling.

Wraps any value that originated from a sample, tool output, log, dump
or telemetry channel into a tagged envelope before it is shown to the
LLM. See integration plan section 10.
"""
from .wrapper import (
    untrusted_wrap,
    untrusted_unwrap,
    MAX_RAW_BYTES,
    INSTRUCTION_LIKE_PATTERNS,
    is_instruction_like,
)

__all__ = [
    "untrusted_wrap",
    "untrusted_unwrap",
    "MAX_RAW_BYTES",
    "INSTRUCTION_LIKE_PATTERNS",
    "is_instruction_like",
]
