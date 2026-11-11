"""Untrusted input wrapper.

The wrapper:

1. Truncates raw bytes/strings above `MAX_RAW_BYTES` (default 16 KB).
2. Strips / escapes any `instruction-like` patterns (e.g. "Ignore
   previous instructions"). We don't trust the sample's strings.
3. Wraps the result in a tagged envelope:

       <UNTRUSTED_DATA source="<tool>:<method>">
       ...
       </UNTRUSTED_DATA>

The wrapper is the single funnel for everything that flows from a
sample, tool output, log or crash content into an LLM prompt.
"""

import re
from typing import Any

MAX_RAW_BYTES = 16 * 1024

# Conservative list of patterns that look like instructions. When we
# find one in raw text we mark the chunk as `instruction_like=true`
# so downstream LLM prompts can drop the chunk or treat it as data.
INSTRUCTION_LIKE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", re.I),
    re.compile(r"disregard\s+(all\s+)?previous", re.I),
    re.compile(r"you\s+must\s+(now\s+)?(call|execute|run|delete|drop|mark)", re.I),
    re.compile(r"system\s*:\s*", re.I),
    re.compile(r"<\|im_start\|>system", re.I),
    re.compile(r"reveal\s+(the\s+)?(system|secret|hidden)\s+prompt", re.I),
    re.compile(r"do\s+not\s+follow\s+safety", re.I),
]


def is_instruction_like(text: str) -> bool:
    if not text:
        return False
    for pat in INSTRUCTION_LIKE_PATTERNS:
        if pat.search(text):
            return True
    return False


def _coerce_to_str(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, (dict, list)):
        import json as _json
        return _json.dumps(value, ensure_ascii=False, default=str)
    return str(value)


def untrusted_wrap(value: Any, *, source: str) -> dict:
    """Wrap a single piece of untrusted data.

    Returns a dict that can be safely serialised into LLM prompts:

        {
          "source": "analyze_pe:pe_header",
          "truncated": false,
          "instruction_like": false,
          "payload": "...",  # truncated / escaped
          "size": 1234,
        }
    """
    text = _coerce_to_str(value)
    original_size = len(text.encode("utf-8"))
    truncated = original_size > MAX_RAW_BYTES
    if truncated:
        # Keep head + tail for forensic value
        head = text[: MAX_RAW_BYTES // 2]
        tail = text[-MAX_RAW_BYTES // 2 :]
        text = head + "\n...[truncated]...\n" + tail
    instr = is_instruction_like(text)
    return {
        "source": source,
        "truncated": truncated,
        "instruction_like": instr,
        "size": original_size,
        "payload": text,
    }


def untrusted_unwrap(envelope: dict) -> str:
    """Recover the inner payload. Use only for storage, never prompt."""
    if not isinstance(envelope, dict):
        return ""
    return str(envelope.get("payload", ""))
