"""Shared prompt helpers."""
from __future__ import annotations

from typing import Any

from ..untrusted.wrapper import untrusted_wrap


def render_untrusted(value: Any, *, source: str) -> str:
    """Render *value* inside an ``<UNTRUSTED_DATA>`` envelope.

    The payload is truncated/escaped by
    :func:`dra.untrusted.wrapper.untrusted_wrap`, and the envelope carries
    the wrapper's ``instruction_like`` / ``truncated`` flags so the model
    can see that the content was suspicious or clipped.
    """
    envelope = untrusted_wrap(value, source=source)
    attributes = [f'source="{source}"']
    if envelope.get("instruction_like"):
        attributes.append('instruction_like="true"')
    if envelope.get("truncated"):
        attributes.append('truncated="true"')
    header = "<UNTRUSTED_DATA " + " ".join(attributes) + ">"
    return f"{header}\n{envelope['payload']}\n</UNTRUSTED_DATA>"
