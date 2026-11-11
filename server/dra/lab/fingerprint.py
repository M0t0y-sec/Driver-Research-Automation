"""Experiment fingerprint.

Design doc section 12.4 requires every experiment to be identified by the
things that can change its outcome::

    sha256(target) + hypothesis_id + sha256(plan) + snapshot
    + tool_versions + sha256(input)

Two runs with the same payload are the *same experiment* (deduplicate
them); any change to the target binary, hypothesis, plan, snapshot, tool
versions or input bytes produces a different fingerprint.

The function accepts either raw bytes/paths or precomputed hashes.  Paths
are read and hashed; a path that does not exist raises instead of being
silently treated as a string.
"""

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

_SHA256_HEX_LENGTH = 64
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def sha256_file(path: str | Path, *, chunk_size: int = 1024 * 1024) -> str:
    """sha256 of a file, streamed so large drivers do not fill memory."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _normalize_hash(value: str, label: str) -> str:
    text = value.strip()
    if text.lower().startswith("sha256:"):
        text = text[len("sha256:"):]
    text = text.lower()
    if len(text) != _SHA256_HEX_LENGTH or any(c not in "0123456789abcdef" for c in text):
        raise ValueError(
            f"{label} must be a 64-character hex sha256 digest (optionally "
            f"prefixed with 'sha256:'), got {value!r}"
        )
    return text


def _hash_target(target: Any, target_hash: str | None) -> str:
    if target is not None and target_hash is not None:
        computed = _hash_target(target, None)
        supplied = _normalize_hash(target_hash, "target_hash")
        if computed != supplied:
            raise ValueError(
                "target and target_hash disagree: the supplied hash does not "
                "match the bytes at the given path"
            )
        return computed
    if target_hash is not None:
        return _normalize_hash(target_hash, "target_hash")
    if target is None:
        raise ValueError(
            "experiment_fingerprint requires target (bytes or path) or "
            "target_hash"
        )
    if isinstance(target, (bytes, bytearray, memoryview)):
        return _sha256_bytes(bytes(target))
    if isinstance(target, (str, Path)):
        path = Path(target)
        if not path.is_file():
            raise FileNotFoundError(
                f"target {str(target)!r} is not a file; pass target_hash for "
                "an already-hashed target"
            )
        return sha256_file(path)
    raise TypeError(
        "target must be bytes, a filesystem path, or None with target_hash"
    )


def _hash_plan(plan: Any) -> str:
    if isinstance(plan, Mapping) or isinstance(plan, (list, tuple)):
        material = json.dumps(
            plan,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        ).encode("utf-8")
    elif isinstance(plan, bytes):
        material = plan
    elif isinstance(plan, str):
        material = plan.encode("utf-8")
    elif plan is None:
        material = b"{}"
    else:
        raise TypeError("plan must be a dict/list, str, bytes, or None")
    return _sha256_bytes(material)


def _hash_input(input_data: Any, input_hash: str | None) -> str:
    if input_data is not None and input_hash is not None:
        computed = _hash_input(input_data, None)
        supplied = _normalize_hash(input_hash, "input_hash")
        if computed != supplied:
            raise ValueError(
                "input_data and input_hash disagree: the supplied hash does "
                "not match the input bytes"
            )
        return computed
    if input_hash is not None:
        return _normalize_hash(input_hash, "input_hash")
    if input_data is None:
        return _EMPTY_SHA256
    if isinstance(input_data, (bytes, bytearray, memoryview)):
        return _sha256_bytes(bytes(input_data))
    if isinstance(input_data, str):
        return _sha256_bytes(input_data.encode("utf-8"))
    raise TypeError("input_data must be bytes, str, or None")


def experiment_fingerprint(
    *,
    hypothesis_id: str,
    plan: Any,
    target: Any = None,
    target_hash: str | None = None,
    snapshot: str | None = None,
    tool_versions: Mapping[str, str] | None = None,
    input_data: Any = None,
    input_hash: str | None = None,
) -> str:
    """Return the stable sha256 experiment fingerprint.

    Parameters
    ----------
    hypothesis_id:
        Non-empty hypothesis identifier the experiment tests.
    plan:
        Experiment plan (dict/list canonicalised as sorted JSON, or raw
        str/bytes).
    target:
        Driver bytes or a path to the driver; alternatively pass
        ``target_hash``.
    snapshot:
        Golden snapshot / VM fingerprint the experiment runs on.
    tool_versions:
        ``{tool_name: version}``; order does not matter.
    input_data / input_hash:
        Test-case bytes, or their precomputed sha256.

    Returns
    -------
    str
        64-character lowercase hex digest.
    """
    if not isinstance(hypothesis_id, str) or not hypothesis_id.strip():
        raise ValueError("hypothesis_id must be a non-empty string")
    if snapshot is not None and not isinstance(snapshot, str):
        raise TypeError("snapshot must be a string or None")

    versions: dict[str, str] = {}
    if tool_versions is not None:
        if not isinstance(tool_versions, Mapping):
            raise TypeError("tool_versions must be a mapping of name -> version")
        for name, version in tool_versions.items():
            if not isinstance(name, str) or not name:
                raise ValueError("tool_versions keys must be non-empty strings")
            versions[name] = "" if version is None else str(version)

    payload = {
        "target_sha256": _hash_target(target, target_hash),
        "hypothesis_id": hypothesis_id.strip(),
        "plan_sha256": _hash_plan(plan),
        "snapshot": snapshot or "",
        "tool_versions": dict(sorted(versions.items())),
        "input_sha256": _hash_input(input_data, input_hash),
    }
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return _sha256_bytes(canonical.encode("utf-8"))
