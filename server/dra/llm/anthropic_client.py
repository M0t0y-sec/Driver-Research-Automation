"""Anthropic (Claude) implementation of the LLMClient interface.

Design notes
------------
* **Tier -> model.** ``dra.llm.router.ROUTING_TABLE`` already assigns a
  :class:`~dra.llm.base.ModelTier` to every task. The ``LLMClient``
  protocol only receives ``task`` and ``temperature``, so this client
  looks the tier up again and maps it to a concrete model id
  (``small`` -> Haiku, ``mid`` -> Sonnet, ``large`` -> Opus by default;
  all overridable through ``DRA_ANTHROPIC_MODEL_*``).
* **Temperature.** The routing table's per-task values are always
  recorded on ``LLMResponse.temperature``. Messages API version
  ``2026-10-21`` (the default of SDK 2.x) rejects
  ``temperature``/``top_p``/``top_k`` with a 400, so the value is only
  transmitted when the operator explicitly pins an older API version via
  ``DRA_ANTHROPIC_API_VERSION`` (legacy escape hatch for deployments
  that still need sampling control).
* **Output trust.** Every response is parsed as JSON and validated
  against the task's Pydantic contract (or the caller-supplied JSON
  Schema). One repair call is attempted; if that also fails,
  :class:`~dra.llm.errors.LLMOutputError` is raised. No defaults are
  invented for a failed call.
* **Structured output.** When a schema is available it is sent through
  ``output_config.format`` so the model is constrained at generation
  time. Unsupported JSON Schema keywords are stripped for the wire but
  remain client-side validation rules in Pydantic.
"""

import json
import logging
import re
import time
from collections.abc import Mapping
from typing import Any

import anthropic
import jsonschema
from pydantic import BaseModel
from pydantic import ValidationError as PydanticValidationError

from .base import LLMMessage, LLMResponse, LLMTask, ModelTier
from .errors import (
    LLMConfigurationError,
    LLMOutputError,
    LLMProviderError,
    LLMRefusalError,
)
from .router import ROUTING_TABLE, Route
from .schemas import contract_for

logger = logging.getLogger("dra.llm.anthropic")

# Current-generation model ids. Model names are part of the public
# configuration surface: override per tier through DRA_ANTHROPIC_MODEL_*.
DEFAULT_MODELS: dict[ModelTier, str] = {
    ModelTier.SMALL: "claude-haiku-5-5",   # parse / classify / JSON repair
    ModelTier.MID: "claude-sonnet-5-5",    # summaries, reports, detection gaps
    ModelTier.LARGE: "claude-opus-5-5",    # hypothesis / cross-fn / QA reasoning
}

# Messages API version that removed sampling parameters. Only versions
# older than this accept `temperature`.
_SAMPLING_REMOVED_IN = "2026-10-21"
_API_VERSION_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

JSON_ONLY_INSTRUCTION = (
    "Return exactly one JSON object and nothing else - no prose, no "
    "Markdown fences, no commentary."
)

REPAIR_INSTRUCTION = (
    "Your previous answer was rejected: {error}\n"
    "Return ONLY a corrected JSON object that satisfies the required schema."
)

# JSON Schema keywords the structured-outputs implementation rejects.
# The Python SDK strips these itself only on the `.parse()` path; we use
# `messages.create()` with a raw schema, so strip them here. Client-side
# validation still enforces the original (unstripped) schema.
_UNSUPPORTED_SCHEMA_KEYWORDS = frozenset(
    {
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "multipleOf",
        "minLength",
        "maxLength",
        "pattern",
        "minItems",
        "maxItems",
        "uniqueItems",
        "default",
        "examples",
    }
)

_FENCED_JSON_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.S | re.I)


def sanitize_json_schema(schema: dict) -> dict:
    """Return a copy of ``schema`` restricted to wire-supported keywords.

    Structured outputs require ``additionalProperties: false`` on every
    object and reject numeric/string/array constraint keywords. Nested
    object definitions (``$defs``) are sanitised too.
    """

    def walk(node: Any) -> Any:
        if isinstance(node, dict):
            cleaned = {
                key: walk(value)
                for key, value in node.items()
                if key not in _UNSUPPORTED_SCHEMA_KEYWORDS
            }
            declared_type = cleaned.get("type")
            is_object = declared_type == "object" or (
                isinstance(declared_type, list) and "object" in declared_type
            )
            if is_object or "properties" in cleaned:
                # The API only accepts the boolean false, never a schema.
                cleaned["additionalProperties"] = False
            return cleaned
        if isinstance(node, list):
            return [walk(item) for item in node]
        return node

    return walk(schema)


def extract_json_object(text: str) -> dict | None:
    """Extract the first JSON object from model text.

    Handles bare JSON, fenced ```json blocks, and JSON surrounded by
    explanatory prose. Returns ``None`` when no object can be parsed.
    """
    if not text:
        return None
    candidates: list[str] = []
    fenced = _FENCED_JSON_RE.search(text)
    if fenced:
        candidates.append(fenced.group(1).strip())
    candidates.append(text.strip())
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        candidates.append(text[start : end + 1])
    for candidate in candidates:
        if not candidate:
            continue
        try:
            value = json.loads(candidate)
        except (json.JSONDecodeError, TypeError):
            continue
        if isinstance(value, dict):
            return value
    return None


def _split_messages(messages: list[LLMMessage]) -> tuple[str, list[dict[str, str]]]:
    """Separate system text from the user/assistant turn list.

    The Messages API takes the system prompt as a top-level argument
    rather than as a message role.
    """
    system_parts: list[str] = []
    api_messages: list[dict[str, str]] = []
    for message in messages:
        if message.role == "system":
            system_parts.append(message.content)
        elif message.role in ("user", "assistant"):
            api_messages.append({"role": message.role, "content": message.content})
        else:
            raise LLMConfigurationError(
                f"unsupported message role {message.role!r}; expected system/user/assistant"
            )
    if not api_messages:
        raise LLMConfigurationError(
            "AnthropicLLMClient requires at least one user or assistant message"
        )
    if api_messages[0]["role"] != "user":
        raise LLMConfigurationError(
            "the first non-system message must have role 'user'"
        )
    return "\n\n".join(part for part in system_parts if part).strip(), api_messages


def _text_from_response(response: Any) -> str:
    parts: list[str] = []
    for block in getattr(response, "content", None) or []:
        if getattr(block, "type", None) == "text":
            parts.append(getattr(block, "text", "") or "")
    return "\n".join(parts)


def _format_pydantic_error(exc: PydanticValidationError) -> str:
    details = []
    for error in exc.errors()[:5]:
        location = ".".join(str(part) for part in error.get("loc", ())) or "<root>"
        details.append(f"{location}: {error.get('msg', 'invalid value')}")
    return "; ".join(details)


class AnthropicLLMClient:
    """Real-model implementation of :class:`dra.llm.base.LLMClient`.

    The call is synchronous to match the existing client protocol; the
    graph nodes already treat LLM calls as blocking points.
    """

    name = "anthropic"

    def __init__(
        self,
        *,
        api_key: str | None = None,
        models: Mapping[ModelTier, str] | None = None,
        max_tokens: int = 16000,
        timeout: float = 300.0,
        max_retries: int = 2,
        api_version: str | None = None,
        client: Any | None = None,
    ) -> None:
        self._models: dict[ModelTier, str] = dict(DEFAULT_MODELS)
        if models:
            self._models.update(models)
        self._max_tokens = int(max_tokens)
        self._api_version = api_version or None
        self._send_temperature = bool(
            self._api_version
            and _API_VERSION_RE.match(self._api_version)
            and self._api_version < _SAMPLING_REMOVED_IN  # ISO dates sort lexicographically
        )

        if client is not None:
            # Test / DI seam: a pre-built client (or compatible fake).
            self._client = client
        else:
            if not api_key:
                raise LLMConfigurationError(
                    "AnthropicLLMClient requires an API key "
                    "(DRA_ANTHROPIC_API_KEY or ANTHROPIC_API_KEY)"
                )
            options: dict[str, Any] = {
                "api_key": api_key,
                "timeout": timeout,
                "max_retries": max_retries,
            }
            if self._api_version:
                options["default_headers"] = {"anthropic-version": self._api_version}
            self._client = anthropic.Anthropic(**options)

        if self._send_temperature:
            logger.info(
                "Anthropic client ready (api_version=%s): per-task temperature is sent.",
                self._api_version,
            )
        else:
            logger.info(
                "Anthropic client ready (api_version=%s): routing temperatures are recorded "
                "on LLMResponse but not sent - this API version rejects sampling parameters.",
                self._api_version or "sdk-default",
            )

    # --- LLMClient interface -------------------------------------------

    def complete(
        self,
        messages: list[LLMMessage],
        *,
        task: LLMTask,
        response_schema: dict | None = None,
        temperature: float | None = None,
    ) -> LLMResponse:
        if task is LLMTask.EMBEDDING:
            raise LLMConfigurationError(
                "the Anthropic Messages API has no embedding endpoint; "
                "route LLMTask.EMBEDDING to a dedicated embedding provider"
            )

        started = time.perf_counter()
        route: Route = ROUTING_TABLE.get(task) or Route(ModelTier.MID, 0.2)
        routed_temperature = (
            float(temperature) if temperature is not None else float(route.temperature)
        )
        system_text, api_messages = _split_messages(messages)

        # A caller-supplied schema wins over the built-in contract.
        contract = contract_for(task) if response_schema is None else None
        schema = (
            response_schema
            if response_schema is not None
            else (contract.model_json_schema() if contract is not None else None)
        )

        model = self._models[route.tier]
        response, text = self._call(
            task=task,
            model=model,
            temperature=routed_temperature,
            system_text=system_text,
            messages=api_messages,
            schema=schema,
        )
        usage = _usage_dict(response, attempts=1)
        data, error = _parse_and_validate(
            text, response_schema=response_schema, contract=contract
        )

        attempts = 1
        if error is not None:
            logger.warning(
                "LLM output rejected (task=%s model=%s): %s - attempting one repair",
                task.value,
                model,
                error,
            )
            repair_route = ROUTING_TABLE.get(LLMTask.JSON_REPAIR) or Route(ModelTier.SMALL, 0.0)
            repair_messages = list(api_messages) + [
                {
                    "role": "assistant",
                    "content": text if text.strip() else "(empty response)",
                },
                {"role": "user", "content": REPAIR_INSTRUCTION.format(error=error)},
            ]
            repair_response, repair_text = self._call(
                task=LLMTask.JSON_REPAIR,
                model=self._models[repair_route.tier],
                temperature=float(repair_route.temperature),
                system_text=system_text,
                messages=repair_messages,
                schema=schema,
            )
            attempts = 2
            usage = _merge_usage(usage, _usage_dict(repair_response, attempts=1))
            response, text = repair_response, repair_text
            data, error = _parse_and_validate(
                text, response_schema=response_schema, contract=contract
            )
            if error is not None:
                raise LLMOutputError(
                    f"LLM response for task {task.value} was invalid after one "
                    f"repair attempt: {error}",
                    raw_text=text,
                    schema_error=error,
                )

        if data is None:  # defensive: unreachable while the checks above hold
            raise LLMOutputError(
                f"LLM response for task {task.value} could not be parsed",
                raw_text=text,
            )
        latency_ms = round((time.perf_counter() - started) * 1000.0, 3)
        chosen_model = getattr(response, "model", None) or model
        usage["attempts"] = attempts
        logger.info(
            "LLM call task=%s model=%s tier=%s latency_ms=%.1f tokens_in=%d tokens_out=%d attempts=%d",
            task.value,
            chosen_model,
            route.tier.value,
            latency_ms,
            usage.get("input_tokens", 0),
            usage.get("output_tokens", 0),
            attempts,
        )
        return LLMResponse(
            content=text,
            structured=data,
            model=chosen_model,
            temperature=routed_temperature,
            usage=usage,
            raw=response,
            latency_ms=latency_ms,
        )

    # --- internals ------------------------------------------------------

    def _call(
        self,
        *,
        task: LLMTask,
        model: str,
        temperature: float,
        system_text: str,
        messages: list[dict[str, str]],
        schema: dict | None,
    ) -> tuple[Any, str]:
        request = self._build_request(
            model=model,
            temperature=temperature,
            system_text=system_text,
            messages=messages,
            schema=schema,
        )
        try:
            response = self._client.messages.create(**request)
        except anthropic.APIError as exc:
            raise LLMProviderError(
                f"Anthropic request failed for task {task.value} "
                f"({type(exc).__name__}): {exc}"
            ) from exc

        stop_reason = getattr(response, "stop_reason", None)
        if stop_reason == "refusal":
            details = getattr(response, "stop_details", None)
            category = getattr(details, "category", None) if details else None
            raise LLMRefusalError(
                f"model refused task {task.value} (category={category})"
            )
        if stop_reason == "max_tokens":
            logger.warning(
                "LLM output hit max_tokens for task=%s model=%s; "
                "the payload may be truncated (raise DRA_ANTHROPIC_MAX_TOKENS)",
                task.value,
                model,
            )
        return response, _text_from_response(response)

    def _build_request(
        self,
        *,
        model: str,
        temperature: float,
        system_text: str,
        messages: list[dict[str, str]],
        schema: dict | None,
    ) -> dict[str, Any]:
        request: dict[str, Any] = {
            "model": model,
            "max_tokens": self._max_tokens,
            "messages": messages,
        }

        if schema is not None:
            request["output_config"] = {
                "format": {
                    "type": "json_schema",
                    "schema": sanitize_json_schema(schema),
                }
            }
        else:
            system_text = (
                f"{system_text}\n\n{JSON_ONLY_INSTRUCTION}"
                if system_text
                else JSON_ONLY_INSTRUCTION
            )

        if system_text:
            # Stable prefix first; cache_control is a no-op below the
            # provider's minimum cacheable size and a win above it.
            request["system"] = [
                {
                    "type": "text",
                    "text": system_text,
                    "cache_control": {"type": "ephemeral"},
                }
            ]

        if self._send_temperature:
            request["extra_body"] = {"temperature": temperature}

        return request


def _usage_dict(response: Any, *, attempts: int) -> dict[str, Any]:
    usage_obj = getattr(response, "usage", None)

    def _int(name: str) -> int:
        if usage_obj is None:
            return 0
        return int(getattr(usage_obj, name, 0) or 0)

    usage: dict[str, Any] = {
        "input_tokens": _int("input_tokens"),
        "output_tokens": _int("output_tokens"),
        "cache_creation_input_tokens": _int("cache_creation_input_tokens"),
        "cache_read_input_tokens": _int("cache_read_input_tokens"),
        "attempts": attempts,
        "stop_reason": getattr(response, "stop_reason", None),
    }
    usage["total_tokens"] = usage["input_tokens"] + usage["output_tokens"]
    request_id = getattr(response, "_request_id", None)
    if request_id:
        usage["request_id"] = request_id
    return usage


def _merge_usage(first: dict[str, Any], second: dict[str, Any]) -> dict[str, Any]:
    merged = dict(first)
    for key in (
        "input_tokens",
        "output_tokens",
        "cache_creation_input_tokens",
        "cache_read_input_tokens",
        "total_tokens",
        "attempts",
    ):
        merged[key] = int(first.get(key, 0) or 0) + int(second.get(key, 0) or 0)
    # Keep the final attempt's stop reason / request id for traceability.
    for key in ("stop_reason", "request_id"):
        if second.get(key) is not None:
            merged[key] = second[key]
    return merged


def _parse_and_validate(
    text: str,
    *,
    response_schema: dict | None,
    contract: type[BaseModel] | None,
) -> tuple[dict | None, str | None]:
    """Parse ``text`` as a JSON object and validate it.

    Returns ``(data, None)`` on success and ``(None, error)`` on failure.
    """
    data = extract_json_object(text)
    if data is None:
        return None, "response was not a valid JSON object"

    if contract is not None:
        try:
            contract.model_validate(data)
        except PydanticValidationError as exc:
            return None, f"payload did not match the task contract ({_format_pydantic_error(exc)})"
    elif response_schema is not None:
        try:
            jsonschema.validate(instance=data, schema=response_schema)
        except jsonschema.ValidationError as exc:
            path = ".".join(str(part) for part in exc.absolute_path) or "<root>"
            return None, f"JSON did not match the caller schema at {path}: {exc.message}"

    return data, None
