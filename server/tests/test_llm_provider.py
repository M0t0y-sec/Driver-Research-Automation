"""Tests for provider selection and the real Anthropic client.

No network here: the Anthropic client is injected with a fake transport
that returns Message-shaped objects. The mock client's behaviour is
covered by the existing graph tests.
"""

import json
import logging
from dataclasses import replace
from types import SimpleNamespace

import pytest

from dra.config import SETTINGS
from dra.llm.anthropic_client import (
    AnthropicLLMClient,
    extract_json_object,
    sanitize_json_schema,
)
from dra.llm.base import LLMMessage, LLMTask
from dra.llm.errors import LLMConfigurationError, LLMOutputError, LLMRefusalError
from dra.llm.factory import build_llm_client, build_llm_router
from dra.llm.mock import MockLLMClient

HYPOTHESIS_PAYLOAD = {
    "hypotheses": [
        {
            "category": "memory_safety",
            "location": "RtlCopyMemory",
            "description": "Unbounded copy from a user-controlled IOCTL buffer.",
            "observation_ids": ["OBS-1"],
            "score_breakdown": {
                "impact": 0.6,
                "confidence": 0.4,
                "reachability": 0.7,
                "testability": 0.5,
                "rule_score": 0.5,
                "model_explanation": "copy length comes from the input buffer",
                "uncertainty": "medium",
            },
            "requires_human_review": True,
        }
    ]
}


def _response(
    text: str,
    *,
    model: str = "claude-opus-5-5",
    stop_reason: str = "end_turn",
    input_tokens: int = 100,
    output_tokens: int = 50,
):
    return SimpleNamespace(
        content=[SimpleNamespace(type="text", text=text)],
        model=model,
        stop_reason=stop_reason,
        stop_details=None,
        usage=SimpleNamespace(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cache_creation_input_tokens=0,
            cache_read_input_tokens=0,
        ),
        _request_id="req_test",
    )


class FakeMessages:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls: list[dict] = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if not self._responses:
            raise AssertionError("unexpected extra provider call")
        item = self._responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class FakeAnthropic:
    def __init__(self, responses):
        self.messages = FakeMessages(responses)


def _client(responses, **kwargs) -> tuple[AnthropicLLMClient, FakeAnthropic]:
    fake = FakeAnthropic(responses)
    return AnthropicLLMClient(client=fake, **kwargs), fake


# --- provider selection -------------------------------------------------


def test_factory_default_mock_matches_existing_behaviour():
    settings = replace(SETTINGS, llm_provider="mock")
    client = build_llm_client(settings)
    assert isinstance(client, MockLLMClient)
    # Same deterministic output the graph relied on before this change.
    resp = client.complete(
        [LLMMessage(role="user", content="Return JSON {\"x\": 1}.")],
        task=LLMTask.TOOL_OUTPUT_PARSE,
    )
    assert resp.structured == {"x": 1}
    assert resp.model == "mock"


def test_factory_falls_back_to_mock_without_key(caplog):
    settings = replace(SETTINGS, llm_provider="anthropic", anthropic_api_key=None)
    with caplog.at_level(logging.WARNING, logger="dra.llm.factory"):
        client = build_llm_client(settings)
    assert isinstance(client, MockLLMClient)
    assert "falling back to MockLLMClient" in caplog.text


def test_factory_builds_anthropic_with_key():
    settings = replace(
        SETTINGS, llm_provider="anthropic", anthropic_api_key="test-key-not-real"
    )
    client = build_llm_client(settings)
    assert isinstance(client, AnthropicLLMClient)
    assert client.name == "anthropic"


def test_factory_unknown_provider_falls_back(caplog):
    settings = replace(SETTINGS, llm_provider="openai")
    with caplog.at_level(logging.WARNING, logger="dra.llm.factory"):
        client = build_llm_client(settings)
    assert isinstance(client, MockLLMClient)
    assert "Unknown DRA_LLM_PROVIDER" in caplog.text


def test_build_ops_uses_factory(monkeypatch, tmp_path):
    from dra.agents._ops import build_ops

    monkeypatch.setattr(SETTINGS, "llm_provider", "mock")
    monkeypatch.setattr(SETTINGS, "anthropic_api_key", None)
    monkeypatch.setattr(SETTINGS, "data_dir", tmp_path / "data")
    monkeypatch.setattr(SETTINGS, "artifacts_dir", tmp_path / "artefacts")
    (tmp_path / "data").mkdir()
    (tmp_path / "artefacts").mkdir()
    ops = build_ops()
    assert isinstance(ops.llm.client, MockLLMClient)


# --- model tier + response metadata ------------------------------------

VALID_HYPOTHESIS_TEXT = json.dumps(HYPOTHESIS_PAYLOAD)


def test_hypothesis_task_routes_to_large_model_and_validates():
    client, fake = _client([_response(VALID_HYPOTHESIS_TEXT)])
    resp = client.complete(
        [LLMMessage(role="user", content="Observations:\n- id: OBS-1 category: memory_copy")],
        task=LLMTask.HYPOTHESIS_GEN,
    )

    call = fake.messages.calls[0]
    assert call["model"] == "claude-opus-5-5"
    assert call["output_config"]["format"]["type"] == "json_schema"
    # Unsupported keywords are stripped on the wire...
    wire_schema = json.dumps(call["output_config"]["format"]["schema"])
    assert "minimum" not in wire_schema
    assert '"additionalProperties": false' in wire_schema

    assert resp.structured == HYPOTHESIS_PAYLOAD
    assert resp.model == "claude-opus-5-5"
    assert resp.temperature == 0.4  # ROUTING_TABLE[HYPOTHESIS_GEN]
    assert resp.usage["input_tokens"] == 100
    assert resp.usage["output_tokens"] == 50
    assert resp.usage["total_tokens"] == 150
    assert resp.usage["attempts"] == 1
    assert resp.latency_ms >= 0.0


def test_small_task_routes_to_haiku_and_hoists_system_prompt():
    client, fake = _client([_response('{"labels": ["ioctl_dispatch"]}')])
    resp = client.complete(
        [
            LLMMessage(role="system", content="You label driver behaviours."),
            LLMMessage(role="user", content="Label: IoCreateDevice"),
        ],
        task=LLMTask.LABEL_EXTRACT,
    )

    call = fake.messages.calls[0]
    assert call["model"] == "claude-haiku-5-5"
    assert call["messages"] == [{"role": "user", "content": "Label: IoCreateDevice"}]
    assert call["system"][0]["text"] == "You label driver behaviours."
    assert call["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert resp.temperature == 0.0
    assert resp.structured == {"labels": ["ioctl_dispatch"]}


def test_temperature_is_not_sent_on_current_api_version():
    client, fake = _client([_response('{"explanation": "ok"}')])
    resp = client.complete(
        [LLMMessage(role="user", content="Explain.")], task=LLMTask.CODE_EXPLAIN
    )
    assert "extra_body" not in fake.messages.calls[0]
    assert resp.temperature == 0.2  # still recorded for traceability


def test_temperature_is_sent_when_legacy_api_version_pinned():
    client, fake = _client(
        [_response('{"explanation": "ok"}')], api_version="2023-06-01"
    )
    client.complete(
        [LLMMessage(role="user", content="Explain.")], task=LLMTask.CODE_EXPLAIN
    )
    assert fake.messages.calls[0]["extra_body"] == {"temperature": 0.2}


# --- invalid / adversarial output --------------------------------------


def test_invalid_json_triggers_one_repair():
    client, fake = _client(
        [_response("I cannot produce JSON."), _response('{"explanation": "repaired"}')]
    )
    resp = client.complete(
        [LLMMessage(role="user", content="Explain.")], task=LLMTask.CODE_EXPLAIN
    )

    assert len(fake.messages.calls) == 2
    repair_call = fake.messages.calls[1]
    assert repair_call["model"] == "claude-haiku-5-5"  # JSON_REPAIR tier
    assert repair_call["messages"][-2]["role"] == "assistant"
    assert repair_call["messages"][-1]["role"] == "user"

    assert resp.structured == {"explanation": "repaired"}
    assert resp.usage["attempts"] == 2
    assert resp.usage["input_tokens"] == 200  # aggregated over both calls


def test_invalid_json_after_repair_raises_explicit_error():
    client, fake = _client([_response("nope"), _response("still nope")])
    with pytest.raises(LLMOutputError) as excinfo:
        client.complete(
            [LLMMessage(role="user", content="Explain.")], task=LLMTask.CODE_EXPLAIN
        )
    assert len(fake.messages.calls) == 2
    assert excinfo.value.raw_text == "still nope"
    assert excinfo.value.schema_error


def test_schema_mismatch_triggers_repair():
    # Valid JSON, wrong shape: CODE_EXPLAIN requires {"explanation": str}.
    client, fake = _client(
        [_response('{"foo": 1}'), _response('{"explanation": "fixed"}')]
    )
    resp = client.complete(
        [LLMMessage(role="user", content="Explain.")], task=LLMTask.CODE_EXPLAIN
    )
    assert len(fake.messages.calls) == 2
    assert resp.structured == {"explanation": "fixed"}


def test_caller_supplied_schema_overrides_task_contract():
    schema = {
        "type": "object",
        "properties": {"answer": {"type": "string"}},
        "required": ["answer"],
        "additionalProperties": False,
    }
    client, fake = _client(
        [_response('{"answer": 42}'), _response('{"answer": "42"}')]
    )
    resp = client.complete(
        [LLMMessage(role="user", content="Answer.")],
        task=LLMTask.LABEL_EXTRACT,
        response_schema=schema,
    )
    assert len(fake.messages.calls) == 2
    assert resp.structured == {"answer": "42"}
    assert fake.messages.calls[0]["output_config"]["format"]["schema"] == schema


def test_refusal_is_an_explicit_error_not_a_repair():
    client, fake = _client([_response("", stop_reason="refusal")])
    with pytest.raises(LLMRefusalError):
        client.complete(
            [LLMMessage(role="user", content="Explain.")], task=LLMTask.CODE_EXPLAIN
        )
    assert len(fake.messages.calls) == 1


def test_embedding_task_is_rejected_clearly():
    client, fake = _client([])
    with pytest.raises(LLMConfigurationError):
        client.complete(
            [LLMMessage(role="user", content="embed this")], task=LLMTask.EMBEDDING
        )
    assert fake.messages.calls == []


# --- helpers ------------------------------------------------------------


def test_extract_json_object_handles_fences_and_prose():
    assert extract_json_object('```json\n{"a": 1}\n```') == {"a": 1}
    assert extract_json_object('Here you go: {"a": 2} hope it helps') == {"a": 2}
    assert extract_json_object("not json") is None


def test_sanitize_schema_strips_unsupported_constraints_recursively():
    schema = {
        "type": "object",
        "properties": {
            "n": {"type": "number", "minimum": 0, "maximum": 1},
            "items": {
                "type": "array",
                "minItems": 1,
                "items": {"type": "object", "properties": {"x": {"type": "string", "maxLength": 5}}},
            },
        },
    }
    cleaned = sanitize_json_schema(schema)
    assert "minimum" not in cleaned["properties"]["n"]
    assert "maxItems" not in cleaned["properties"]["items"]
    assert "minItems" not in cleaned["properties"]["items"]
    assert cleaned["additionalProperties"] is False
    assert cleaned["properties"]["items"]["items"]["additionalProperties"] is False
    assert "maxLength" not in cleaned["properties"]["items"]["items"]["properties"]["x"]
