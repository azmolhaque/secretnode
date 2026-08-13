"""
v2.10.0 — tests for the Ollama adapter.

No Ollama required: a mock transport stands in, so these run in CI and on any
machine without a model pulled. What is being pinned is the failure behaviour —
that the adapter raises rather than returning a plausible default, because a
business process continuing on an invented value is worse than one that halts.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import httpx
import pytest

from ops import llm

SCHEMA = {
    "type": "object",
    "properties": {
        "email": {"type": "string"},
        "confidence": {"type": "integer"},
    },
    "required": ["email"],
}


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _chat_reply(content: str, status: int = 200) -> httpx.Response:
    return httpx.Response(status, json={
        "model": "llama3.2:3b",
        "message": {"role": "assistant", "content": content},
        "done": True,
        "eval_count": 42,
    })


# ── Happy path ───────────────────────────────────────────────────────────────

async def test_returns_parsed_data_on_a_valid_response():
    async with _client(lambda r: _chat_reply(json.dumps(
        {"email": "hello@acme.test", "confidence": 90}
    ))) as c:
        res = await llm.complete_json("find the email", SCHEMA, client=c)
    assert res["email"] == "hello@acme.test"
    assert res.attempts == 1
    assert res.eval_count == 42


async def test_request_carries_the_schema_and_deterministic_options():
    """The schema must reach Ollama as `format` — that is what constrains
    generation. Determinism (temp 0 + fixed seed) matters because a business
    decision may have to be explained later."""
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(json.loads(request.content))
        return _chat_reply(json.dumps({"email": "a@b.test"}))

    async with _client(handler) as c:
        await llm.complete_json("q", SCHEMA, client=c, system="be terse")

    assert seen["format"] == SCHEMA
    assert seen["stream"] is False
    assert seen["options"]["temperature"] == 0.0
    assert seen["options"]["seed"] == llm.DEFAULT_SEED
    assert seen["keep_alive"] == llm.KEEP_ALIVE
    assert seen["messages"][0] == {"role": "system", "content": "be terse"}


# ── Failure behaviour: raise, never fabricate ────────────────────────────────

async def test_unreachable_ollama_raises_rather_than_returning_a_default():
    def handler(request):
        raise httpx.ConnectError("connection refused")

    async with _client(handler) as c:
        with pytest.raises(llm.OllamaUnavailable, match="Is the service running"):
            await llm.complete_json("q", SCHEMA, client=c)


async def test_missing_model_says_how_to_fix_it():
    async with _client(lambda r: httpx.Response(404, text="model not found")) as c:
        with pytest.raises(llm.OllamaUnavailable, match="ollama pull"):
            await llm.complete_json("q", SCHEMA, client=c)


async def test_unparseable_output_is_retried_then_raises():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return _chat_reply('{"email": "truncat')      # cut off mid-stream

    async with _client(handler) as c:
        with pytest.raises(llm.SchemaViolation, match="truncated"):
            await llm.complete_json("q", SCHEMA, client=c, attempts=3)
    assert calls["n"] == 3


async def test_retries_vary_the_seed():
    """Retrying a deterministic failure with identical inputs reproduces it
    exactly — on a Pi, that is just an expensively slower way to fail."""
    seeds: list[int] = []

    def handler(request):
        seeds.append(json.loads(request.content)["options"]["seed"])
        return _chat_reply("not json at all")

    async with _client(handler) as c:
        with pytest.raises(llm.SchemaViolation):
            await llm.complete_json("q", SCHEMA, client=c, attempts=3)
    assert len(seeds) == 3 and len(set(seeds)) == 3


async def test_a_missing_required_field_is_rejected_not_returned():
    async with _client(lambda r: _chat_reply(json.dumps({"confidence": 90}))) as c:
        with pytest.raises(llm.SchemaViolation, match="required field 'email'"):
            await llm.complete_json("q", SCHEMA, client=c, attempts=1)


async def test_a_wrong_field_type_is_rejected():
    async with _client(lambda r: _chat_reply(json.dumps(
        {"email": "a@b.test", "confidence": "ninety"}
    ))) as c:
        with pytest.raises(llm.SchemaViolation, match="expected integer"):
            await llm.complete_json("q", SCHEMA, client=c, attempts=1)


async def test_boolean_is_not_accepted_as_an_integer():
    """bool subclasses int in Python, so a naive isinstance check lets True
    through as a count."""
    async with _client(lambda r: _chat_reply(json.dumps(
        {"email": "a@b.test", "confidence": True}
    ))) as c:
        with pytest.raises(llm.SchemaViolation, match="expected integer, got boolean"):
            await llm.complete_json("q", SCHEMA, client=c, attempts=1)


async def test_a_value_outside_an_enum_is_rejected():
    schema = {
        "type": "object",
        "properties": {"choice": {"type": "string", "enum": ["yes", "no"]}},
        "required": ["choice"],
    }
    async with _client(lambda r: _chat_reply(json.dumps({"choice": "maybe"}))) as c:
        with pytest.raises(llm.SchemaViolation, match="not in allowed"):
            await llm.complete_json("q", schema, client=c, attempts=1)


async def test_server_errors_are_retried():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if calls["n"] < 3:
            return httpx.Response(503, text="model loading")
        return _chat_reply(json.dumps({"email": "a@b.test"}))

    async with _client(handler) as c:
        res = await llm.complete_json("q", SCHEMA, client=c, attempts=3)
    assert res["email"] == "a@b.test" and res.attempts == 3


async def test_an_oversized_prompt_is_refused_before_any_network_call():
    """On a Pi this is minutes of prompt evaluation, not a big job. The caller
    should chunk; failing fast says so."""
    def handler(request):
        pytest.fail("no request should be made for an oversized prompt")

    async with _client(handler) as c:
        with pytest.raises(llm.PromptTooLarge, match="chunk"):
            await llm.complete_json("x" * (llm.MAX_PROMPT_CHARS + 1), SCHEMA, client=c)


# ── Health check ─────────────────────────────────────────────────────────────

async def test_health_distinguishes_a_dead_daemon_from_a_missing_model():
    """These fail differently and the fix differs — one is `ollama pull`, the
    other is a service that is not running."""
    async with _client(lambda r: httpx.Response(200, json={"models": []})) as c:
        ok, msg = await llm.health(c)
    assert ok is False and "not pulled" in msg

    def dead(request):
        raise httpx.ConnectError("refused")

    async with _client(dead) as c:
        ok, msg = await llm.health(c)
    assert ok is False and "unreachable" in msg


async def test_health_ok_when_the_model_is_present():
    async with _client(lambda r: httpx.Response(200, json={
        "models": [{"name": llm.DEFAULT_MODEL}]
    })) as c:
        ok, msg = await llm.health(c)
    assert ok is True and "ok" in msg


# ── classify(): the one shape a 3B model is reliable at ──────────────────────

async def test_classify_constrains_the_answer_to_the_option_list():
    seen: dict = {}

    def handler(request):
        seen.update(json.loads(request.content))
        return _chat_reply(json.dumps({"choice": "spam", "reason": "no company named"}))

    async with _client(handler) as c:
        choice, reason = await llm.classify("hi", "Is this a real enquiry?",
                                            ["real", "spam"], client=c)
    assert choice == "spam" and reason
    assert seen["format"]["properties"]["choice"]["enum"] == ["real", "spam"]
