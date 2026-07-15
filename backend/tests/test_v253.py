"""
SecretNode v2.5.3 — AI config-error handling.

From a real scan against a live target with an invalid GEMINI_API_KEY: every
finding hit `400 INVALID_ARGUMENT: API key not valid`, and the old engine retried
each one 3×/tier and dumped all of them into needs-review — a flood of identical
scary alerts and ~6× the necessary API calls.

Now a permanent config error (invalid key / forbidden / missing model → 400/401/403/404)
fails fast (no retry), latches AI off for the rest of the scan (so later findings make
zero further calls), and returns findings as *skipped/unvalidated* (confidence 50) with a
single actionable reason — instead of the needs-review flood.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import pytest

import scanner
from google.genai import errors as genai_errors


@pytest.fixture(autouse=True)
def _reset_ai_latch():
    scanner._ai_disabled_reason = None
    yield
    scanner._ai_disabled_reason = None


class _Models:
    def __init__(self, exc):
        self.exc = exc
        self.calls = 0

    def generate_content(self, *, model, contents, config):
        self.calls += 1
        raise self.exc


class _Client:
    def __init__(self, exc):
        self.models = _Models(exc)


def _raw(i=0):
    return scanner.RawFinding(
        scan_id="s", target_url="https://t", source_url="https://t/a.js",
        secret_type="Generic High-Entropy Secret", raw_match=f"AKIA{i}xLY7H0T4vN2p9Qr",
        context_snippet="k = ...", entropy=4.2,
    )


def _wire(monkeypatch, exc):
    monkeypatch.setattr(scanner, "GEMINI_API_KEY", "bad-key")
    monkeypatch.setattr(scanner, "GEMINI_ESCALATE_SEVERITIES", frozenset({"CRITICAL"}))
    client = _Client(exc)
    monkeypatch.setattr(scanner, "_get_client", lambda: client)
    return client.models


def _invalid_key():
    return genai_errors.ClientError(
        400, {"error": {"code": 400, "message": "API key not valid. Please pass a valid API key.",
                        "status": "INVALID_ARGUMENT"}})


@pytest.mark.asyncio
async def test_invalid_key_fails_fast_no_retry(monkeypatch):
    models = _wire(monkeypatch, _invalid_key())
    await scanner.validate_with_gemini(_raw(1), broadcast=None)
    # One call, not RETRY_ATTEMPTS (3) — a 400 is not retried.
    assert models.calls == 1


@pytest.mark.asyncio
async def test_invalid_key_returns_skipped_not_needs_review(monkeypatch):
    _wire(monkeypatch, _invalid_key())
    r = await scanner.validate_with_gemini(_raw(1), broadcast=None)
    assert r.confidence == 50                       # skipped/unvalidated, not…
    assert r.confidence != scanner.NEEDS_REVIEW_SENTINEL
    assert r.is_valid is True
    assert "rejected" in r.reason.lower() or "invalid" in r.reason.lower()
    assert "aistudio.google.com" in r.reason        # actionable guidance


@pytest.mark.asyncio
async def test_ai_disabled_latch_short_circuits_rest_of_scan(monkeypatch):
    models = _wire(monkeypatch, _invalid_key())
    await scanner.validate_with_gemini(_raw(1), broadcast=None)
    calls_after_first = models.calls
    # Subsequent findings must make no further API calls this scan.
    for i in range(5):
        await scanner.validate_with_gemini(_raw(i + 2), broadcast=None)
    assert models.calls == calls_after_first
    assert scanner._ai_disabled_reason is not None


@pytest.mark.asyncio
async def test_model_not_found_reports_model_guidance(monkeypatch):
    _wire(monkeypatch, genai_errors.ClientError(404, {"error": {"code": 404, "message": "model not found"}}))
    r = await scanner.validate_with_gemini(_raw(1), broadcast=None)
    assert r.confidence == 50
    assert "model" in r.reason.lower()


@pytest.mark.asyncio
async def test_transient_429_still_needs_review(monkeypatch):
    """A rate-limit (429) is transient — it must NOT latch AI off; it retries and
    still degrades to needs-review, preserving the never-drop guarantee."""
    monkeypatch.setattr(scanner, "RETRY_ATTEMPTS", 1)  # avoid backoff sleeps
    _wire(monkeypatch, genai_errors.ClientError(429, {"error": {"code": 429, "message": "quota"}}))
    r = await scanner.validate_with_gemini(_raw(1), broadcast=None)
    assert r.confidence == scanner.NEEDS_REVIEW_SENTINEL
    assert scanner._ai_disabled_reason is None
