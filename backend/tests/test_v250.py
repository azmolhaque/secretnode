"""
SecretNode v2.5.0 — two-tier google-genai validation engine tests.

Covers the AI-validation rewrite: migration to the `google-genai` SDK, the
Tier-1 pre-filter → Tier-2 deep-validation escalation logic, strict structured
output via the Pydantic `GeminiVerdict` schema, and graceful degradation to
`needs_review` on API failure (429 / exhaustion) — all with a fake client, so
the suite stays fully offline and never touches the network or a real key.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import pytest

import scanner
from google.genai import errors as genai_errors, types


# ── Fakes ────────────────────────────────────────────────────────────────────

class _Resp:
    """Stand-in for the SDK's GenerateContentResponse."""
    def __init__(self, parsed=None, text=""):
        self.parsed = parsed
        self.text = text


class _FakeModels:
    def __init__(self, script):
        # script maps a model-id → a _Resp, a GeminiVerdict, or an Exception to raise
        self.script = script
        self.calls = []  # ordered list of model-ids actually invoked

    def generate_content(self, *, model, contents, config):
        self.calls.append(model)
        action = self.script[model]
        if isinstance(action, Exception):
            raise action
        if isinstance(action, scanner.GeminiVerdict):
            return _Resp(parsed=action)
        return action  # already a _Resp


class _FakeClient:
    def __init__(self, script):
        self.models = _FakeModels(script)


def _raw(secret_type="AWS Access Key", raw_match="AKIAIOSFODNN7EXAMPLE"):
    return scanner.RawFinding(
        scan_id="s1", target_url="https://example.com",
        source_url="https://example.com/app.js",
        secret_type=secret_type, raw_match=raw_match,
        context_snippet=f"const key = '{raw_match}'", entropy=4.2,
    )


@pytest.fixture
def engine(monkeypatch):
    """Wire a fake client + known model ids/severities into the scanner module.

    Returns a helper that installs a per-test `script` (model → response/exception)
    and yields the FakeModels so a test can assert which tiers were called."""
    monkeypatch.setattr(scanner, "GEMINI_API_KEY", "fake-key")
    monkeypatch.setattr(scanner, "GEMINI_TIER1_MODEL", "tier1-model")
    monkeypatch.setattr(scanner, "GEMINI_TIER2_MODEL", "tier2-model")
    monkeypatch.setattr(scanner, "GEMINI_ESCALATE_SEVERITIES", frozenset({"CRITICAL"}))
    monkeypatch.setattr(scanner, "RETRY_ATTEMPTS", 1)  # no backoff sleeps in failure tests

    installed = {}

    def install(script, severity="MEDIUM"):
        client = _FakeClient(script)
        monkeypatch.setattr(scanner, "_get_client", lambda: client)
        monkeypatch.setattr(scanner, "_severity_for", lambda _st: severity)
        installed["models"] = client.models
        return client.models

    return install


# ── GeminiVerdict schema ─────────────────────────────────────────────────────

class TestGeminiVerdict:
    def test_valid_payload(self):
        v = scanner.GeminiVerdict(is_valid=True, confidence=91, reason="live AWS key")
        assert v.is_valid and v.confidence == 91

    def test_confidence_out_of_range_rejected_by_schema(self):
        with pytest.raises(Exception):
            scanner.GeminiVerdict(is_valid=True, confidence=150, reason="x")

    def test_bound_to_response_schema(self):
        cfg = scanner._tier_config("high")
        assert cfg.response_schema is scanner.GeminiVerdict
        assert cfg.response_mime_type == "application/json"
        # SDK coerces the "high" string into the ThinkingLevel enum.
        assert cfg.thinking_config.thinking_level == types.ThinkingLevel.HIGH


# ── Skip path (no key) ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_no_key_skips(monkeypatch):
    monkeypatch.setattr(scanner, "GEMINI_API_KEY", "")
    result = await scanner.validate_with_gemini(_raw(), broadcast=None)
    assert isinstance(result, scanner.ValidatedFinding)
    assert result.confidence == 50 and "skipped" in result.reason.lower()


# ── Tier escalation logic ────────────────────────────────────────────────────

class TestEscalation:
    @pytest.mark.asyncio
    async def test_prefilter_rejects_noise_no_escalation(self, engine):
        """MEDIUM finding the cheap tier confidently rejects → Tier 2 never runs."""
        models = engine(
            {"tier1-model": scanner.GeminiVerdict(is_valid=False, confidence=95, reason="mock var")},
            severity="MEDIUM",
        )
        result = await scanner.validate_with_gemini(_raw(), broadcast=None)
        assert result.is_valid is False and result.confidence == 95
        assert models.calls == ["tier1-model"]  # no deep call

    @pytest.mark.asyncio
    async def test_prefilter_positive_escalates(self, engine):
        """Tier 1 thinks it is real → escalate; Tier 2 verdict wins."""
        models = engine(
            {
                "tier1-model": scanner.GeminiVerdict(is_valid=True, confidence=60, reason="looks real"),
                "tier2-model": scanner.GeminiVerdict(is_valid=True, confidence=97, reason="confirmed live"),
            },
            severity="MEDIUM",
        )
        result = await scanner.validate_with_gemini(_raw(), broadcast=None)
        assert result.confidence == 97 and result.reason == "confirmed live"
        assert models.calls == ["tier1-model", "tier2-model"]

    @pytest.mark.asyncio
    async def test_critical_always_escalates_even_when_prefilter_rejects(self, engine):
        """CRITICAL severity escalates even if the cheap tier says 'not a secret' —
        we never let the pre-filter be the last word on a critical."""
        models = engine(
            {
                "tier1-model": scanner.GeminiVerdict(is_valid=False, confidence=80, reason="prefilter unsure"),
                "tier2-model": scanner.GeminiVerdict(is_valid=True, confidence=99, reason="real cloud key"),
            },
            severity="CRITICAL",
        )
        result = await scanner.validate_with_gemini(_raw("GCP Service Account Key"), broadcast=None)
        assert result.is_valid is True and result.confidence == 99
        assert models.calls == ["tier1-model", "tier2-model"]


# ── Structured-output parsing ────────────────────────────────────────────────

class TestStructuredOutput:
    @pytest.mark.asyncio
    async def test_parsed_object_used_directly(self, engine):
        engine(
            {"tier1-model": scanner.GeminiVerdict(is_valid=False, confidence=88, reason="placeholder")},
            severity="MEDIUM",
        )
        result = await scanner.validate_with_gemini(_raw(), broadcast=None)
        assert result.reason == "placeholder"

    @pytest.mark.asyncio
    async def test_text_json_fallback_when_parsed_missing(self, engine):
        """If .parsed is None, raw JSON text is validated against the schema."""
        engine(
            {"tier1-model": _Resp(parsed=None, text='{"is_valid": false, "confidence": 42, "reason": "from text"}')},
            severity="MEDIUM",
        )
        result = await scanner.validate_with_gemini(_raw(), broadcast=None)
        assert result.confidence == 42 and result.reason == "from text"

    @pytest.mark.asyncio
    async def test_out_of_range_confidence_degrades_to_needs_review(self, engine):
        """The strict 0-100 schema rejects a malformed/over-range verdict on the
        text-fallback path — it degrades to needs_review rather than being coerced."""
        bad = _Resp(parsed=None, text='{"is_valid": true, "confidence": 250, "reason": "hot"}')
        engine({"tier1-model": bad, "tier2-model": bad}, severity="MEDIUM")
        result = await scanner.validate_with_gemini(_raw(), broadcast=None)
        assert result.confidence == scanner.NEEDS_REVIEW_SENTINEL


# ── Graceful degradation ─────────────────────────────────────────────────────

class TestGracefulDegradation:
    @pytest.mark.asyncio
    async def test_rate_limit_falls_back_to_needs_review(self, engine):
        """Both tiers 429 → surface as needs_review, never drop the finding."""
        err = genai_errors.ClientError(429, {"error": {"message": "quota", "status": "RESOURCE_EXHAUSTED"}})
        engine({"tier1-model": err, "tier2-model": err}, severity="CRITICAL")
        result = await scanner.validate_with_gemini(_raw("GCP Service Account Key"), broadcast=None)
        assert result.confidence == scanner.NEEDS_REVIEW_SENTINEL
        assert result.is_valid is False
        assert "manual review" in result.reason.lower()

    @pytest.mark.asyncio
    async def test_deep_tier_fails_falls_back_to_prefilter(self, engine):
        """Tier 1 succeeded, Tier 2 died → keep the Tier-1 verdict, not needs_review."""
        engine(
            {
                "tier1-model": scanner.GeminiVerdict(is_valid=True, confidence=70, reason="prefilter says real"),
                "tier2-model": RuntimeError("deep tier exploded"),
            },
            severity="CRITICAL",
        )
        result = await scanner.validate_with_gemini(_raw("GCP Service Account Key"), broadcast=None)
        assert result.confidence == 70 and result.is_valid is True

    @pytest.mark.asyncio
    async def test_never_returns_none_on_total_failure(self, engine):
        engine({"tier1-model": RuntimeError("boom")}, severity="MEDIUM")
        result = await scanner.validate_with_gemini(_raw(), broadcast=None)
        assert isinstance(result, scanner.ValidatedFinding)
        assert result.confidence == scanner.NEEDS_REVIEW_SENTINEL
