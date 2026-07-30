"""
v2.3.0 — tests for the optional live-verification module. No real network:
a lightweight mock client stands in for httpx.AsyncClient.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import pytest

import verifier


class _Resp:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


class _MockClient:
    """Records the last request and returns a scripted response."""
    def __init__(self, resp):
        self._resp = resp
        self.calls = []

    async def get(self, url, **kw):
        self.calls.append(("GET", url, kw))
        return self._resp

    async def post(self, url, **kw):
        self.calls.append(("POST", url, kw))
        return self._resp


@pytest.mark.asyncio
async def test_unsupported_type_returns_unsupported():
    # AWS keys have no safe automatic verifier here.
    status = await verifier.verify_finding("AWS Access Key", "AKIA...", _MockClient(_Resp(200)))
    assert status == "unsupported"


@pytest.mark.asyncio
async def test_github_verified_on_200():
    client = _MockClient(_Resp(200))
    status = await verifier.verify_finding("GitHub Personal Access Token", "ghp_x", client)
    assert status == "verified"
    assert client.calls[0][1] == "https://api.github.com/user"


@pytest.mark.asyncio
async def test_github_unverified_on_401():
    status = await verifier.verify_finding("GitHub Fine-Grained PAT", "github_pat_x", _MockClient(_Resp(401)))
    assert status == "unverified"


@pytest.mark.asyncio
async def test_slack_uses_ok_field():
    ok = await verifier.verify_finding("Slack Token", "xoxb-x", _MockClient(_Resp(200, {"ok": True})))
    not_ok = await verifier.verify_finding("Slack Token", "xoxb-x", _MockClient(_Resp(200, {"ok": False})))
    assert ok == "verified"
    assert not_ok == "unverified"


@pytest.mark.asyncio
async def test_verifier_fails_closed_on_exception():
    class _Boom:
        async def get(self, *a, **k):
            raise RuntimeError("network down")
        async def post(self, *a, **k):
            raise RuntimeError("network down")
    status = await verifier.verify_finding("OpenAI API Key", "sk-x", _Boom())
    assert status == "unverified"   # never raises, never "verified"


def test_supported_types_are_registered():
    for t in ("GitHub Personal Access Token", "Stripe Secret Key", "Slack Token",
              "OpenAI API Key", "GitLab Personal Access Token"):
        assert verifier.is_supported(t)
    assert not verifier.is_supported("AWS Access Key")


def test_every_verifier_maps_to_a_real_pattern():
    # Guard against typos: each verifiable type must exist in the scanner registry.
    import scanner
    names = {p.name for p in scanner.SECRET_PATTERNS}
    for secret_type in verifier.VERIFIERS:
        assert secret_type in names, f"{secret_type} not in SECRET_PATTERNS"


@pytest.mark.asyncio
async def test_detailed_github_captures_identity_and_scopes():
    class _R:
        status_code = 200
        headers = {"x-oauth-scopes": "repo, read:org"}
        def json(self): return {"login": "acme-bot"}
    class _C:
        async def get(self, *a, **k): return _R()
        async def post(self, *a, **k): return _R()
    res = await verifier.verify_finding_detailed("GitHub Personal Access Token", "ghp_x", _C())
    assert res.status == "verified"
    assert "acme-bot" in res.detail and "repo" in res.detail


@pytest.mark.asyncio
async def test_detailed_backward_compatible_string_api():
    # verify_finding() still returns a bare status string.
    s = await verifier.verify_finding("GitHub Personal Access Token", "ghp_x", _MockClient(_Resp(200)))
    assert s == "verified"


@pytest.mark.asyncio
async def test_detailed_no_detail_when_body_empty():
    # 200 but no login/scopes (mock without headers) → verified, empty detail, no crash.
    res = await verifier.verify_finding_detailed("GitHub Personal Access Token", "ghp_x", _MockClient(_Resp(200)))
    assert res.status == "verified" and res.detail == ""


@pytest.mark.asyncio
async def test_detailed_fails_closed():
    class _Boom:
        async def get(self, *a, **k): raise RuntimeError("down")
        async def post(self, *a, **k): raise RuntimeError("down")
    res = await verifier.verify_finding_detailed("OpenAI API Key", "sk-x", _Boom())
    assert res.status == "unverified" and res.detail == ""


@pytest.mark.asyncio
async def test_r6_verifiers_registered():
    for t in ("Cloudflare API Token", "DigitalOcean PAT", "Datadog API Key",
              "Notion Integration Token", "Linear API Key",
              "Figma Personal Access Token", "Postman API Key", "Doppler Token"):
        assert verifier.is_supported(t), t


@pytest.mark.asyncio
async def test_cloudflare_active_vs_disabled():
    active = await verifier.verify_finding_detailed(
        "Cloudflare API Token", "cf", _MockClient(_Resp(200, {"success": True, "result": {"status": "active"}})))
    disabled = await verifier.verify_finding_detailed(
        "Cloudflare API Token", "cf", _MockClient(_Resp(200, {"success": True, "result": {"status": "disabled"}})))
    assert active.status == "verified"
    assert disabled.status == "unverified"


@pytest.mark.asyncio
async def test_datadog_valid_field():
    ok = await verifier.verify_finding("Datadog API Key", "dd", _MockClient(_Resp(200, {"valid": True})))
    no = await verifier.verify_finding("Datadog API Key", "dd", _MockClient(_Resp(200, {"valid": False})))
    assert ok == "verified" and no == "unverified"


@pytest.mark.asyncio
async def test_linear_identity_extracted():
    res = await verifier.verify_finding_detailed(
        "Linear API Key", "lin",
        _MockClient(_Resp(200, {"data": {"viewer": {"name": "Ada", "email": "ada@x.com"}}})))
    assert res.status == "verified" and "ada@x.com" in res.detail


@pytest.mark.asyncio
async def test_figma_and_digitalocean_identity():
    fig = await verifier.verify_finding_detailed(
        "Figma Personal Access Token", "fig", _MockClient(_Resp(200, {"handle": "ada"})))
    do = await verifier.verify_finding_detailed(
        "DigitalOcean PAT", "do", _MockClient(_Resp(200, {"account": {"email": "ops@acme.io"}})))
    assert fig.status == "verified" and "ada" in fig.detail
    assert do.status == "verified" and "ops@acme.io" in do.detail


# ── v2.7.3 — AI/ML provider verifiers ────────────────────────────────────────
# Each pairs with a v2.7.2 detector. The impact signal for an AI key is usually
# the billing surface it exposes (tier + remaining quota), so the assertions
# check that the identity label actually carries that detail.

@pytest.mark.asyncio
async def test_elevenlabs_reports_tier_and_quota():
    payload = {"subscription": {"tier": "creator",
                                "character_count": 12345, "character_limit": 100000}}
    client = _MockClient(_Resp(200, payload))
    res = await verifier.verify_finding_detailed("ElevenLabs API Key", "sk_x", client)
    assert res.status == "verified"
    assert "creator tier" in res.detail
    assert "quota 12,345/100,000" in res.detail
    assert client.calls[0][1] == "https://api.elevenlabs.io/v1/user"
    # the key must go to its own issuer as a header, never to the scan target
    assert client.calls[0][2]["headers"]["xi-api-key"] == "sk_x"


@pytest.mark.asyncio
async def test_elevenlabs_dead_key_is_unverified():
    client = _MockClient(_Resp(401))
    res = await verifier.verify_finding_detailed("ElevenLabs API Key", "sk_x", client)
    assert res.status == "unverified"
    assert res.detail == ""


@pytest.mark.asyncio
async def test_huggingface_reports_user_role_and_orgs():
    payload = {"name": "acme-bot", "orgs": [{"name": "acme"}, {"name": "acme-labs"}],
               "auth": {"accessToken": {"role": "write"}}}
    res = await verifier.verify_finding_detailed(
        "Hugging Face Access Token", "hf_x", _MockClient(_Resp(200, payload)))
    assert res.status == "verified"
    assert "@acme-bot" in res.detail
    assert "role: write" in res.detail
    assert "2 org(s)" in res.detail


@pytest.mark.asyncio
async def test_openrouter_reports_credit_exposure():
    payload = {"data": {"label": "prod-key", "usage": 42, "limit": 500}}
    res = await verifier.verify_finding_detailed(
        "OpenRouter API Key", "sk-or-v1-x", _MockClient(_Resp(200, payload)))
    assert "key: prod-key" in res.detail
    assert "quota 42/500" in res.detail


@pytest.mark.asyncio
async def test_replicate_reports_account():
    payload = {"username": "acme", "type": "organization"}
    res = await verifier.verify_finding_detailed(
        "Replicate API Token", "r8_x", _MockClient(_Resp(200, payload)))
    assert "@acme" in res.detail and "organization" in res.detail


@pytest.mark.asyncio
async def test_xai_blocked_key_counts_as_unverified():
    """A 200 that reports the key as blocked must not be called live."""
    payload = {"name": "old-key", "api_key_blocked": True}
    res = await verifier.verify_finding_detailed(
        "xAI API Key", "xai-x", _MockClient(_Resp(200, payload)))
    assert res.status == "unverified"


@pytest.mark.asyncio
async def test_groq_and_pinecone_verify():
    groq = await verifier.verify_finding_detailed(
        "Groq API Key", "gsk_x", _MockClient(_Resp(200, {"data": [{"id": "a"}, {"id": "b"}]})))
    assert groq.status == "verified" and "2 models" in groq.detail
    pc = await verifier.verify_finding_detailed(
        "Pinecone API Key", "pcsk_x", _MockClient(_Resp(200, {"indexes": [{"name": "i"}]})))
    assert pc.status == "verified" and "1 index" in pc.detail


@pytest.mark.asyncio
async def test_ai_verifiers_fail_closed_on_exception():
    class _Boom:
        async def get(self, *a, **kw):
            raise RuntimeError("network down")

    for stype, val in [("ElevenLabs API Key", "sk_x"), ("Groq API Key", "gsk_x"),
                       ("OpenRouter API Key", "sk-or-x"), ("Pinecone API Key", "pcsk_x")]:
        res = await verifier.verify_finding_detailed(stype, val, _Boom())
        assert res.status == "unverified", stype


def test_every_ai_detector_has_a_verifier_or_is_documented():
    """Guard: a new AI detector should ship with a verifier where one is safe."""
    import scanner
    ai = {"ElevenLabs API Key", "Groq API Key", "Hugging Face Access Token",
          "Replicate API Token", "OpenRouter API Key", "xAI API Key", "Pinecone API Key"}
    names = {p.name for p in scanner.SECRET_PATTERNS}
    assert ai <= names, "detector missing from scanner"
    for t in ai:
        assert verifier.is_supported(t), f"{t} has no verifier"
