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
