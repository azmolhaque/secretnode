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
