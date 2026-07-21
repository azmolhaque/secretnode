"""Tests for subdomain-takeover detection (deep-dive slice D1). The pure check is
exercised directly; network/DNS is mocked."""

from __future__ import annotations

import httpx
import pytest

import takeover


class TestCheckTakeover:
    def test_github_pages_takeover_with_cname(self):
        f = takeover.check_takeover(
            "blog.example.com",
            ["example.github.io"],
            "<h1>404</h1> There isn't a GitHub Pages site here.",
        )
        assert f is not None
        assert f.service == "GitHub Pages"
        assert f.cname == "example.github.io"
        assert f.secret_type == "Subdomain Takeover"

    def test_s3_takeover_is_critical(self):
        f = takeover.check_takeover(
            "assets.example.com",
            ["assets.example.com.s3.amazonaws.com"],
            "<Error><Code>NoSuchBucket</Code></Error>",
        )
        assert f is not None and f.severity == "CRITICAL"

    def test_body_signature_without_resolvable_cname_still_flags(self):
        # When CNAMEs can't be resolved ([]), a SPECIFIC body signature alone flags.
        f = takeover.check_takeover(
            "old.example.com", [], "Fastly error: unknown domain: old.example.com",
        )
        assert f is not None and f.service == "Fastly"

    def test_cname_present_but_wrong_service_does_not_flag(self):
        # CNAMEs resolved but none point at the service in the body signature →
        # a look-alike string on an unrelated host must NOT over-trigger.
        f = takeover.check_takeover(
            "x.example.com", ["x.example.com.cdn.cloudflare.net"],
            "There isn't a GitHub Pages site here.",
        )
        assert f is None

    def test_clean_page_is_not_flagged(self):
        f = takeover.check_takeover(
            "www.example.com", ["www.example.com.edgekey.net"],
            "<html><body>Welcome to Example</body></html>",
        )
        assert f is None


class _Resp:
    def __init__(self, text: str):
        self.text = text


class _FakeClient:
    def __init__(self, body: str = "", raise_all: bool = False):
        self._body = body
        self._raise = raise_all

    async def get(self, url, **_kw):
        if self._raise:
            raise httpx.ConnectError("dead")
        return _Resp(self._body)


@pytest.fixture(autouse=True)
def _stub_dns(monkeypatch):
    # Deterministic CNAMEs without real DNS.
    monkeypatch.setattr(takeover, "resolve_cnames", lambda host: ["x.github.io"])


@pytest.mark.asyncio
async def test_detect_takeover_positive():
    client = _FakeClient("There isn't a GitHub Pages site here.")
    f = await takeover.detect_takeover(client, "blog.example.com")
    assert f is not None and f.service == "GitHub Pages"


@pytest.mark.asyncio
async def test_detect_takeover_unreachable_returns_none():
    client = _FakeClient(raise_all=True)
    assert await takeover.detect_takeover(client, "dead.example.com") is None


@pytest.mark.asyncio
async def test_scan_hosts_collects_only_findings(monkeypatch):
    # blog → takeover; www → clean.
    def _client_get(body):
        return _FakeClient(body)

    class _Router:
        async def get(self, url, **_kw):
            body = ("There isn't a GitHub Pages site here." if "blog" in url
                    else "<html>fine</html>")
            return _Resp(body)

    findings = await takeover.scan_hosts_for_takeover(_Router(), ["blog.example.com", "www.example.com"])
    assert len(findings) == 1
    assert findings[0].host == "blog.example.com"
