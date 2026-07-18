"""Tests for passive reconnaissance (subdomain enumeration via Certificate
Transparency). Network is mocked so these are fast and deterministic; the pure
parsing/normalisation helpers are exercised directly."""

from __future__ import annotations

import json

import pytest

import recon


class TestExtractRegistrableDomain:
    def test_bare_domain(self):
        assert recon.extract_registrable_domain("example.com") == "example.com"

    def test_url_with_subdomain_and_path(self):
        assert recon.extract_registrable_domain("https://api.blog.example.com/x?y=1") == "example.com"

    def test_host_with_port(self):
        assert recon.extract_registrable_domain("shop.example.com:8443") == "example.com"

    def test_two_level_suffix_uk(self):
        assert recon.extract_registrable_domain("https://api.example.co.uk/") == "example.co.uk"

    def test_two_level_suffix_bd(self):
        # Cindrasec's home market — must not truncate to the public suffix itself.
        assert recon.extract_registrable_domain("mail.gov.bd") == "mail.gov.bd"
        assert recon.extract_registrable_domain("www.dhaka.gov.bd") == "dhaka.gov.bd"

    def test_ip_literal_returns_none(self):
        assert recon.extract_registrable_domain("http://192.168.1.1/") is None
        assert recon.extract_registrable_domain("10.0.0.5") is None

    def test_single_label_returns_none(self):
        assert recon.extract_registrable_domain("localhost") is None


class TestIsIpLiteral:
    def test_ipv4(self):
        assert recon.is_ip_literal("https://203.0.113.5:8000/") is True

    def test_domain_is_not_ip(self):
        assert recon.is_ip_literal("example.com") is False


class TestParseCrtshJson:
    def test_harvests_and_dedupes_in_scope_names(self):
        payload = [
            {"name_value": "api.example.com\nwww.example.com", "common_name": "example.com"},
            {"name_value": "www.example.com", "common_name": "cdn.example.com"},
        ]
        out = recon.parse_crtsh_json(payload, "example.com")
        assert out == ["api.example.com", "cdn.example.com", "example.com", "www.example.com"]

    def test_strips_wildcards(self):
        payload = [{"name_value": "*.example.com", "common_name": ""}]
        assert recon.parse_crtsh_json(payload, "example.com") == ["example.com"]

    def test_drops_out_of_scope_and_emails(self):
        payload = [{
            "name_value": "good.example.com\nevil.example.com.attacker.net\nadmin@example.com",
            "common_name": "notexample.com",
        }]
        # Only the genuine in-scope host survives; a look-alike suffix and an
        # email address must both be rejected (no false surface).
        assert recon.parse_crtsh_json(payload, "example.com") == ["good.example.com"]

    def test_accepts_raw_json_string(self):
        payload = json.dumps([{"name_value": "a.example.com", "common_name": ""}])
        assert recon.parse_crtsh_json(payload, "example.com") == ["a.example.com"]

    def test_malformed_payload_yields_empty(self):
        assert recon.parse_crtsh_json("not json", "example.com") == []
        assert recon.parse_crtsh_json({"unexpected": "shape"}, "example.com") == []


class _FakeResponse:
    def __init__(self, status_code: int, text: str):
        self.status_code = status_code
        self.text = text


class _FakeClient:
    """Minimal async httpx.AsyncClient stand-in for enumerate_subdomains_ct."""
    def __init__(self, response=None, exc=None):
        self._response = response
        self._exc = exc
        self.requested_url: str | None = None

    async def get(self, url, **kwargs):
        self.requested_url = url
        if self._exc is not None:
            raise self._exc
        return self._response


@pytest.mark.asyncio
async def test_enumerate_success():
    body = json.dumps([{"name_value": "api.example.com\nwww.example.com", "common_name": ""}])
    client = _FakeClient(response=_FakeResponse(200, body))
    result = await recon.enumerate_subdomains_ct(client, "example.com")
    assert result.error is None
    assert result.subdomains == ["api.example.com", "www.example.com"]
    assert result.count == 2
    # Query must target crt.sh with the wildcard, never the target host itself.
    assert "crt.sh" in client.requested_url and "%25.example.com" in client.requested_url


@pytest.mark.asyncio
async def test_enumerate_non_200_fails_closed():
    client = _FakeClient(response=_FakeResponse(503, ""))
    result = await recon.enumerate_subdomains_ct(client, "example.com")
    assert result.subdomains == []
    assert result.error is not None and "503" in result.error


@pytest.mark.asyncio
async def test_enumerate_network_error_fails_closed():
    import httpx
    client = _FakeClient(exc=httpx.ConnectError("boom"))
    result = await recon.enumerate_subdomains_ct(client, "example.com")
    assert result.subdomains == []
    assert result.error is not None


@pytest.mark.asyncio
async def test_enumerate_respects_limit():
    names = "\n".join(f"h{i}.example.com" for i in range(10))
    client = _FakeClient(response=_FakeResponse(200, json.dumps([{"name_value": names}])))
    result = await recon.enumerate_subdomains_ct(client, "example.com", limit=3)
    assert result.count == 3
