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


class TestParseCertspotterJson:
    def test_harvests_dns_names(self):
        payload = [
            {"dns_names": ["a.example.com", "*.example.com"]},
            {"dns_names": ["b.example.com", "admin@example.com"]},
        ]
        # Wildcard collapses to the base host; the email is rejected.
        assert recon.parse_certspotter_json(payload, "example.com") == [
            "a.example.com", "b.example.com", "example.com",
        ]

    def test_malformed_yields_empty(self):
        assert recon.parse_certspotter_json("nope", "example.com") == []


class _Resp:
    def __init__(self, status_code: int, text: str = ""):
        self.status_code = status_code
        self.text = text


class _FakeClient:
    """Async httpx.AsyncClient stand-in that routes by URL substring. A route
    value may be a response, an Exception (raised), or a list consumed in order
    (last item repeats) — the list form lets us exercise retry-then-succeed."""
    def __init__(self, routes: dict):
        self._routes = {k: (list(v) if isinstance(v, list) else v) for k, v in routes.items()}
        self.requested_urls: list[str] = []

    async def get(self, url, **kwargs):
        self.requested_urls.append(url)
        val = next((v for k, v in self._routes.items() if k in url), _Resp(404))
        item = (val.pop(0) if len(val) > 1 else val[0]) if isinstance(val, list) else val
        if isinstance(item, Exception):
            raise item
        return item


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    """Neutralise backoff sleeps so retry paths run instantly in tests."""
    async def _fast(*_a, **_k):
        return None
    monkeypatch.setattr(recon.asyncio, "sleep", _fast)


def _crtsh_body(*names: str) -> str:
    return json.dumps([{"name_value": "\n".join(names), "common_name": ""}])


def _certspotter_body(*names: str) -> str:
    return json.dumps([{"dns_names": list(names)}])


@pytest.mark.asyncio
async def test_enumerate_success_from_crtsh():
    client = _FakeClient({"crt.sh": _Resp(200, _crtsh_body("api.example.com", "www.example.com"))})
    result = await recon.enumerate_subdomains(client, "example.com")
    assert result.error is None
    assert result.subdomains == ["api.example.com", "www.example.com"]
    assert "crt.sh" in result.sources
    # crt.sh must be queried with the wildcard, never the target host itself.
    assert any("crt.sh" in u and "%25.example.com" in u for u in client.requested_urls)


@pytest.mark.asyncio
async def test_enumerate_merges_both_sources():
    client = _FakeClient({
        "crt.sh": _Resp(200, _crtsh_body("a.example.com")),
        "certspotter": _Resp(200, _certspotter_body("b.example.com")),
    })
    result = await recon.enumerate_subdomains(client, "example.com")
    assert result.subdomains == ["a.example.com", "b.example.com"]
    assert set(result.sources) == {"crt.sh", "certspotter"}


@pytest.mark.asyncio
async def test_enumerate_survives_one_source_down():
    client = _FakeClient({
        "crt.sh": _Resp(503),                                  # down (after retries)
        "certspotter": _Resp(200, _certspotter_body("b.example.com")),
    })
    result = await recon.enumerate_subdomains(client, "example.com")
    assert result.subdomains == ["b.example.com"]
    assert result.sources == ["certspotter"]
    assert result.error is None       # at least one source worked → not an error


@pytest.mark.asyncio
async def test_enumerate_retries_transient_then_succeeds():
    # crt.sh returns 502 then 200 — the retry must recover it.
    client = _FakeClient({
        "crt.sh": [_Resp(502), _Resp(200, _crtsh_body("a.example.com"))],
        "certspotter": _Resp(429),
    })
    result = await recon.enumerate_subdomains(client, "example.com")
    assert result.subdomains == ["a.example.com"]
    assert result.sources == ["crt.sh"]


@pytest.mark.asyncio
async def test_enumerate_all_sources_fail_sets_error():
    import httpx
    client = _FakeClient({
        "crt.sh": _Resp(503),
        "certspotter": httpx.ConnectError("boom"),
    })
    result = await recon.enumerate_subdomains(client, "example.com")
    assert result.subdomains == []
    assert result.error is not None
    # Error names each source's failure (never blank, unlike the old timeout bug).
    assert "crt.sh" in result.error and "certspotter" in result.error


@pytest.mark.asyncio
async def test_enumerate_respects_limit():
    names = [f"h{i}.example.com" for i in range(10)]
    client = _FakeClient({"crt.sh": _Resp(200, _crtsh_body(*names))})
    result = await recon.enumerate_subdomains(client, "example.com", limit=3)
    assert result.count == 3
