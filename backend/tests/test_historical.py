"""Tests for historical path discovery (deep-ASM slice 3): Wayback + CommonCrawl.
Network is mocked; the pure parsers are exercised directly."""

from __future__ import annotations

import json

import httpx
import pytest

import historical


class TestParseWaybackCdx:
    def test_skips_header_and_keeps_in_scope(self):
        payload = [
            ["original"],                                   # CDX header row
            ["https://example.com/admin"],
            ["https://api.example.com/v1/keys"],
            ["https://evil.com/example.com"],               # out of scope
        ]
        out = historical.parse_wayback_cdx(payload, "example.com")
        assert out == ["https://api.example.com/v1/keys", "https://example.com/admin"]

    def test_accepts_raw_json_and_bad_input(self):
        raw = json.dumps([["original"], ["https://example.com/x"]])
        assert historical.parse_wayback_cdx(raw, "example.com") == ["https://example.com/x"]
        assert historical.parse_wayback_cdx("nope", "example.com") == []
        assert historical.parse_wayback_cdx({"bad": 1}, "example.com") == []


class TestParseCommoncrawlJsonl:
    def test_parses_jsonl_and_filters_scope(self):
        text = "\n".join([
            json.dumps({"url": "https://example.com/old.js"}),
            json.dumps({"url": "https://shop.example.com/checkout"}),
            json.dumps({"url": "https://other.net/x"}),           # out of scope
            "not-json-line",                                      # tolerated
        ])
        out = historical.parse_commoncrawl_jsonl(text, "example.com")
        assert out == ["https://example.com/old.js", "https://shop.example.com/checkout"]


class TestHistoricalResultViews:
    def test_paths_and_js_urls(self):
        r = historical.HistoricalResult(domain="example.com", urls=[
            "https://example.com/a", "https://example.com/a?x=1",
            "https://example.com/static/app.js", "https://example.com/b",
        ])
        # /a and /a?x=1 collapse to one path.
        assert r.paths == ["/a", "/b", "/static/app.js"]
        assert r.js_urls() == ["https://example.com/static/app.js"]

    def test_js_urls_dedupes_cache_buster_variants(self):
        # The same file under many ?v=… cache-busters must collapse to one seed —
        # this is what turns 11 api_data.js?v=… into a single fetch.
        r = historical.HistoricalResult(domain="example.com", urls=[
            "https://rest.example.com/docs/api_data.js?v=1596328976710",
            "https://rest.example.com/docs/api_data.js?v=1596328981612",
            "https://rest.example.com/docs/api_data.js?v=1743672225794",
            "https://rest.example.com/docs/api_project.js?v=1",
        ])
        assert r.js_urls() == [
            "https://rest.example.com/docs/api_data.js?v=1596328976710",
            "https://rest.example.com/docs/api_project.js?v=1",
        ]


class _Resp:
    def __init__(self, status_code: int, text: str = ""):
        self.status_code = status_code
        self.text = text


class _FakeClient:
    """Routes GETs by URL substring; a route value may be a response, an
    Exception, or a list consumed in order (for retry tests)."""
    def __init__(self, routes: dict):
        self._routes = {k: (list(v) if isinstance(v, list) else v) for k, v in routes.items()}
        self.requested_urls: list[str] = []

    async def get(self, url, **_kw):
        self.requested_urls.append(url)
        val = next((v for k, v in self._routes.items() if k in url), _Resp(404))
        item = (val.pop(0) if len(val) > 1 else val[0]) if isinstance(val, list) else val
        if isinstance(item, Exception):
            raise item
        return item


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    async def _fast(*_a, **_k):
        return None
    monkeypatch.setattr(historical.asyncio, "sleep", _fast)


def _wayback_body(*urls: str) -> str:
    return json.dumps([["original"], *[[u] for u in urls]])


@pytest.mark.asyncio
async def test_discover_wayback_only():
    client = _FakeClient({"web.archive.org": _Resp(200, _wayback_body(
        "https://example.com/admin", "https://example.com/app.js"))})
    result = await historical.discover_historical_urls(
        client, "example.com", enable_commoncrawl=False)
    assert result.error is None
    assert result.urls == ["https://example.com/admin", "https://example.com/app.js"]
    assert result.sources == ["wayback"]
    assert result.js_urls() == ["https://example.com/app.js"]


@pytest.mark.asyncio
async def test_discover_merges_wayback_and_commoncrawl():
    collinfo = json.dumps([{"id": "CC-MAIN-latest", "cdx-api": "https://index.commoncrawl.org/CC-MAIN-latest-index"}])
    client = _FakeClient({
        "web.archive.org": _Resp(200, _wayback_body("https://example.com/a")),
        "collinfo.json": _Resp(200, collinfo),
        "CC-MAIN-latest-index": _Resp(200, json.dumps({"url": "https://example.com/b"})),
    })
    result = await historical.discover_historical_urls(client, "example.com")
    assert result.urls == ["https://example.com/a", "https://example.com/b"]
    assert set(result.sources) == {"wayback", "commoncrawl"}


@pytest.mark.asyncio
async def test_discover_survives_one_source_down():
    client = _FakeClient({
        "web.archive.org": _Resp(200, _wayback_body("https://example.com/a")),
        "collinfo.json": _Resp(503),                       # CommonCrawl down
    })
    result = await historical.discover_historical_urls(client, "example.com")
    assert result.urls == ["https://example.com/a"]
    assert result.sources == ["wayback"]
    assert result.error is None       # one good source → not an error


@pytest.mark.asyncio
async def test_discover_retries_transient_then_succeeds():
    client = _FakeClient({
        "web.archive.org": [_Resp(502), _Resp(200, _wayback_body("https://example.com/a"))],
    })
    result = await historical.discover_historical_urls(
        client, "example.com", enable_commoncrawl=False)
    assert result.urls == ["https://example.com/a"]


@pytest.mark.asyncio
async def test_discover_all_fail_sets_error():
    client = _FakeClient({
        "web.archive.org": httpx.ConnectError("boom"),
        "collinfo.json": _Resp(503),
    })
    result = await historical.discover_historical_urls(client, "example.com")
    assert result.urls == []
    assert result.error is not None
    assert "wayback" in result.error and "commoncrawl" in result.error


@pytest.mark.asyncio
async def test_discover_respects_limit():
    urls = [f"https://example.com/p{i}" for i in range(10)]
    client = _FakeClient({"web.archive.org": _Resp(200, _wayback_body(*urls))})
    result = await historical.discover_historical_urls(
        client, "example.com", limit=3, enable_commoncrawl=False)
    assert result.count == 3
