"""
v2.7.7 — R10 asset caching: conditional GET, 304 handling, and the rule that a
previously-dirty asset is always refetched so a finding can never silently
disappear from a report.

No response body is ever cached, so these tests also assert that nothing
resembling a body is persisted.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import asyncio

import pytest

import scanner


class _Resp:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}

    def raise_for_status(self):
        pass


class _Client:
    """Records every request so we can assert on conditional headers."""
    def __init__(self, *responses):
        self._responses = list(responses)
        self.requests = []

    async def get(self, url, headers=None, **kw):
        self.requests.append({"url": url, "headers": headers or {}})
        return self._responses.pop(0) if self._responses else _Resp(200, "")


@pytest.fixture(autouse=True)
def _clean():
    scanner.load_asset_cache({})
    yield
    scanner.load_asset_cache({})


def _fetch(client, url="https://t/app.js"):
    sem = asyncio.Semaphore(4)
    return asyncio.run(scanner.fetch_url(client, url, sem))


# ── conditional GET ──────────────────────────────────────────────────────────

def test_no_conditional_headers_without_a_cache_entry():
    c = _Client(_Resp(200, "body", {"etag": '"v1"'}))
    _fetch(c)
    h = c.requests[0]["headers"]
    assert "If-None-Match" not in h and "If-Modified-Since" not in h


def test_validators_are_recorded_after_a_successful_fetch():
    c = _Client(_Resp(200, "body", {"etag": '"v1"', "last-modified": "Wed, 21 Oct 2015 07:28:00 GMT"}))
    _fetch(c)
    out = scanner.drain_asset_cache()
    entry = out["https://t/app.js"]
    assert entry["etag"] == '"v1"'
    assert entry["last_modified"] == "Wed, 21 Oct 2015 07:28:00 GMT"
    assert entry["was_clean"] is True


def test_cached_entry_sends_conditional_headers():
    scanner.load_asset_cache({
        "https://t/app.js": {"etag": '"v1"', "last_modified": "Wed, 21 Oct 2015 07:28:00 GMT",
                             "content_hash": "abc", "was_clean": True}
    })
    c = _Client(_Resp(304, "", {}))
    _fetch(c)
    h = c.requests[0]["headers"]
    assert h["If-None-Match"] == '"v1"'
    assert h["If-Modified-Since"] == "Wed, 21 Oct 2015 07:28:00 GMT"


# ── 304 behaviour ────────────────────────────────────────────────────────────

def test_304_on_previously_clean_asset_is_skipped():
    scanner.load_asset_cache({
        "https://t/app.js": {"etag": '"v1"', "last_modified": None,
                             "content_hash": "abc", "was_clean": True}
    })
    url, body = _fetch(_Client(_Resp(304, "", {})))
    assert body == scanner.CACHED_CLEAN
    assert not scanner._usable_body(body), "sentinel must never be scanned as text"


def test_304_on_previously_dirty_asset_refetches_the_body():
    """A finding must never vanish because the asset was unchanged."""
    scanner.load_asset_cache({
        "https://t/app.js": {"etag": '"v1"', "last_modified": None,
                             "content_hash": "abc", "was_clean": False}
    })
    c = _Client(_Resp(304, "", {}), _Resp(200, "secret body", {"etag": '"v1"'}))
    url, body = _fetch(c)
    assert body == "secret body"
    assert len(c.requests) == 2, "should have refetched"
    # the retry must NOT carry the validators, or we'd 304 forever
    assert "If-None-Match" not in c.requests[1]["headers"]


def test_sentinel_is_not_a_usable_body():
    assert scanner._usable_body("real") is True
    assert scanner._usable_body(None) is False
    assert scanner._usable_body("") is False
    assert scanner._usable_body(scanner.CACHED_CLEAN) is False


# ── dirty marking ────────────────────────────────────────────────────────────

def test_mark_asset_dirty_flips_the_flag():
    c = _Client(_Resp(200, "body", {"etag": '"v1"'}))
    _fetch(c)
    scanner.mark_asset_dirty("https://t/app.js")
    assert scanner.drain_asset_cache()["https://t/app.js"]["was_clean"] is False


def test_mark_asset_dirty_on_unknown_url_is_a_noop():
    scanner.mark_asset_dirty("https://t/never-seen.js")   # must not raise


# ── privacy: no bodies cached ────────────────────────────────────────────────

def test_cache_never_stores_the_response_body():
    """A client's JS can hold live credentials; we keep validators only."""
    secret = "sk-ant-" + "A1b2C3d4E5f6G7h8J9k0" * 2
    c = _Client(_Resp(200, f'const k="{secret}";', {"etag": '"v1"'}))
    _fetch(c)
    entry = scanner.drain_asset_cache()["https://t/app.js"]
    blob = repr(entry)
    assert secret not in blob
    assert "const k" not in blob
    assert set(entry) == {"etag", "last_modified", "content_hash", "was_clean"}


def test_can_be_disabled_by_config():
    original = scanner.ASSET_CACHE_ENABLED
    try:
        scanner.ASSET_CACHE_ENABLED = False
        scanner.load_asset_cache({
            "https://t/app.js": {"etag": '"v1"', "last_modified": None,
                                 "content_hash": "abc", "was_clean": True}
        })
        c = _Client(_Resp(200, "body", {"etag": '"v1"'}))
        _fetch(c)
        assert "If-None-Match" not in c.requests[0]["headers"]
    finally:
        scanner.ASSET_CACHE_ENABLED = original


# ── v2.7.8 regressions in the 304 path ───────────────────────────────────────

def test_dirty_304_refetches_even_with_one_retry_attempt():
    """The refetch must not consume a retry attempt.

    With RETRY_ATTEMPTS=1 the `continue`-based implementation never re-issued the
    request, so a previously-dirty asset was dropped — the exact "finding
    silently vanishes" failure the cache is supposed to prevent.
    """
    original = scanner.RETRY_ATTEMPTS
    try:
        scanner.RETRY_ATTEMPTS = 1
        scanner.load_asset_cache({
            "https://t/app.js": {"etag": '"v1"', "last_modified": None,
                                 "content_hash": "h", "was_clean": False}
        })
        c = _Client(_Resp(304, "", {}), _Resp(200, "SECRET BODY", {"etag": '"v1"'}))
        url, body = _fetch(c)
        assert body == "SECRET BODY"
        assert len(c.requests) == 2
        assert "If-None-Match" not in c.requests[1]["headers"]
    finally:
        scanner.RETRY_ATTEMPTS = original


def test_unprompted_304_without_cache_entry_refetches():
    """A server may answer 304 we never asked for; don't burn a retry on it."""
    scanner.load_asset_cache({})
    c = _Client(_Resp(304, "", {}), _Resp(200, "body", {}))
    url, body = _fetch(c)
    assert body == "body"


def test_server_insisting_on_304_terminates():
    """Unconditional request still 304 -> give up, never spin."""
    scanner.load_asset_cache({})
    c = _Client(_Resp(304, "", {}), _Resp(304, "", {}))
    url, body = _fetch(c)
    assert body is None
    assert len(c.requests) == 2


def test_validator_stripping_helper():
    h = {"User-Agent": "x", "If-None-Match": '"v1"', "If-Modified-Since": "date"}
    out = scanner.extract_headers_without_validators(h)
    assert out == {"User-Agent": "x"}
    assert scanner.extract_headers_without_validators(None) is None
    assert scanner.extract_headers_without_validators(
        {"If-None-Match": '"v"'}) is None
