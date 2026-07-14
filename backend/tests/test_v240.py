"""
v2.4.0 — tests for the fetch-resilience, asset-discovery and detector upgrades
driven by real-world dashboard feedback:

  * WAF/CDN 403 on the target root (browser-like client + retry with a rotated
    fingerprint instead of an instant give-up),
  * thin coverage (only linked .js) — now source maps, module/preload scripts,
  * current-generation provider detectors (Supabase, Sentry, Doppler, GCP SA …).
"""

import os
import secrets
import string
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import asyncio

import httpx
import pytest

import scanner


def _rnd(n: int) -> str:
    return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(n))


def _hex(n: int) -> str:
    return "".join(secrets.choice("0123456789abcdef") for _ in range(n))


def _hits(body: str) -> set[str]:
    return {
        f.secret_type
        for f in scanner.extract_secrets("s", "https://t", "https://t/a.js", body)
    }


# ── new detectors ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "expected,body",
    [
        ("Supabase Access Token",        f'k="sbp_{_hex(40)}"'),
        ("Supabase Secret Key",          f'k="sb_secret_{_rnd(30)}"'),
        ("Sentry DSN",                   f'dsn:"https://{_hex(32)}@o42.ingest.sentry.io/7"'),
        ("Linear API Key",               f'k="lin_api_{_rnd(40)}"'),
        ("Notion Integration Token",     f'k="ntn_{_rnd(46)}"'),
        ("Doppler Token",                f"DOPPLER=dp.st.{_rnd(43)}"),
        ("PostHog Project API Key",      f'k="phc_{_rnd(43)}"'),
        ("Figma Personal Access Token",  f'k="figd_{_rnd(45)}"'),
        ("Cloudflare API Token",         f'k="cfat_{_rnd(40)}"'),
        ("GCP Service Account Key (JSON)",
         '{"type":"service_account","private_key_id":"' + _hex(40) + '"}'),
    ],
)
def test_v240_new_detectors(expected, body):
    assert expected in _hits(body)


def test_gcp_key_id_needs_json_context_not_bare_sha():
    # A bare 40-hex string (looks like a git SHA) must NOT be flagged as a GCP key.
    assert "GCP Service Account Key (JSON)" not in _hits(f'commit = "{_hex(40)}"')


def test_registry_grew_to_v240_size():
    assert len(scanner.SECRET_PATTERNS) >= 50


# ── source-map discovery ──────────────────────────────────────────────────────

def test_source_map_url_discovered_and_scoped():
    js = "console.log(1)\n//# sourceMappingURL=app.min.js.map\n"
    maps = scanner.extract_source_map_urls(js, "https://ex.com/static/app.min.js")
    assert maps == ["https://ex.com/static/app.min.js.map"]


def test_inline_data_source_map_is_skipped():
    js = "x=1//# sourceMappingURL=data:application/json;base64,eyJ2IjozfQ=="
    assert scanner.extract_source_map_urls(js, "https://ex.com/a.js") == []


def test_cross_domain_source_map_is_out_of_scope(monkeypatch):
    monkeypatch.setattr(scanner, "SCOPE_SAME_DOMAIN", True)
    js = "//# sourceMappingURL=https://cdn.other.com/a.js.map"
    assert scanner.extract_source_map_urls(js, "https://ex.com/a.js") == []


# ── module / preload script discovery ─────────────────────────────────────────

def test_module_and_preload_scripts_discovered():
    html = (
        '<script type="module" src="/m.js"></script>'
        '<link rel="modulepreload" href="/assets/chunk-abc.js">'
        '<link rel="preload" as="script" href="https://ex.com/p.js">'
        '<link rel="stylesheet" href="/style.css">'   # must be ignored
    )
    urls = set(scanner.extract_js_urls(html, "https://ex.com/"))
    assert "https://ex.com/m.js" in urls
    assert "https://ex.com/assets/chunk-abc.js" in urls
    assert "https://ex.com/p.js" in urls
    assert "https://ex.com/style.css" not in urls


# ── content-type gate ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("ct,ok", [
    ("text/html; charset=utf-8", True),
    ("application/javascript", True),
    ("application/json", True),
    ("image/svg+xml", True),
    ("", True),
    ("image/png", False),
    ("font/woff2", False),
    ("video/mp4", False),
])
def test_looks_scannable(ct, ok):
    assert scanner._looks_scannable(ct) is ok


# ── browser-like HTTP client ──────────────────────────────────────────────────

async def test_client_sends_browser_user_agent():
    async with scanner.build_client() as client:
        ua = client.headers["user-agent"]
        assert "Mozilla/5.0" in ua and "SecretNode" not in ua
        assert "sec-fetch-mode" in {k.lower() for k in client.headers}


def test_user_agent_override(monkeypatch):
    monkeypatch.setattr(scanner, "_UA_OVERRIDE", "MyCorp-Approved-Scanner/1.0")
    client = scanner.build_client()
    assert client.headers["user-agent"] == "MyCorp-Approved-Scanner/1.0"


# ── WAF/CDN 403 resilience (the headline real-world fix) ──────────────────────

async def test_fetch_retries_waf_block_then_succeeds(monkeypatch):
    """First response is a Cloudflare-style 403; the retry (different
    fingerprint) gets a 200. The old code gave up on the first 403."""
    monkeypatch.setattr(scanner, "RETRY_BACKOFF_BASE", 1.0)  # no real backoff sleep
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(403, headers={"server": "cloudflare"}, text="blocked")
        return httpx.Response(200, headers={"content-type": "text/html"}, text="<html>ok</html>")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        url, body = await scanner.fetch_url(client, "https://ex.com/", asyncio.Semaphore(2))
    assert calls["n"] >= 2
    assert body is not None and "ok" in body


async def test_fetch_gives_up_after_persistent_waf_block(monkeypatch):
    monkeypatch.setattr(scanner, "RETRY_BACKOFF_BASE", 1.0)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, headers={"server": "cloudflare"}, text="blocked")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        url, body = await scanner.fetch_url(client, "https://ex.com/", asyncio.Semaphore(2))
    assert body is None   # blocked, but handled gracefully (no crash)


async def test_fetch_skips_binary_content_type():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "image/png"}, content=b"\x89PNG")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        url, body = await scanner.fetch_url(client, "https://ex.com/logo.png", asyncio.Semaphore(2))
    assert body is None
