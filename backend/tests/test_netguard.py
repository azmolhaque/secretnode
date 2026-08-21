"""
The redirect chain was unguarded, and a redirect is enough to undo every
pre-flight check the tool makes.

`build_client()` set `follow_redirects=True`. `assert_public_target` ran once,
against the URL the operator typed, and never again. Everything after that — the
redirect off the root document, the redirect on a JS bundle — was resolved and
connected by httpx with nothing looking at where it went.

A probe against the pre-fix code confirmed all three consequences:

    requested:    http://127.0.0.1:PORT/redirect
    returned url: http://127.0.0.1:PORT/redirect      <- the URL asked for
    body:         const k = "AKIA…"                   <- from /internal

That is (1) an SSRF — a 302 to 169.254.169.254 reaches instance metadata, and
any open redirect on an authorized target is a sufficient trigger; (2) an
out-of-scope fetch, from a tool whose ledger asserts only authorized hosts were
contacted; and (3) a misattribution, because the body was filed under the URL
requested rather than the one that answered.

These tests pin the fixed behaviour. The address checks are deliberately written
against `netguard` directly (no DNS, no sockets) and the chain tests against a
fake client, so the suite stays hermetic.
"""

from __future__ import annotations

import asyncio
import ipaddress
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import netguard  # noqa: E402
import scanner  # noqa: E402


class FakeResponse:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}

    def raise_for_status(self):
        pass


class RedirectClient:
    """Serves a scripted redirect map, recording every URL actually requested."""

    def __init__(self, chain: dict[str, str], body: str = "ok", status: int = 302):
        self.chain = chain
        self.body = body
        self.status = status
        self.requested: list[str] = []

    async def get(self, url, headers=None, **kw):
        self.requested.append(url)
        if url in self.chain:
            return FakeResponse(self.status, "", {"location": self.chain[url]})
        return FakeResponse(200, self.body, {"content-type": "application/javascript"})


# ── address classification ───────────────────────────────────────────────────

@pytest.mark.parametrize("addr", [
    "127.0.0.1",            # loopback
    "::1",                  # loopback, v6
    "10.0.0.1",             # RFC1918
    "192.168.1.1",          # RFC1918
    "169.254.169.254",      # cloud instance metadata — the prize
    "fd00::1",              # unique-local v6
    "0.0.0.0",              # unspecified
    "224.0.0.1",            # multicast
    "100.64.0.1",           # RFC6598 CGNAT
    "::ffff:127.0.0.1",     # IPv4-mapped loopback
    "::ffff:169.254.169.254",  # IPv4-mapped metadata
])
def test_non_public_addresses_are_refused(addr):
    assert netguard.is_forbidden_address(ipaddress.ip_address(addr)) is True, addr


@pytest.mark.parametrize("addr", ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700::1111"])
def test_ordinary_public_addresses_are_allowed(addr):
    assert netguard.is_forbidden_address(ipaddress.ip_address(addr)) is False, addr


def test_cgnat_was_the_gap_the_old_rule_left_open():
    """100.64.0.0/10 is not `is_private`, so the previous hand-rolled check —
    private/loopback/link-local/reserved/multicast — let it through. It is
    routable inside carrier and provider networks, which is precisely what makes
    it worth reaching."""
    ip = ipaddress.ip_address("100.64.0.1")
    old_rule = ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast
    assert old_rule is False, "documenting the old rule's blind spot"
    assert netguard.is_forbidden_address(ip) is True


def test_allow_private_targets_is_read_live_not_snapshotted(monkeypatch):
    """main.py cached this into a module constant at import while cli.py read it
    per call. A check that decides whether a packet leaves the machine must read
    the current setting, not the one that was true at import."""
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "false")
    assert netguard.private_targets_allowed() is False
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "true")
    assert netguard.private_targets_allowed() is True


def test_a_lab_exemption_still_works(monkeypatch):
    """`make bench-http` and local-lab use depend on this escape hatch."""
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "true")
    netguard.assert_public_host("localhost")  # must not raise


def test_a_non_http_target_is_refused():
    with pytest.raises(netguard.BlockedTarget):
        netguard.assert_public_target("file:///etc/passwd")


# ── per-hop scope ────────────────────────────────────────────────────────────

def test_a_redirect_out_of_scope_is_refused(monkeypatch):
    monkeypatch.setattr(netguard, "assert_public_host", lambda host: None)
    with pytest.raises(netguard.BlockedTarget, match="leaves the authorized scope"):
        netguard.check_redirect_hop(
            "https://acme.example/app.js",
            "https://cdn.thirdparty.net/app.js",
            enforce_scope=True,
        )


def test_apex_to_www_stays_in_scope(monkeypatch):
    """The single most common redirect on the internet must not be refused —
    a guard that breaks ordinary targets gets turned off, and then guards
    nothing."""
    monkeypatch.setattr(netguard, "assert_public_host", lambda host: None)
    netguard.check_redirect_hop(
        "https://acme.example/", "https://www.acme.example/", enforce_scope=True,
    )


def test_scope_is_judged_against_the_origin_not_the_previous_hop(monkeypatch):
    """Chaining scope hop-to-hop is the whole trick: A redirects to B (in scope
    for A), B redirects to C (in scope for B), and C is a host nobody
    authorized. Each hop is measured against the URL originally requested."""
    monkeypatch.setattr(netguard, "assert_public_host", lambda host: None)
    # b.acme.example is in scope for acme.example …
    netguard.check_redirect_hop(
        "https://acme.example/", "https://b.acme.example/", enforce_scope=True,
    )
    # … but a hop from there to evil.example is judged against acme.example.
    with pytest.raises(netguard.BlockedTarget, match="leaves the authorized scope"):
        netguard.check_redirect_hop(
            "https://acme.example/", "https://evil.example/", enforce_scope=True,
        )


def test_an_out_of_scope_host_is_refused_before_it_is_resolved(monkeypatch):
    """Resolving a host we have already decided not to contact tells a DNS
    server we were interested in it, and reports the refusal as a DNS failure
    rather than as the scope decision it actually was."""
    resolved: list[str] = []

    def _spy(host):
        resolved.append(host)
        return []

    monkeypatch.setattr(netguard, "resolve_host", _spy)
    with pytest.raises(netguard.BlockedTarget, match="leaves the authorized scope"):
        netguard.check_redirect_hop(
            "https://acme.example/", "https://cdn.thirdparty.net/x.js", enforce_scope=True,
        )
    assert resolved == [], "no lookup for a host the scope rule already refused"


def test_a_redirect_to_a_non_http_scheme_is_refused():
    with pytest.raises(netguard.BlockedTarget):
        netguard.check_redirect_hop(
            "https://acme.example/", "file:///etc/passwd", enforce_scope=False,
        )


# ── the chain, through fetch_url ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_fetch_url_returns_the_url_that_answered(monkeypatch):
    """Attribution. Before the fix this returned the URL requested, so a
    credential served by the redirect's destination was reported at the
    original location — and the remediation instruction pointed at the wrong
    system."""
    monkeypatch.setattr(netguard, "assert_public_host", lambda host: None)
    client = RedirectClient({"https://acme.example/a.js": "https://acme.example/b.js"})

    url, body = await scanner.fetch_url(client, "https://acme.example/a.js", asyncio.Semaphore(1))

    assert url == "https://acme.example/b.js", "the URL that answered, not the one requested"
    assert body == "ok"
    assert client.requested == ["https://acme.example/a.js", "https://acme.example/b.js"]


@pytest.mark.asyncio
async def test_a_redirect_into_private_space_is_never_requested(monkeypatch):
    """The SSRF. The refused hop must not merely be discarded after the fact —
    for an internal address, making the request *is* the harm, so the guard has
    to sit before the connection."""
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "false")
    client = RedirectClient(
        {"https://acme.example/": "http://169.254.169.254/latest/meta-data/"},
        body='{"AccessKeyId":"AKIAIOSFODNN7EXAMPLE"}',
    )

    url, body = await scanner.fetch_url(client, "https://acme.example/", asyncio.Semaphore(1))

    assert body is None, "the metadata response must never reach the scan"
    assert client.requested == ["https://acme.example/"], "the second hop was never sent"
    assert url == "https://acme.example/"


@pytest.mark.asyncio
async def test_a_refused_hop_is_logged_loudly(monkeypatch):
    """Refusing silently trades an SSRF for a coverage loss nothing reports, and
    a scan that quietly stopped reading still prints CLEAN. The operator is
    told."""
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "false")
    client = RedirectClient({"https://acme.example/": "http://127.0.0.1:9/"})
    events: list[dict] = []

    async def broadcast(evt):
        events.append(evt)

    await scanner.fetch_url(client, "https://acme.example/", asyncio.Semaphore(1), broadcast)

    errors = [e for e in events if e.get("level") == "ERROR"]
    assert errors, "a refused redirect must produce an ERROR log line"
    assert any("Refused to follow redirect" in e["message"] for e in errors)


@pytest.mark.asyncio
async def test_a_refused_hop_skips_the_asset_not_the_scan(monkeypatch):
    """One bad redirect on one bundle must not cost the whole engagement."""
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "false")
    client = RedirectClient({"https://acme.example/bad.js": "http://10.0.0.1/x.js"})

    # Returns normally rather than raising — the caller treats None as a skip.
    url, body = await scanner.fetch_url(client, "https://acme.example/bad.js", asyncio.Semaphore(1))
    assert body is None
    assert url == "https://acme.example/bad.js"


@pytest.mark.asyncio
async def test_a_redirect_loop_terminates(monkeypatch):
    monkeypatch.setattr(netguard, "assert_public_host", lambda host: None)
    client = RedirectClient({
        "https://acme.example/a": "https://acme.example/b",
        "https://acme.example/b": "https://acme.example/a",
    })

    _, body = await scanner.fetch_url(client, "https://acme.example/a", asyncio.Semaphore(1))

    assert body is None
    assert len(client.requested) <= netguard.MAX_REDIRECTS + 1, "the chain is bounded"


@pytest.mark.asyncio
async def test_a_redirect_status_with_no_location_is_not_a_redirect(monkeypatch):
    """A broken server, not a redirect. Fall through to ordinary status handling
    rather than crashing on the missing header."""
    monkeypatch.setattr(netguard, "assert_public_host", lambda host: None)

    class _Client:
        async def get(self, url, headers=None, **kw):
            return FakeResponse(302, "", {})

    url, body = await scanner.fetch_url(_Client(), "https://acme.example/", asyncio.Semaphore(1))
    assert url == "https://acme.example/"


@pytest.mark.asyncio
async def test_a_relative_location_resolves_against_the_current_hop(monkeypatch):
    monkeypatch.setattr(netguard, "assert_public_host", lambda host: None)
    client = RedirectClient({"https://acme.example/en/": "app/index.html"})

    url, _ = await scanner.fetch_url(client, "https://acme.example/en/", asyncio.Semaphore(1))
    assert url == "https://acme.example/en/app/index.html"


# ── the cache must survive the new keying ────────────────────────────────────

@pytest.mark.asyncio
async def test_a_redirected_asset_with_a_finding_is_still_marked_dirty(monkeypatch):
    """The cache is keyed on the URL requested (stable across scans), but
    callers now hold the URL that answered, so `mark_asset_dirty` is called with
    the latter. Without the alias map it would find no entry and mark nothing —
    and next scan's 304 would skip an asset that holds a live credential, so the
    finding would vanish from the report and read as 'resolved'."""
    monkeypatch.setattr(netguard, "assert_public_host", lambda host: None)
    client = RedirectClient({"https://acme.example/a.js": "https://acme.example/b.js"})
    client.chain_headers = None

    scanner.load_asset_cache({})
    try:
        # Serve an ETag on the final hop so a cache entry is actually recorded.
        async def get(url, headers=None, **kw):
            client.requested.append(url)
            if url in client.chain:
                return FakeResponse(302, "", {"location": client.chain[url]})
            return FakeResponse(200, "body", {"etag": '"v1"', "content-type": "text/javascript"})

        client.get = get
        final_url, _ = await scanner.fetch_url(
            client, "https://acme.example/a.js", asyncio.Semaphore(1)
        )
        assert final_url == "https://acme.example/b.js"

        # The scan loop marks dirty using the URL it holds — the final one.
        scanner.mark_asset_dirty(final_url)

        out = scanner.drain_asset_cache()
        assert "https://acme.example/a.js" in out, "cache stays keyed on the requested URL"
        assert out["https://acme.example/a.js"]["was_clean"] is False, (
            "the finding must survive into the next scan's cache decision"
        )
    finally:
        scanner.load_asset_cache({})


# ── content-length robustness ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_a_malformed_content_length_does_not_drop_the_asset(monkeypatch):
    """`int(headers.get("content-length", 0))` raised ValueError on the
    duplicated form some proxies emit ("512, 512"). The catch-all handler turned
    that into a silent asset drop with no retry — an unread asset is an
    unscanned asset, and the scan still reported CLEAN."""
    monkeypatch.setattr(netguard, "assert_public_host", lambda host: None)

    class _Client:
        async def get(self, url, headers=None, **kw):
            return FakeResponse(
                200, 'const k = "x";',
                {"content-length": "512, 512", "content-type": "application/javascript"},
            )

    _, body = await scanner.fetch_url(_Client(), "https://acme.example/a.js", asyncio.Semaphore(1))
    assert body == 'const k = "x";', "the asset is still read"


# ── the client must not be quietly following redirects itself ────────────────

def test_the_http_client_does_not_follow_redirects_on_its_own():
    """The guard only works if httpx hands the 3xx back instead of chasing it.
    If someone re-enables follow_redirects, every test above still passes while
    the hole reopens — httpx would resolve the chain internally and `fetch_url`
    would simply never see a 3xx. This is the test that fails instead."""
    client = scanner.build_client()
    try:
        assert client.follow_redirects is False
    finally:
        asyncio.run(client.aclose())
