"""
v2.13.2 — two defects a second live deep scan exposed, both reproduced against
the real pipeline before being fixed.

The first is mine, introduced by v2.13.0: making the client stop following
redirects (so every hop could be address-checked) silently changed what the
posture check measures. It now analysed the 301, not the page behind it. On a
lab server whose landing page sets six headers and whose redirect hop sets none,
it reported five missing headers for a page that has them all.

The second is older: `www.example.com` 301-ing to `example.com` looked like two
independent live hosts, so the deep scan crawled the same site twice — eleven
requests for four unique paths in the lab, and a client report claiming double
the coverage it had.
"""

from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import orchestrator
import posture
import report as report_gen


# ─────────────────────────────────────────────────────────────────────────────
# 1 · Posture must measure the landing page, not the redirect that points at it
# ─────────────────────────────────────────────────────────────────────────────

SECURE = {
    "Strict-Transport-Security": "max-age=31536000",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=()",
}


class _Resp:
    def __init__(self, headers, url):
        self.headers = headers
        self.url = url


class TestPostureFollowsRedirects:
    """A redirect hop is not the site. Cloudflare-style edges apply header rules
    to redirects too, which is why this agreed by luck on the first real target
    and stayed invisible."""

    def test_bare_get_measures_the_redirect_hop(self):
        """Documents the defect: with no `get_final`, whatever answers first is
        what gets analysed — a bare 301 here."""
        async def go():
            class C:
                async def get(self, url, **kw):
                    return _Resp({}, url)          # the 301: no security headers
            return await posture.fetch_posture(C(), "https://www.acme.test/")

        findings = asyncio.run(go())
        assert len(findings) >= 5

    def test_injected_walk_measures_the_landing_page(self):
        async def go():
            async def get_final(client, url, headers):
                return _Resp(SECURE, "https://acme.test/"), "https://acme.test/"
            return await posture.fetch_posture(
                object(), "https://www.acme.test/", get_final=get_final)

        assert asyncio.run(go()) == []

    def test_the_final_url_decides_https_only_checks(self):
        """HSTS is only meaningful on an HTTPS response, so the scheme must come
        from where the chain ended, not where it started."""
        async def go():
            async def get_final(client, url, headers):
                # http:// start, https:// landing, no HSTS on the landing page
                landed = dict(SECURE)
                landed.pop("Strict-Transport-Security")
                return _Resp(landed, "https://acme.test/"), "https://acme.test/"
            return await posture.fetch_posture(
                object(), "http://acme.test/", get_final=get_final)

        names = [f.name for f in asyncio.run(go())]
        assert "Missing HSTS" in names

    def test_a_refused_hop_yields_no_findings_rather_than_raising(self):
        """A redirect into internal space is refused by the walk. Posture is
        best-effort and must never sink a scan."""
        async def go():
            async def get_final(client, url, headers):
                raise RuntimeError("blocked: redirect to a private address")
            return await posture.fetch_posture(
                object(), "https://acme.test/", get_final=get_final)

        assert asyncio.run(go()) == []


# ─────────────────────────────────────────────────────────────────────────────
# 2 · One site must not be scanned twice
# ─────────────────────────────────────────────────────────────────────────────

class TestCollapseRedirectDuplicates:
    def test_www_redirecting_to_apex_is_collapsed(self):
        probed = [("https://acme.test", ""), ("https://www.acme.test", "acme.test")]
        targets, collapsed = orchestrator.collapse_redirect_duplicates(probed)
        assert targets == ["https://acme.test"]
        assert collapsed == [("www.acme.test", "acme.test")]

    def test_order_does_not_change_the_outcome(self):
        """The apex may be probed after the www that points at it."""
        probed = [("https://www.acme.test", "acme.test"), ("https://acme.test", "")]
        targets, collapsed = orchestrator.collapse_redirect_duplicates(probed)
        assert targets == ["https://acme.test"]
        assert collapsed == [("www.acme.test", "acme.test")]

    def test_a_redirect_leaving_the_scanned_set_is_still_scanned(self):
        """Dropping it would lose coverage: that redirect may be the only route
        to content nothing else reaches."""
        probed = [("https://acme.test", ""), ("https://shop.acme.test", "cdn.vendor.test")]
        targets, collapsed = orchestrator.collapse_redirect_duplicates(probed)
        assert targets == ["https://acme.test", "https://shop.acme.test"]
        assert collapsed == []

    def test_hosts_answering_directly_are_untouched(self):
        probed = [("https://a.acme.test", ""), ("https://b.acme.test", "")]
        targets, collapsed = orchestrator.collapse_redirect_duplicates(probed)
        assert len(targets) == 2
        assert collapsed == []

    def test_a_self_redirect_is_not_a_duplicate(self):
        """http -> https on the same host is one host, not two."""
        probed = [("https://acme.test", "acme.test")]
        targets, collapsed = orchestrator.collapse_redirect_duplicates(probed)
        assert targets == ["https://acme.test"]
        assert collapsed == []

    def test_a_mutual_redirect_loop_still_scans_something(self):
        """If every host collapsed there would be nothing left. Duplicate work
        beats a scan that reads nothing and still prints a verdict."""
        probed = [("https://a.acme.test", "b.acme.test"),
                  ("https://b.acme.test", "a.acme.test")]
        targets, collapsed = orchestrator.collapse_redirect_duplicates(probed)
        assert len(targets) == 2
        assert collapsed == []


class TestCollapsedHostIsReportedNotHidden:
    def deep(self, host_entries: list[dict]) -> dict:
        return {
            "domain": "acme.test", "scan_id": "d-1",
            "generated_at": "2026-08-21T18:08:17+00:00",
            "subdomains": ["acme.test", "www.acme.test"],
            "live_hosts": ["acme.test", "www.acme.test"],
            "hosts": host_entries,
            "totals": {"confirmed": 0, "needs_review": 0, "posture_issues": 0,
                       "assets": 3, "live_hosts": 2},
            "confirmed_findings": [], "needs_review_findings": [],
            "posture_findings": [], "takeovers": [],
            "historical_urls": [], "external_hosts": [],
        }

    SCANNED = {"host": "acme.test", "url": "https://acme.test", "assets": 3,
               "confirmed": 0, "needs_review": 0, "posture_issues": 0,
               "error": None, "status": "", "note": ""}
    COLLAPSED = {"host": "www.acme.test", "url": "https://www.acme.test", "assets": 0,
                 "confirmed": 0, "needs_review": 0, "posture_issues": 0,
                 "error": None, "status": "redirect",
                 "note": "redirects to acme.test — that site was scanned, not this alias"}

    def test_the_collapsed_host_still_appears_with_its_reason(self):
        """A host missing from the table with no explanation is indistinguishable
        from one the scan failed to reach."""
        html = report_gen.generate_deep_scan_html(self.deep([self.SCANNED, self.COLLAPSED]))
        assert "www.acme.test" in html
        assert "redirects to acme.test" in html

    def test_it_is_not_rendered_as_an_error(self):
        html = report_gen.generate_deep_scan_html(self.deep([self.SCANNED, self.COLLAPSED]))
        assert '<span class="err">error</span>' not in html
        assert "redirect" in html

    def test_it_does_not_hedge_the_verdict_to_partial(self):
        """Its content WAS scanned, at the host it points to. Counting it as
        unexamined is the mirror image of the overstatement PARTIAL exists to
        prevent."""
        html = report_gen.generate_deep_scan_html(self.deep([self.SCANNED, self.COLLAPSED]))
        assert "PARTIAL" not in html
        assert "CLEAN" in html

    def test_a_genuinely_failed_host_still_reads_as_an_error(self):
        failed = {**self.SCANNED, "host": "dead.acme.test",
                  "error": "skipped: resolves to a private/internal address (SSRF guard)"}
        html = report_gen.generate_deep_scan_html(self.deep([self.SCANNED, failed]))
        assert '<span class="err">error</span>' in html
        assert "SSRF guard" in html


class TestProbeCapturesRedirectTarget:
    """The probe is the only place that sees the 301: since v2.13.0 the shared
    client does not follow redirects, so it arrives here intact."""

    class _R:
        def __init__(self, status, location=""):
            self.status_code = status
            self.headers = {"location": location} if location else {}

    def _client(self, responses: dict):
        outer = self

        class C:
            async def get(self, url, **kw):
                if url not in responses:
                    import httpx
                    raise httpx.ConnectError("dead")
                return outer._R(*responses[url])
        return C()

    def test_a_direct_answer_reports_no_redirect(self):
        c = self._client({"https://acme.test": (200,)})
        got = asyncio.run(orchestrator._probe_one(c, "acme.test"))
        assert got == ("https://acme.test", "")

    def test_a_redirect_reports_its_destination_host(self):
        c = self._client({"https://www.acme.test": (301, "https://acme.test/")})
        got = asyncio.run(orchestrator._probe_one(c, "www.acme.test"))
        assert got == ("https://www.acme.test", "acme.test")

    def test_a_relative_location_resolves_against_the_probed_url(self):
        c = self._client({"https://acme.test": (302, "/en/")})
        got = asyncio.run(orchestrator._probe_one(c, "acme.test"))
        assert got == ("https://acme.test", "acme.test")

    def test_an_unreachable_host_is_still_none(self):
        assert asyncio.run(orchestrator._probe_one(self._client({}), "dead.acme.test")) is None

    def test_the_plain_wrapper_still_returns_bare_urls(self):
        """`probe_live_hosts` keeps its old contract for existing callers."""
        c = self._client({"https://acme.test": (200,)})
        live = asyncio.run(orchestrator.probe_live_hosts(c, ["acme.test", "dead.acme.test"]))
        assert live == ["https://acme.test"]
