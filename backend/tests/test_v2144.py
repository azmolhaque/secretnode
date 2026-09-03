"""
v2.14.4 — two defects found by reading four live deep scans of intentionally
vulnerable targets (vulnweb.com, nmap.org, badssl.com, testfire.net) next to the
code that produced them.

The first is a coverage lie. nmap.org's report said CLEAN across 5 of 5 hosts.
One of those five, issues.nmap.org, redirected to github.com — out of scope, so
the redirect was refused and its root document was never fetched. The spider
logged that and returned an empty asset list; the scan then completed
"successfully" with zero assets, and the per-host table rendered `scanned` with
no note. Worse, the coverage verdict counts only hosts carrying an `error`, so
it could not hedge to PARTIAL either.

The root cause was wider than that one host: `run_scan` reports failure through
`status` and `errors` (plural), while `_summarise_scan` read `scan["error"]` —
a key `run_scan` never sets. EVERY single-target failure, including a fatal
spider crash, arrived in the deep-scan table as `scanned`.

The second is host selection. The cap is a prefix slice of an alphabetically
sorted candidate list, which is the worst ordering under wildcard DNS: whatever
sorts first takes the whole budget. badssl.com survived it by luck — its
generated `wowmoarhost*` fleet sorts last — but a fleet that sorts first takes
every slot and the real hosts are never read.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import orchestrator
import report as report_gen
import scanner


# ─────────────────────────────────────────────────────────────────────────────
# 1 · A host that was never read must not report as `scanned`
# ─────────────────────────────────────────────────────────────────────────────

class TestScanFailureReachesTheHostTable:
    def test_a_failed_scan_is_an_error_not_a_clean_host(self):
        """The exact shape run_scan returns when the spider cannot get the root."""
        scan = {"status": "failed", "errors": ["could not fetch the target root"],
                "assets_fetched": 0}
        hs = orchestrator._summarise_scan("issues.nmap.org",
                                          "https://issues.nmap.org", scan)
        assert hs.error is not None
        assert "could not fetch the target root" in hs.error

    def test_a_cancelled_scan_is_also_not_clean(self):
        hs = orchestrator._summarise_scan(
            "a.test", "https://a.test", {"status": "cancelled", "assets_fetched": 0})
        assert hs.error is not None

    def test_a_completed_scan_with_nothing_in_it_stays_clean(self):
        """Zero assets is not by itself a failure — a host can genuinely serve a
        page with no scripts. Only the scan's own verdict decides."""
        hs = orchestrator._summarise_scan(
            "b.test", "https://b.test", {"status": "complete", "assets_fetched": 0})
        assert hs.error is None

    def test_a_directly_set_error_still_wins(self):
        """`_scan_host` sets `error` when the scan call raises — something
        status/errors cannot describe."""
        hs = orchestrator._summarise_scan(
            "c.test", "https://c.test", {"error": "ConnectError: dead"})
        assert hs.error == "ConnectError: dead"

    def test_the_failure_reason_survives_into_the_report(self):
        deep = _deep_with_hosts([
            {"host": "nmap.org", "url": "https://nmap.org", "assets": 6, "confirmed": 0,
             "needs_review": 0, "informational": 0, "posture_issues": 6,
             "error": None, "status": "", "note": ""},
            {"host": "issues.nmap.org", "url": "https://issues.nmap.org", "assets": 0,
             "confirmed": 0, "needs_review": 0, "informational": 0, "posture_issues": 0,
             "error": "failed: could not fetch the target root", "status": "", "note": ""},
        ], live_total=2)
        html = report_gen.generate_deep_scan_html(deep)
        assert "could not fetch the target root" in html
        assert '<span class="err">error</span>' in html

    def test_an_unread_host_hedges_the_verdict_to_partial(self):
        """This is the point of the fix. While the failure was invisible the
        verdict could only ever say CLEAN — it counts hosts carrying an error,
        and this host carried none."""
        deep = _deep_with_hosts([
            {"host": "nmap.org", "url": "https://nmap.org", "assets": 6, "confirmed": 0,
             "needs_review": 0, "informational": 0, "posture_issues": 6,
             "error": None, "status": "", "note": ""},
            {"host": "issues.nmap.org", "url": "https://issues.nmap.org", "assets": 0,
             "confirmed": 0, "needs_review": 0, "informational": 0, "posture_issues": 0,
             "error": "failed: could not fetch the target root", "status": "", "note": ""},
        ], live_total=2)
        html = report_gen.generate_deep_scan_html(deep)
        assert "PARTIAL" in html


class TestUnreachableRootIsRaised:
    def test_the_exception_type_exists_and_is_catchable(self):
        assert issubclass(scanner.RootUnreachable, RuntimeError)


def _deep_with_hosts(hosts: list[dict], live_total: int) -> dict:
    return {
        "domain": "nmap.org", "scan_id": "d-1",
        "generated_at": "2026-09-03T20:08:32+00:00",
        "subdomains": [h["host"] for h in hosts],
        "live_hosts": [h["host"] for h in hosts],
        "hosts": hosts,
        "totals": {"confirmed": 0, "needs_review": 0, "informational": 0,
                   "posture_issues": 0, "assets": 6, "live_hosts": live_total},
        "confirmed_findings": [], "needs_review_findings": [],
        "informational_findings": [], "posture_findings": [], "takeovers": [],
        "historical_urls": 0, "external_hosts": [],
    }


# ─────────────────────────────────────────────────────────────────────────────
# 2 · The host budget must not be swallowed by a generated fleet
# ─────────────────────────────────────────────────────────────────────────────

FLEET = [f"https://aaa{n}.acme.com" for n in range(1000, 1400)]
DISTINCT = ["https://acme.com", "https://api.acme.com", "https://admin.acme.com",
            "https://staging.acme.com", "https://vpn.acme.com"]


class TestPrioritiseHosts:
    def test_a_fleet_that_sorts_first_no_longer_takes_every_slot(self):
        """Sorted alphabetically, `aaa1000…` fills the whole cap and not one
        real host is ever read."""
        urls = sorted(FLEET + DISTINCT)
        assert [u for u in urls[:25] if "aaa" not in u] == []
        got = orchestrator.prioritise_hosts(urls, "acme.com")[:25]
        assert sorted(u for u in got if "aaa" not in u) == sorted(DISTINCT)

    def test_the_apex_is_read_first(self):
        urls = sorted(FLEET + DISTINCT)
        assert orchestrator.prioritise_hosts(urls, "acme.com")[0] == "https://acme.com"

    def test_the_fleet_is_sampled_not_dropped(self):
        """A generated fleet is worth looking at — one of them may serve
        something the others do not. Representatives stay in the priority band."""
        urls = sorted(FLEET + DISTINCT)
        got = orchestrator.prioritise_hosts(urls, "acme.com")
        # DISTINCT already contains the apex, so it is not a separate slot.
        head = got[:len(DISTINCT) + orchestrator.FAMILY_KEEP]
        assert len([u for u in head if "aaa" in u]) == orchestrator.FAMILY_KEEP

    def test_nothing_is_lost_only_reordered(self):
        """The cap decides what is read; this decides the order. A run whose cap
        exceeds the candidate count must still reach every host."""
        urls = sorted(FLEET + DISTINCT)
        assert sorted(orchestrator.prioritise_hosts(urls, "acme.com")) == sorted(urls)

    def test_a_small_group_of_numbered_hosts_is_not_a_fleet(self):
        """`web1`/`web2`/`web3` are three real servers, not wildcard noise."""
        urls = ["https://acme.com", "https://web1.acme.com",
                "https://web2.acme.com", "https://web3.acme.com"]
        assert orchestrator.prioritise_hosts(urls, "acme.com") == urls

    def test_ordering_is_stable_and_deterministic(self):
        urls = sorted(FLEET + DISTINCT)
        assert orchestrator.prioritise_hosts(urls, "acme.com") == \
               orchestrator.prioritise_hosts(urls, "acme.com")

    def test_badssl_shape_is_unchanged_because_it_was_already_lucky(self):
        """Honest negative result: badssl's fleet sorts LAST, so the alphabetical
        slice already reached all six distinct hosts. This fix did not rescue
        that scan — it removes the luck."""
        fleet = [f"https://wowmoarhost{n}.badssl.com" for n in range(1000, 1440)]
        distinct = ["https://badssl.com", "https://10000-sans.badssl.com",
                    "https://revoked.badssl.com", "https://rsa8192.badssl.com",
                    "https://sha1-2016.badssl.com"]
        urls = sorted(fleet + distinct)
        n_before = len([u for u in urls[:25] if "wowmoar" not in u])
        after = orchestrator.prioritise_hosts(urls, "badssl.com")[:25]
        assert len([u for u in after if "wowmoar" not in u]) == n_before == len(distinct)

    def test_an_empty_candidate_list_is_handled(self):
        assert orchestrator.prioritise_hosts([], "acme.com") == []
