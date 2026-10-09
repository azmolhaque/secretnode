"""
v2.18.0 — how long has this credential been public?

SecretNode has pulled archived bundles from the Wayback CDX index since v2.9.
It asked that index for `fl=original` — the URL field alone — and threw away the
timestamp that comes back free on every row. Three releases scanned archived
assets while discarding the only thing in the whole scanner that can date them.

The question matters because it changes the answer. A credential in a 2021
bundle AND in today's has been readable by anyone for five years, so the advice
is not "rotate" but "rotate and assume it was used". One present only in the
archive was already fixed — which is good news, and good news is something this
report has never had a way to deliver.

No literal credential appears in this file; values are assembled at runtime.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import date

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import pytest  # noqa: E402

import historical  # noqa: E402
import orchestrator  # noqa: E402
import report  # noqa: E402

TODAY = date(2026, 10, 9)
ARCHIVED = "https://acme.test/static/old.bundle.js"
LIVE = "https://acme.test/static/app.js"


# ── Recovering the timestamp ─────────────────────────────────────────────

class TestCdxTimestamps:
    def test_the_query_asks_for_the_timestamp(self):
        """The whole defect was one missing field name in one URL."""
        import inspect
        src = inspect.getsource(historical.fetch_wayback)
        assert "fl=original,timestamp" in src

    def test_the_parser_returns_the_earliest_capture_per_url(self):
        payload = json.dumps([
            ["original", "timestamp"],
            ["https://acme.test/app.js", "20240101000000"],
            ["https://acme.test/app.js", "20210314071233"],   # earlier
            ["https://acme.test/old.js", "20190622120000"],
        ])
        urls, dates = historical.parse_wayback_cdx(payload, "acme.test", with_dates=True)
        assert urls == ["https://acme.test/app.js", "https://acme.test/old.js"]
        assert dates["https://acme.test/app.js"] == "2021-03-14"
        assert dates["https://acme.test/old.js"] == "2019-06-22"

    def test_out_of_scope_rows_contribute_no_dates(self):
        payload = json.dumps([
            ["original", "timestamp"],
            ["https://evil.test/x.js", "20200101000000"],
        ])
        urls, dates = historical.parse_wayback_cdx(payload, "acme.test", with_dates=True)
        assert urls == [] and dates == {}

    def test_the_bare_list_return_is_unchanged_for_existing_callers(self):
        payload = json.dumps([["original", "timestamp"],
                              ["https://acme.test/a.js", "20210314071233"]])
        assert historical.parse_wayback_cdx(payload, "acme.test") == [
            "https://acme.test/a.js"]

    @pytest.mark.parametrize("stamp,expected", [
        ("20210314071233", "2021-03-14"),
        ("20210314", "2021-03-14"),
        ("2021", None),
        ("20213401000000", None),      # month 34
        ("", None),
        ("notadate000000", None),
    ])
    def test_timestamp_parsing_refuses_what_it_cannot_read(self, stamp, expected):
        assert historical._cdx_date(stamp) == expected


# ── Turning a date into a verdict ────────────────────────────────────────

class TestExposureWindow:
    def test_still_served_says_assume_use_not_merely_rotate(self):
        w = historical.exposure_window("2021-03-14", still_served=True, today=TODAY)
        assert w.days == 2035 and w.still_served
        assert "5.6 years" in w.verdict
        assert "as used rather than merely exposed" in w.advice
        assert "audit log" in w.advice

    def test_archive_only_is_reported_as_good_news(self):
        w = historical.exposure_window("2019-06-22", still_served=False, today=TODAY)
        assert not w.still_served
        assert "NOT" in w.verdict and "removed or rotated" in w.verdict
        assert "No action needed on the live asset" in w.advice

    def test_archive_only_still_warns_that_deleting_is_not_revoking(self):
        """The trap in the good-news case: a secret removed from a bundle is
        still live until someone revokes it, and the archived copy stays
        readable forever."""
        w = historical.exposure_window("2019-06-22", still_served=False, today=TODAY)
        assert "does not" in w.advice and "revoke" in w.advice

    @pytest.mark.parametrize("first_seen,expected", [
        ("2026-10-09", "under a day"),
        ("2026-09-20", "19 days"),
        ("2026-04-01", "6 months"),
        ("2021-03-14", "5.6 years"),
    ])
    def test_spans_are_phrased_at_the_scale_a_reader_needs(self, first_seen, expected):
        w = historical.exposure_window(first_seen, still_served=True, today=TODAY)
        assert expected in w.verdict

    @pytest.mark.parametrize("bad", ["2030-01-01", "not-a-date", "", "2021-13-45"])
    def test_an_unusable_date_produces_no_claim_at_all(self, bad):
        """Clock skew or a malformed row must not become a confident statement
        about a time window."""
        assert historical.exposure_window(bad, still_served=True, today=TODAY) is None


# ── Attaching it to the credential, not the asset ────────────────────────

def _finding(fingerprint: str, source_url: str, secret_type: str = "AWS Access Key") -> dict:
    return {
        "fingerprint": fingerprint, "source_url": source_url,
        "secret_type": secret_type, "severity": "CRITICAL",
        "raw_match": "AKIA****", "cwe": "CWE-798", "confidence": 95,
        "impact": "Full API access as this identity.", "reason": "structural match",
        "found_at": "2026-10-09T00:00:00Z", "is_new": True, "verified": "disabled",
    }


def _result(findings: list[dict], archived: dict[str, str] | None = None):
    r = orchestrator.DeepScanResult(domain="acme.test")
    r.archive_first_seen = archived if archived is not None else {ARCHIVED: "2021-03-14"}
    r.scans = [{
        "target_url": "https://acme.test",
        "confirmed_findings": findings,
        "needs_review_findings": [], "informational_findings": [], "posture_findings": [],
    }]
    return r


class TestExposureIsAPropertyOfTheCredential:
    def test_a_key_in_both_the_archive_and_the_live_bundle_is_still_served(self):
        d = _result([_finding("fp1", ARCHIVED), _finding("fp1", LIVE)]).to_dict()
        windows = [f["exposure"] for f in d["confirmed_findings"]]
        assert len(windows) == 2
        assert all(w["still_served"] for w in windows)

    def test_the_window_attaches_to_every_copy_of_the_same_credential(self):
        """Keyed on fingerprint, not source URL: the same key found live and in
        the archive has one exposure history, and both rows should say so."""
        d = _result([_finding("fp1", ARCHIVED), _finding("fp1", LIVE)]).to_dict()
        assert {f["exposure"]["first_seen"] for f in d["confirmed_findings"]} == {"2021-03-14"}

    def test_a_key_only_in_the_archive_is_not_still_served(self):
        d = _result([_finding("fp2", ARCHIVED)]).to_dict()
        assert d["confirmed_findings"][0]["exposure"]["still_served"] is False

    def test_a_key_only_in_the_live_bundle_carries_no_window(self):
        """The archive has nothing to say about it, so the report says nothing
        rather than implying the exposure began today."""
        d = _result([_finding("fp3", LIVE)]).to_dict()
        assert "exposure" not in d["confirmed_findings"][0]

    def test_no_archive_data_means_no_windows_anywhere(self):
        d = _result([_finding("fp1", ARCHIVED)], archived={}).to_dict()
        assert all("exposure" not in f for f in d["confirmed_findings"])

    def test_the_earliest_capture_wins_across_hosts(self):
        r = _result([_finding("fp1", ARCHIVED)])
        other = "https://cdn.acme.test/old.js"
        r.archive_first_seen[other] = "2018-01-02"
        r.scans.append({
            "target_url": "https://cdn.acme.test",
            "confirmed_findings": [_finding("fp1", other)],
            "needs_review_findings": [], "informational_findings": [], "posture_findings": [],
        })
        d = r.to_dict()
        assert {f["exposure"]["first_seen"] for f in d["confirmed_findings"]} == {"2018-01-02"}


# ── Reaching the deliverables ────────────────────────────────────────────

class TestEveryDeliverableCarriesIt:
    """A finding computed correctly and rendered nowhere is the defect v2.14.3
    shipped a whole release to fix. Each export is checked, not assumed."""

    def test_csv_appends_three_columns_without_moving_the_others(self):
        d = _result([_finding("fp1", ARCHIVED), _finding("fp1", LIVE)]).to_dict()
        rows = report.generate_csv_report(d).splitlines()
        header = rows[0].split(",")
        assert header[:4] == ["status", "severity", "cwe", "secret_type"]
        assert header[-3:] == ["exposed_since", "exposed_days", "still_served"]
        assert rows[1].split(",")[-3:] == ["2021-03-14", "2035", "YES"]

    def test_csv_leaves_the_columns_blank_when_the_archive_cannot_date_it(self):
        d = _result([_finding("fp3", LIVE)]).to_dict()
        assert report.generate_csv_report(d).splitlines()[1].split(",")[-3:] == ["", "", ""]

    def test_sarif_carries_it_in_result_properties(self):
        d = _result([_finding("fp1", ARCHIVED)]).to_dict()
        sarif = json.loads(report.generate_sarif_report(d))
        props = sarif["runs"][0]["results"][0]["properties"]
        assert props["exposure"]["first_seen"] == "2021-03-14"

    def test_sarif_omits_the_key_entirely_when_there_is_no_window(self):
        d = _result([_finding("fp3", LIVE)]).to_dict()
        sarif = json.loads(report.generate_sarif_report(d))
        assert "exposure" not in sarif["runs"][0]["results"][0]["properties"]

    def test_the_html_badges_the_two_cases_apart(self):
        d = _result([_finding("fp1", ARCHIVED), _finding("fp1", LIVE),
                     _finding("fp2", ARCHIVED, "Stripe Secret Key")]).to_dict()
        page = report.generate_deep_scan_html(d)
        assert "EXPOSED 2021-03-14" in page
        assert "ARCHIVE ONLY" in page
        assert "Public since at least 2021-03-14" in page
        assert "appears to have been removed or rotated" in page

    def test_the_html_escapes_what_it_renders(self):
        r = _result([_finding("fp1", ARCHIVED)])
        r.scans[0]["confirmed_findings"][0]["exposure"] = None
        d = r.to_dict()
        d["confirmed_findings"][0]["exposure"] = {
            "first_seen": "<script>alert(1)</script>", "days": 1,
            "still_served": True, "verdict": "<b>x</b>", "advice": "<i>y</i>",
        }
        page = report.generate_deep_scan_html(d)
        assert "<script>alert(1)</script>" not in page
        assert "&lt;script&gt;" in page
