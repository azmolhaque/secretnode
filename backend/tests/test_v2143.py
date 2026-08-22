"""
v2.14.3 — a public-by-design finding reached no deep-scan deliverable.

Found by reading a real deep scan of an authorized bug-bounty target next to
the bundle it read. `mtw-pwa-test.telenor.se/js/index.js` ships a Firebase web
config in plain sight — `apiKey:"AIzaSy…"` immediately beside `authDomain`,
`projectId`, `storageBucket` and `appId`. The detector matched it, the offline
triage tier correctly called it public-by-design at INFO, and then the CSV, the
SARIF and the HTML all showed nothing at all.

The cause was one missing line: `DeepScanResult.to_dict()` aggregated
`confirmed_findings`, `needs_review_findings` and `posture_findings` and not
`informational_findings`. Every reporter already knew how to render that bucket
— they were simply never handed it.

This is the same defect class v2.13.0 fixed one level down, where public-by-design
findings were *deleted* rather than reported. The argument is unchanged and is the
whole reason the bucket exists: an absent finding and an examined-and-cleared one
look identical to the reader, and only one of them is true. A client who greps a
report for their own Firebase key and finds nothing learns that the scanner missed
it — which is the opposite of what happened.

The second defect here is the SARIF disagreeing with the CSV about the same
finding: one `is_review` flag served both "needs review" and "public by design",
so the SARIF told readers "Manual review required" and set
`properties.status = needs_review` on a value that needs no action, while the CSV
called it INFORMATIONAL.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import orchestrator
import report as report_gen
import scanner

# The real config shape from the bundle, with a key of the same form. The
# adjacency is the whole discriminator — an `AIza…` on its own is not
# identifiable as a web key, which is why the proximity matters here.
FIREBASE_BUNDLE = (
    'const cfg={apiKey:"AIzaSyCjFeYsl3rpaFFGbgYh_JAmft-U5FW0O-o",'
    'authDomain:"my-telenor-pwa-e5912.firebaseapp.com",'
    'projectId:"my-telenor-pwa-e5912",'
    'storageBucket:"my-telenor-pwa-e5912.appspot.com",'
    'messagingSenderId:"438396965410",'
    'appId:"1:438396965410:web:abc123def456"};'
)
SRC = "https://mtw-pwa-test.telenor.se/js/index.js"
TGT = "https://mtw-pwa-test.telenor.se"


def _informational_finding() -> dict:
    """Drive the real pipeline rather than hand-building a dict: the point of
    this test is that detection and triage already worked, so a fixture that
    skipped them would prove nothing about where the finding was lost."""
    raw = scanner.extract_secrets("s1", TGT, SRC, FIREBASE_BUNDLE)
    google = [r for r in raw if r.secret_type == "Google Cloud API Key"]
    assert google, "the detector must still match a Firebase web apiKey"
    vf = scanner._ai_skipped(google[0], "AI validation unavailable.")
    assert vf.public_by_design is True
    assert vf.effective_severity() == "INFO"
    assert scanner.classify_validated(vf) == "informational"
    return vf.to_dict()


def _deep(host_scan: dict) -> dict:
    return orchestrator.DeepScanResult(
        domain="telenor.se",
        subdomains=["mtw-pwa-test.telenor.se"],
        live_hosts=["mtw-pwa-test.telenor.se"],
        hosts=[orchestrator._summarise_scan(
            "mtw-pwa-test.telenor.se", TGT, host_scan)],
        scans=[host_scan],
    ).to_dict()


def _one_info_host() -> dict:
    return _deep({
        "target_url": TGT,
        "confirmed_findings": [], "needs_review_findings": [],
        "informational_findings": [_informational_finding()],
        "posture_findings": [], "assets_fetched": 12,
    })


class TestDeepScanCarriesInformationalFindings:
    def test_the_finding_survives_aggregation(self):
        deep = _one_info_host()
        assert len(deep["informational_findings"]) == 1
        assert deep["informational_findings"][0]["secret_type"] == "Google Cloud API Key"

    def test_it_is_tagged_with_the_host_that_served_it(self):
        """Provenance is what makes a domain-wide list actionable — the same
        contract the other three buckets already have."""
        deep = _one_info_host()
        assert deep["informational_findings"][0]["_host"] == "mtw-pwa-test.telenor.se"

    def test_the_domain_total_counts_it(self):
        assert _one_info_host()["totals"]["informational"] == 1

    def test_the_per_host_row_counts_it(self):
        assert _one_info_host()["hosts"][0]["informational"] == 1

    def test_a_host_with_none_reports_zero_rather_than_omitting_the_key(self):
        deep = _deep({"target_url": TGT, "confirmed_findings": [],
                      "needs_review_findings": [], "informational_findings": [],
                      "posture_findings": [], "assets_fetched": 3})
        assert deep["hosts"][0]["informational"] == 0
        assert deep["totals"]["informational"] == 0
        assert deep["informational_findings"] == []


class TestEveryDeliverableShowsIt:
    """Three deliverables are built from one scan. Any of them silently omitting
    a bucket the others carry is worse than all of them omitting it, because each
    looks authoritative read alone."""

    def test_csv_carries_it_as_informational(self):
        rows = [r for r in report_gen.generate_csv_report(_one_info_host()).splitlines()
                if "Google Cloud API Key" in r]
        assert len(rows) == 1
        assert rows[0].startswith("INFORMATIONAL,INFO,")

    def test_sarif_carries_it_at_note_level(self):
        sarif = json.loads(report_gen.generate_sarif_report(_one_info_host()))
        hits = [r for r in sarif["runs"][0]["results"]
                if r["ruleId"] == "secretnode/google-cloud-api-key"]
        assert len(hits) == 1
        # `note` is deliberate: a pipeline that goes red on a publishable key is
        # a pipeline someone disables, and then the AWS key goes unnoticed too.
        assert hits[0]["level"] == "note"

    def test_sarif_does_not_call_it_needs_review(self):
        sarif = json.loads(report_gen.generate_sarif_report(_one_info_host()))
        hit = [r for r in sarif["runs"][0]["results"]
               if r["ruleId"] == "secretnode/google-cloud-api-key"][0]
        assert hit["properties"]["status"] == "informational"
        assert "Manual review required" not in hit["message"]["text"]
        assert "no action required" in hit["message"]["text"]

    def test_sarif_still_calls_a_real_review_finding_needs_review(self):
        deep = _deep({"target_url": TGT, "confirmed_findings": [],
                      "needs_review_findings": [{"secret_type": "Generic API Key",
                                                 "severity": "MEDIUM", "source_url": SRC,
                                                 "reason": "unvalidated"}],
                      "informational_findings": [], "posture_findings": [],
                      "assets_fetched": 1})
        sarif = json.loads(report_gen.generate_sarif_report(deep))
        hit = sarif["runs"][0]["results"][0]
        assert hit["properties"]["status"] == "needs_review"
        assert "Manual review required" in hit["message"]["text"]

    def test_deep_scan_html_has_a_cleared_section_listing_it(self):
        html = report_gen.generate_deep_scan_html(_one_info_host())
        assert "Examined and Cleared — Public by Design (1)" in html
        assert "Google Cloud API Key" in html
        assert "mtw-pwa-test.telenor.se" in html

    def test_deep_scan_html_never_prints_the_raw_value(self):
        """Public-by-design is not a licence to stop masking: the masking
        contract is unconditional, and a report is a document that gets emailed."""
        html = report_gen.generate_deep_scan_html(_one_info_host())
        assert "AIzaSyCjFeYsl3rpaFFGbgYh_JAmft-U5FW0O-o" not in html

    def test_the_cleared_section_reads_empty_rather_than_vanishing(self):
        deep = _deep({"target_url": TGT, "confirmed_findings": [],
                      "needs_review_findings": [], "informational_findings": [],
                      "posture_findings": [], "assets_fetched": 3})
        html = report_gen.generate_deep_scan_html(deep)
        assert "Examined and Cleared — Public by Design (0)" in html


class TestTheVerdictIsUnchangedByInformationalFindings:
    """A public-by-design value is not an exposure. Letting it colour the domain
    verdict would make the bucket useless — operators would go back to wanting
    them suppressed, which is the behaviour v2.13.0 removed."""

    def test_a_domain_with_only_informational_findings_is_still_clean(self):
        html = report_gen.generate_deep_scan_html(_one_info_host())
        assert "EXPOSURE" not in html
        assert "CLEAN" in html
