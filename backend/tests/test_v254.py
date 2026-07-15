"""
SecretNode v2.5.4 — impact-aware validation.

Clients pay for impact, not for known-public information. A Firebase Web `apiKey`
shipped in client JS is public by design (an identifier, not a secret), yet the old
prompt flagged it as a HIGH "compromised credential". Now the validator classifies
public-by-design identifiers (Firebase web key, publishable pk_ keys, Sentry DSN…)
separately and attaches an impact/blast-radius statement to genuine findings.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import json

import report
import scanner


def _finding(**over):
    raw = scanner.RawFinding(
        scan_id="s", target_url="https://t", source_url="https://t/app.js",
        secret_type=over.pop("secret_type", "Google Cloud API Key"),
        raw_match="AIzaSyEXAMPLE", context_snippet="apiKey:'AIza…',authDomain:'x.firebaseapp.com'",
        entropy=4.7,
    )
    return scanner.ValidatedFinding(raw=raw, **over)


class TestVerdictSchema:
    def test_schema_has_impact_fields(self):
        f = scanner.GeminiVerdict.model_fields
        assert "impact" in f and "public_by_design" in f

    def test_old_style_construction_still_works(self):
        v = scanner.GeminiVerdict(is_valid=True, confidence=90, reason="x")
        assert v.impact == "" and v.public_by_design is False

    def test_schema_bound_to_response(self):
        cfg = scanner._tier_config("high")
        assert cfg.response_schema is scanner.GeminiVerdict


class TestImpactAwareFinding:
    def test_public_by_design_downgraded_to_info(self):
        f = _finding(is_valid=False, confidence=95, reason="firebase web key", public_by_design=True)
        assert f.effective_severity() == "INFO"
        assert f.to_dict()["severity"] == "INFO"
        assert f.to_dict()["public_by_design"] is True

    def test_real_secret_keeps_registry_severity_and_carries_impact(self):
        f = _finding(is_valid=True, confidence=96, reason="live",
                     impact="Grants read/write to the project's Firestore if security rules are open.")
        d = f.to_dict()
        assert d["severity"] != "INFO"          # a genuine secret is not downgraded
        assert "Firestore" in d["impact"]


class TestReportShowsImpact:
    def _scan(self):
        f = _finding(is_valid=True, confidence=96, reason="live",
                     impact="Grants read/write to the project's Firestore if security rules are open.").to_dict()
        return {"scan_id": "a", "target_url": "https://t", "status": "complete",
                "assets_fetched": 5, "raw_findings": 3,
                "confirmed_findings": [f], "needs_review_findings": []}

    def test_html_has_impact_column_and_text(self):
        h = report.generate_html_report(self._scan())
        assert "Impact / Blast Radius" in h
        assert "Firestore" in h

    def test_csv_and_sarif_carry_impact(self):
        s = self._scan()
        assert "impact" in report.generate_csv_report(s).splitlines()[0]
        sarif = json.loads(report.generate_sarif_report(s))
        res = sarif["runs"][0]["results"][0]
        assert res["properties"]["impact"]
        assert "Impact:" in res["message"]["text"]
