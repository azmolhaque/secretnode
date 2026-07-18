"""
v2.2.0 — tests for report generation (HTML / CSV / SARIF), severity ordering,
and SARIF 2.1.0 structural validity.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import json

import report


def _scan() -> dict:
    return {
        "scan_id": "scan-123",
        "target_url": "https://example.com",
        "status": "complete",
        "assets_fetched": 5,
        "duration_seconds": 2.5,
        "new_findings_count": 1,
        "recurring_findings_count": 1,
        "confirmed_findings": [
            {
                "fingerprint": "fp-medium", "secret_type": "Bearer Token",
                "source_url": "https://example.com/app.js", "confidence": 85,
                "raw_match": "Bearer ab***", "reason": "looks real", "is_new": True,
                "severity": "MEDIUM", "cwe": "CWE-798", "remediation": "rotate it",
                "found_at": "now",
            },
            {
                "fingerprint": "fp-crit", "secret_type": "AWS Access Key",
                "source_url": "https://example.com/config.js", "confidence": 97,
                "raw_match": "AKIA***", "reason": "live key", "is_new": False,
                "severity": "CRITICAL", "cwe": "CWE-798", "remediation": "revoke now",
                "verified": "verified", "verified_detail": "account acme-bot · scopes: repo",
                "found_at": "now",
            },
        ],
        "needs_review_findings": [
            {
                "fingerprint": "fp-review", "secret_type": "Private Key Block",
                "source_url": "https://example.com/x.js", "reason": "AI unavailable",
                "severity": "CRITICAL", "cwe": "CWE-321", "raw_match": "-----BEGIN",
                "found_at": "now",
            }
        ],
    }


def test_html_report_contains_severity_and_cwe():
    out = report.generate_html_report(_scan(), agency_name="Acme Security")
    assert "CRITICAL" in out
    assert "CWE-798" in out
    assert "Acme Security" in out
    assert "Remediation Guidance" in out
    assert "revoke now" in out


def test_html_report_is_html_escaped():
    scan = _scan()
    scan["target_url"] = 'https://x.com/"><script>alert(1)</script>'
    out = report.generate_html_report(scan)
    assert "<script>alert(1)" not in out           # raw injection must not appear
    assert "&lt;script&gt;" in out                  # it is escaped instead


def test_csv_report_has_new_columns():
    out = report.generate_csv_report(_scan())
    header = out.splitlines()[0]
    assert "severity" in header and "cwe" in header
    assert "CONFIRMED" in out and "NEEDS_REVIEW" in out


def test_sarif_is_valid_2_1_0():
    doc = json.loads(report.generate_sarif_report(_scan()))
    assert doc["version"] == "2.1.0"
    assert "runs" in doc and len(doc["runs"]) == 1
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "SecretNode"
    # confirmed (2) + needs_review (1) = 3 results
    assert len(run["results"]) == 3
    # each result carries a ruleId that exists in the rules list
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for res in run["results"]:
        assert res["ruleId"] in rule_ids
        assert res["level"] in ("error", "warning", "note")


def test_sarif_severity_maps_to_level():
    doc = json.loads(report.generate_sarif_report(_scan()))
    results = {r["properties"]["severity"]: r for r in doc["runs"][0]["results"]
               if r["properties"]["status"] == "confirmed"}
    assert results["CRITICAL"]["level"] == "error"
    assert results["MEDIUM"]["level"] == "warning"


def test_sarif_needs_review_downgraded_to_note():
    doc = json.loads(report.generate_sarif_report(_scan()))
    review = [r for r in doc["runs"][0]["results"] if r["properties"]["status"] == "needs_review"]
    assert review and all(r["level"] == "note" for r in review)


def test_confirmed_findings_sorted_critical_first():
    scan = _scan()
    out = report.generate_html_report(scan)
    # CRITICAL row must appear before the MEDIUM row in the rendered table
    assert out.index("AWS Access Key") < out.index("Bearer Token")


def test_html_shows_verified_active_badge():
    out = report.generate_html_report(_scan())
    assert "VERIFIED ACTIVE" in out


def test_csv_has_verified_column():
    out = report.generate_csv_report(_scan())
    assert "verified" in out.splitlines()[0]
    assert "verified" in out  # the value for the verified finding


def test_sarif_carries_verified_property_and_prefix():
    import json as _j
    doc = _j.loads(report.generate_sarif_report(_scan()))
    results = doc["runs"][0]["results"]
    verified = [r for r in results if r["properties"].get("verified") == "verified"]
    assert verified
    assert verified[0]["message"]["text"].startswith("[VERIFIED ACTIVE]")


def test_sarif_advertises_full_detector_catalog():
    """The SARIF driver must describe every detector it can apply (industrial
    best practice), not only rules that fired. Catalog is built from the live
    registry, so it stays in sync with the scanner."""
    import scanner
    doc = json.loads(report.generate_sarif_report(_scan()))
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = {r["id"] for r in rules}
    # Every registry pattern is advertised as a rule, regardless of findings.
    assert len(rules) >= len(scanner.SECRET_PATTERNS)
    for p in scanner.SECRET_PATTERNS:
        assert report._rule_id(p.name) in rule_ids
    # Rules carry the metadata CI consumers rely on.
    sample = next(r for r in rules if r["id"] == report._rule_id("AWS Access Key"))
    assert sample["properties"]["cwe"].startswith("CWE-")
    assert "security-severity" in sample["properties"]
    assert sample["defaultConfiguration"]["level"] in ("error", "warning", "note")


def test_sarif_clean_scan_still_lists_rules():
    """A clean scan (zero findings) must still advertise the rule catalog so the
    report is a complete, self-describing artifact."""
    clean = {"scan_id": "s0", "target_url": "https://example.com",
             "confirmed_findings": [], "needs_review_findings": [], "assets_fetched": 2}
    doc = json.loads(report.generate_sarif_report(clean))
    run = doc["runs"][0]
    assert run["results"] == []
    assert len(run["tool"]["driver"]["rules"]) > 0


def test_html_surfaces_verified_identity_detail():
    """A VERIFIED-active key must show WHO it belongs to / what it reaches (R1)."""
    out = report.generate_html_report(_scan())
    assert "live access" in out
    assert "account acme-bot" in out


def test_csv_has_verified_detail_column():
    out = report.generate_csv_report(_scan())
    header = out.splitlines()[0]
    assert "verified_detail" in header
    assert "account acme-bot" in out


def test_sarif_message_carries_identity_and_keeps_token():
    doc = json.loads(report.generate_sarif_report(_scan()))
    v = [r for r in doc["runs"][0]["results"] if r["properties"].get("verified") == "verified"][0]
    # literal token preserved for downstream matchers, identity appended
    assert v["message"]["text"].startswith("[VERIFIED ACTIVE]")
    assert "account acme-bot" in v["message"]["text"]
    assert v["properties"]["verified_detail"] == "account acme-bot · scopes: repo"
