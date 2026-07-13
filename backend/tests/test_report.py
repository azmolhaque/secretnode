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
