"""
SecretNode v2.5.2 — report-generation fixes.

Locks in two things broken/absent before:
  1. A zero-finding scan finishes with status "clean"; the report endpoint used to
     reject anything != "complete", so a clean scan could not be exported at all
     ("Report export failed: Scan is not complete yet (status: clean)"). Reports
     must be available for both "complete" and "clean" scans.
  2. Client reports stamped a stale hard-coded tool version (2.3.0) and gave clean
     scans no real content. The HTML report now carries an executive-summary verdict
     banner, a scope/methodology section, and the live version from pyproject.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import report
import storage


def _clean_scan(scan_id="clean-1"):
    return {
        "scan_id": scan_id, "target_url": "https://clean.example", "status": "clean",
        "assets_fetched": 3, "raw_findings": 0, "duration_seconds": 4.2,
        "confirmed_findings": [], "needs_review_findings": [],
    }


def _findings_scan(scan_id="hit-1"):
    return {
        "scan_id": scan_id, "target_url": "https://hit.example", "status": "complete",
        "assets_fetched": 8, "raw_findings": 4, "duration_seconds": 9.9,
        "confirmed_findings": [{
            "severity": "CRITICAL", "secret_type": "AWS Secret Key", "cwe": "CWE-798",
            "source_url": "https://hit.example/app.js", "confidence": 96, "is_new": True,
            "verified": "verified", "raw_match": "AKIA…", "reason": "live", "remediation": "rotate",
        }],
        "needs_review_findings": [],
    }


# ── Report content ───────────────────────────────────────────────────────────

class TestReportContent:
    def test_clean_scan_produces_assurance_report(self):
        h = report.generate_html_report(_clean_scan())
        assert "No exposed credentials detected" in h
        assert ">CLEAN<" in h                       # risk pill
        assert "Scope &amp; Methodology" in h
        assert "3 asset(s) were analysed" in h      # coverage statement

    def test_findings_scan_shows_verdict_and_risk(self):
        h = report.generate_html_report(_findings_scan())
        assert "1 confirmed credential exposure" in h
        assert "verified currently ACTIVE" in h     # verified-active surfaced
        assert ">CRITICAL<" in h

    def test_report_version_not_stale(self):
        # Must reflect the real project version, never the old hard-coded 2.3.0.
        import pathlib
        pyproject = (pathlib.Path(report.__file__).resolve().parent.parent / "pyproject.toml").read_text()
        ver = next(l.split("=", 1)[1].strip().strip('"') for l in pyproject.splitlines()
                   if l.strip().startswith("version"))
        assert report._TOOL_VERSION == ver
        assert report._TOOL_VERSION != "2.3.0"
        assert f"SecretNode v{ver}" in report.generate_html_report(_clean_scan())

    def test_clean_scan_csv_and_sarif_do_not_crash(self):
        s = _clean_scan()
        assert report.generate_csv_report(s)          # header row at minimum
        import json
        json.loads(report.generate_sarif_report(s))   # valid JSON, 0 results


# ── Report endpoint gate ─────────────────────────────────────────────────────

def _client():
    import main
    from fastapi.testclient import TestClient
    return TestClient(main.app)


HEADERS = {"X-API-Key": "test-key-for-pytest"}


async def _persist(scan):
    await storage.init_db()
    await storage.save_scan(scan["scan_id"], scan)


def test_report_endpoint_allows_clean_scan():
    """The reported bug: a 'clean' scan must be exportable, not 409'd."""
    scan = _clean_scan("clean-endpoint")
    asyncio.run(_persist(scan))
    r = _client().get(f"/api/scans/{scan['scan_id']}/report?format=html", headers=HEADERS)
    assert r.status_code == 200, r.text
    assert "No exposed credentials detected" in r.text


def test_report_endpoint_rejects_unfinished_scan():
    scan = dict(_clean_scan("still-running"), status="running")
    asyncio.run(_persist(scan))
    r = _client().get(f"/api/scans/{scan['scan_id']}/report?format=html", headers=HEADERS)
    assert r.status_code == 409
