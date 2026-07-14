"""v2.3.0 — CLI tests (pure logic + SSRF guard; no network)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import json

import pytest

import cli


_SAMPLE = {
    "scan_id": "s1", "target_url": "https://example.com", "status": "complete",
    "assets_fetched": 3, "duration_seconds": 1.0,
    "confirmed_findings": [
        {"fingerprint": "f1", "secret_type": "GitLab Personal Access Token",
         "source_url": "https://example.com/a.js", "confidence": 95, "severity": "CRITICAL",
         "cwe": "CWE-798", "verified": "verified", "raw_match": "glpat-***", "is_new": True,
         "reason": "x", "found_at": "now"}
    ],
    "needs_review_findings": [],
}


def test_build_output_sarif_is_valid_json():
    doc = json.loads(cli.build_output(_SAMPLE, "sarif"))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"]


def test_build_output_csv_and_html_and_json():
    assert "severity" in cli.build_output(_SAMPLE, "csv").splitlines()[0]
    assert "<!DOCTYPE html>" in cli.build_output(_SAMPLE, "html")
    assert json.loads(cli.build_output(_SAMPLE, "json"))["scan_id"] == "s1"


def test_parser_flags():
    args = cli.build_parser().parse_args(
        ["https://example.com", "-f", "json", "--verify", "--only-verified", "--crawl", "4", "--fail-on-findings"]
    )
    assert args.format == "json"
    assert args.verify and args.only_verified and args.fail_on_findings
    assert args.crawl == 4


def test_ssrf_guard_blocks_loopback(monkeypatch):
    monkeypatch.delenv("ALLOW_PRIVATE_TARGETS", raising=False)
    with pytest.raises(SystemExit):
        cli.assert_public_target("http://127.0.0.1/")


def test_ssrf_guard_blocks_metadata_ip(monkeypatch):
    monkeypatch.delenv("ALLOW_PRIVATE_TARGETS", raising=False)
    with pytest.raises(SystemExit):
        cli.assert_public_target("http://169.254.169.254/latest/meta-data/")


def test_ssrf_guard_bypass_when_allowed(monkeypatch):
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "true")
    # Should not raise when explicitly allowed.
    cli.assert_public_target("http://127.0.0.1/")
