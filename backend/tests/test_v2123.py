"""
v2.12.3 — fixes found by running a real deep scan of cindrasec.com on the Pi and
reading the dashboard against the downloaded report.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import orchestrator
import scanner


# ── Preloaded fonts are not JavaScript ───────────────────────────────────────

def test_preloaded_fonts_are_not_fetched_as_js_assets():
    """`rel=preload` alone was treated as script-ish, so every preloaded font
    was downloaded as a candidate JS asset. Font preloading is near-universal,
    which made this a per-host tax of binary downloads that cannot contain a
    credential."""
    html = (
        '<link rel="preload" href="fonts/inter-var.woff2" as="font" type="font/woff2" crossorigin>'
        '<link rel="preload" href="fonts/space-grotesk-var.woff2" as="font" crossorigin>'
    )
    assert scanner.extract_js_urls(html, "https://acme.test/") == []


def test_preload_as_script_is_still_collected():
    html = '<link rel="preload" href="/early.js" as="script">'
    assert scanner.extract_js_urls(html, "https://acme.test/") == ["https://acme.test/early.js"]


def test_modulepreload_is_still_collected():
    html = '<link rel="modulepreload" href="/mod.js">'
    assert scanner.extract_js_urls(html, "https://acme.test/") == ["https://acme.test/mod.js"]


def test_a_js_href_is_collected_whatever_the_rel():
    html = '<link rel="stylesheet" href="/weird.js">'
    assert scanner.extract_js_urls(html, "https://acme.test/") == ["https://acme.test/weird.js"]


def test_script_tags_are_unaffected():
    html = '<script src="/app.js"></script>'
    assert scanner.extract_js_urls(html, "https://acme.test/") == ["https://acme.test/app.js"]


def test_non_script_preloads_of_other_types_are_excluded():
    html = (
        '<link rel="preload" href="/data.json" as="fetch">'
        '<link rel="preload" href="/hero.avif" as="image">'
        '<link rel="preload" href="/main.css" as="style">'
    )
    assert scanner.extract_js_urls(html, "https://acme.test/") == []


# ── The deep-scan event must carry what the dashboard displays ───────────────

def test_deep_scan_totals_include_duration_and_raw_findings():
    """`totals` is the entire payload of the deep_scan_complete event, so a
    field missing from it is a field the dashboard cannot show. Their absence
    is why a 14-second run over 6 assets displayed as 0s and 1 asset."""
    result = orchestrator.DeepScanResult(domain="acme.test")
    result.duration_seconds = 14.37
    totals = result.to_dict()["totals"]

    assert "duration_seconds" in totals
    assert "raw_findings" in totals
    assert totals["duration_seconds"] == 14.37


def test_deep_scan_totals_still_carry_the_original_keys():
    """Additive change — nothing that previously read `totals` may break."""
    totals = orchestrator.DeepScanResult(domain="acme.test").to_dict()["totals"]
    for key in ("subdomains", "live_hosts", "hosts_scanned", "historical_urls",
                "assets_fetched", "assets_scanned", "confirmed", "needs_review",
                "posture_issues", "takeover_risks"):
        assert key in totals, f"{key} disappeared from totals"


def test_totals_duration_matches_the_top_level_duration():
    """The report reads the top-level key and the dashboard reads totals; they
    describe the same scan and must not be able to disagree."""
    result = orchestrator.DeepScanResult(domain="acme.test")
    result.duration_seconds = 9.128
    d = result.to_dict()
    assert d["duration_seconds"] == d["totals"]["duration_seconds"]
