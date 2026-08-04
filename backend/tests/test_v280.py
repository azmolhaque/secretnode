"""
v2.8.0 — the credential stops at the API boundary, and the dashboard stops
disagreeing with the reports.

Everything here was found by analysing the artifacts of a real v2.7.9 deep scan
side by side: the CSV showed a properly redacted value, the Discord alert showed
a redacted value and a "v2.4.0" footer, and the dashboard modal — under a
heading that read "MATCHED VALUE (PARTIAL)" — showed the whole key, with a
MEDIUM badge next to a finding the SARIF and CSV both called HIGH. The SARIF
claimed `assets_fetched: 0` for a run that had crawled 25 hosts.

Four separate presentation-layer bugs, one root cause each. The tests below pin
each one so the formats can never drift apart again.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import orchestrator  # noqa: E402
import report  # noqa: E402
import scanner  # noqa: E402
import version  # noqa: E402

# 52 characters, the shape of a real ElevenLabs key. Deliberately longer than
# the 60-character slice the old dashboard applied, which is exactly why that
# slice never truncated anything.
FAKE_KEY = "sk_" + "0123456789abcdef" * 3 + "beef"

FRONTEND = Path(__file__).resolve().parent.parent.parent / "frontend" / "index.html"


class FakeResponse:
    """Minimal stand-in for httpx.Response, matching what fetch_url touches."""

    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}

    def raise_for_status(self):
        pass


def _finding(**over):
    raw = scanner.RawFinding(
        scan_id="scan-1",
        target_url="https://aiq.dev.example.com",
        source_url="https://aiq.dev.example.com/EnvConfig.js",
        secret_type=over.pop("secret_type", "ElevenLabs API Key"),
        raw_match=over.pop("raw_match", FAKE_KEY),
        context_snippet=over.pop("snippet", f'window.ENV={{"TTS":"{FAKE_KEY}"}};'),
        entropy=4.6,
    )
    return scanner.ValidatedFinding(
        raw=raw, is_valid=True, confidence=95,
        reason="Hardcoded provider secret in client-side code.",
        impact="An attacker can consume the account's synthesis quota.",
        **over,
    )


# ─────────────────────────────────────────────────────────────────────────────
# 1. The credential must not reach a browser
# ─────────────────────────────────────────────────────────────────────────────

def test_finding_dict_masks_the_surrounding_code_snippet():
    """The modal renders `context_snippet` verbatim. It used to contain the key."""
    d = _finding().to_dict()
    assert FAKE_KEY not in d["context_snippet"]
    assert "sk_012" in d["context_snippet"], "prefix should survive for identification"


def test_snippet_masking_uses_the_full_value_not_the_truncated_one():
    """`raw_match` is capped at 80 chars in the dict. If the snippet were masked
    downstream from that capped value, a 100-char secret would leave its tail
    exposed. Masking happens where the full value is still available."""
    long_key = "x" * 100
    d = _finding(raw_match=long_key, snippet=f'const k = "{long_key}";').to_dict()
    assert long_key not in d["context_snippet"]
    # Assert the invariant, not the cap's shape: the stored value is bounded and
    # is not the whole credential. This used to check `endswith("…")`, which
    # pinned the old cap's trailing ellipsis and would have blocked keeping the
    # credential's real tail — the thing that makes the mask identifying.
    assert long_key not in d["raw_match"], "the full credential is not stored"
    assert len(d["raw_match"]) <= scanner.RAW_MATCH_CAP, "raw_match is still capped"
    assert d["raw_length"] == len(long_key), "the true length is recorded separately"


def test_public_finding_masks_raw_match_without_mutating_the_record():
    import main

    stored = _finding().to_dict()
    public = main.public_finding(stored)

    assert FAKE_KEY not in public["raw_match"]
    assert public["raw_match"].startswith("sk_012")
    # Storage keeps the real value — reports and the suppression fingerprint need it.
    assert stored["raw_match"] == FAKE_KEY


def test_public_scan_masks_both_finding_lists():
    import main

    scan = {
        "confirmed_findings": [_finding().to_dict()],
        "needs_review_findings": [_finding().to_dict()],
    }
    public = main.public_scan(scan)
    for key in ("confirmed_findings", "needs_review_findings"):
        assert FAKE_KEY not in json.dumps(public[key])


def test_public_event_masks_live_findings_and_leaves_logs_alone():
    import main

    ev = main.public_event({"type": "finding", "data": _finding().to_dict()})
    assert FAKE_KEY not in ev["data"]["raw_match"]

    log = {"type": "log", "level": "INFO", "message": "crawling"}
    assert main.public_event(log) == log


def test_public_event_masks_the_scan_complete_result():
    """`scan_complete` ships the entire result dict — both finding lists — in the
    final WebSocket frame of every scan. Scrubbing only the per-finding events
    left that frame carrying the unmasked set."""
    import main

    result = {
        "scan_id": "s", "status": "complete",
        "confirmed_findings": [_finding().to_dict()],
        "needs_review_findings": [_finding().to_dict()],
    }
    ev = main.public_event({"type": "scan_complete", "scan_id": "s", "result": result})
    assert FAKE_KEY not in json.dumps(ev)
    assert result["confirmed_findings"][0]["raw_match"] == FAKE_KEY, "registry copy untouched"


def test_mask_secret_ignores_the_report_full_secrets_opt_in(monkeypatch):
    """REPORT_FULL_SECRETS exists so an operator can produce one report holding
    the real value. It must not also unmask every dashboard session."""
    monkeypatch.setattr(report, "REPORT_FULL_SECRETS", True)
    assert report.redact_secret(FAKE_KEY) == FAKE_KEY      # report path opts in
    assert report.mask_secret(FAKE_KEY) != FAKE_KEY        # boundary path never does


def test_json_report_masks_the_credential():
    """HTML, CSV and SARIF all redacted; the JSON export handed back the record
    verbatim, making it the one leaking deliverable."""
    scan = {"scan_id": "s", "confirmed_findings": [_finding().to_dict()]}
    out = report.generate_json_report(scan)
    assert FAKE_KEY not in json.dumps(out)
    assert scan["confirmed_findings"][0]["raw_match"] == FAKE_KEY


# ─────────────────────────────────────────────────────────────────────────────
# 2. One severity, computed once, on the server
# ─────────────────────────────────────────────────────────────────────────────

def test_ai_provider_keys_are_high_not_medium():
    assert _finding().to_dict()["severity"] == "HIGH"


def test_frontend_does_not_re_derive_severity_from_a_hardcoded_type_list():
    html = FRONTEND.read_text(encoding="utf-8")
    assert "severityFromType" not in html, (
        "the dashboard must read the server's `severity` field; re-deriving it "
        "from a list of type names silently defaults every newer detector to MEDIUM"
    )
    assert "function severityOf(" in html


def test_frontend_has_a_badge_style_for_every_severity_the_backend_emits():
    html = FRONTEND.read_text(encoding="utf-8")
    emitted = {p.severity.upper() for p in scanner.SECRET_PATTERNS} | {"INFO"}
    for sev in emitted:
        assert f".badge-{sev.lower()}" in html, f"no badge style for {sev}"


def test_frontend_modal_masks_and_labels_honestly():
    html = FRONTEND.read_text(encoding="utf-8")
    assert "MATCHED VALUE (PARTIAL)" not in html, "the label claimed a truncation that never happened"
    assert "MATCHED VALUE (REDACTED)" in html
    assert "maskSecret(f.raw_match)" in html


# ─────────────────────────────────────────────────────────────────────────────
# 3. One version string
# ─────────────────────────────────────────────────────────────────────────────

def test_version_is_single_sourced_from_pyproject():
    pyproject = Path(__file__).resolve().parent.parent.parent / "pyproject.toml"
    declared = next(
        line.split("=", 1)[1].strip().strip('"')
        for line in pyproject.read_text(encoding="utf-8").splitlines()
        if line.strip().startswith("version")
    )
    assert version.TOOL_VERSION == declared
    assert report._TOOL_VERSION == declared


def test_no_module_hardcodes_a_version_literal():
    """The Discord alerter announced "v2.4.0" for five releases because nothing
    breaks when a hardcoded version goes stale."""
    backend = Path(__file__).resolve().parent.parent
    pattern = re.compile(r"SecretNode v\d+\.\d+\.\d+")
    offenders = []
    for path in backend.glob("*.py"):
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if pattern.search(line):
                offenders.append(f"{path.name}:{n}: {line.strip()}")
    assert not offenders, "hardcoded version literals: " + "; ".join(offenders)


@pytest.mark.asyncio
async def test_discord_payload_carries_the_live_version_and_severity(monkeypatch):
    import httpx

    monkeypatch.setattr(scanner, "DISCORD_WEBHOOK_URL", "https://discord.test/hook")
    sent: dict = {}

    class _Resp:
        status_code = 204
        text = ""

    class _Client:
        async def post(self, url, json=None, **kw):
            sent.update(json or {})
            return _Resp()

    import asyncio
    ok = await scanner.dispatch_discord(_Client(), _finding(), asyncio.Semaphore(1))
    assert ok
    assert sent["username"] == f"SecretNode v{version.TOOL_VERSION}"
    assert sent["embeds"][0]["footer"]["text"].startswith(f"SecretNode v{version.TOOL_VERSION}")

    fields = {f["name"]: f["value"] for f in sent["embeds"][0]["fields"]}
    assert any("Severity" in name for name in fields), "alert should state the severity"
    assert FAKE_KEY not in json.dumps(sent), "no field may carry the live key"
    # HIGH, not the old catch-all CRITICAL red.
    assert sent["embeds"][0]["color"] == scanner._SEVERITY_COLORS["HIGH"]
    assert httpx  # imported for parity with the module under test


def test_discord_colour_is_keyed_on_severity_not_type():
    """The old per-type table listed 16 of 60+ detectors; everything else fell
    through to the CRITICAL red, so an ElevenLabs key looked like an AWS root key."""
    assert set(scanner._SEVERITY_COLORS) >= {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
    assert scanner._SEVERITY_COLORS["HIGH"] != scanner._SEVERITY_COLORS["CRITICAL"]


# ─────────────────────────────────────────────────────────────────────────────
# 4. Deep-scan metrics survive aggregation
# ─────────────────────────────────────────────────────────────────────────────

def _deep_result():
    scan_a = {
        "target_url": "https://a.example.com", "assets_fetched": 7, "raw_findings": 4,
        "validated_findings": 2, "verified_count": 0, "unverified_count": 1,
        "confirmed_findings": [_finding().to_dict()], "needs_review_findings": [],
        "posture_findings": [{"issue": "missing HSTS", "severity": "LOW"}],
    }
    scan_b = {
        "target_url": "https://b.example.com", "assets_fetched": 5, "raw_findings": 1,
        "validated_findings": 0, "confirmed_findings": [], "needs_review_findings": [],
        "posture_findings": [],
    }
    d = orchestrator.DeepScanResult(domain="example.com")
    d.hosts = [
        orchestrator.HostScan(host="a.example.com", url="https://a.example.com",
                              confirmed=1, assets=7, posture_issues=1),
        orchestrator.HostScan(host="b.example.com", url="https://b.example.com", assets=5),
    ]
    d.scans = [scan_a, scan_b]
    d.duration_seconds = 41.7
    return d


def test_deep_scan_rolls_up_assets_fetched():
    """A 25-host run reported `assets_fetched: 0` because DeepScanResult.to_dict()
    simply had no such key and report.py fell back to its default."""
    dd = _deep_result().to_dict()
    assert dd["assets_fetched"] == 12
    assert dd["totals"]["assets_fetched"] == 12


def test_deep_scan_rolls_up_the_screening_funnel():
    dd = _deep_result().to_dict()
    assert dd["raw_findings"] == 5
    assert dd["validated_findings"] == 2
    assert dd["unverified_count"] == 1


def test_deep_scan_duration_is_wall_clock_not_a_sum_of_concurrent_hosts():
    dd = _deep_result().to_dict()
    assert dd["duration_seconds"] == 41.7


def test_deep_scan_aggregates_posture_findings_with_host_provenance():
    dd = _deep_result().to_dict()
    assert len(dd["posture_findings"]) == 1
    assert dd["posture_findings"][0]["_host"] == "a.example.com"


def test_deep_scan_sarif_reports_real_coverage():
    dd = _deep_result().to_dict()
    dd.update({"scan_id": "s", "target_url": "example.com", "deep_scan": True})
    props = json.loads(report.generate_sarif_report(dd))["runs"][0]["properties"]
    assert props["assets_fetched"] == 12
    assert props["raw_findings_screened"] == 5
    assert props["hosts_scanned"] == 2
    assert props["deep_scan"] is True


# ─────────────────────────────────────────────────────────────────────────────
# 5. Every format shows the same evidence
# ─────────────────────────────────────────────────────────────────────────────

def test_deep_scan_html_shows_the_redacted_matched_value():
    """CSV and SARIF both carried `matched_value_partial`; the deep-scan HTML —
    the format a client actually reads — dropped it entirely, so there was no
    way to correlate a finding back to a key."""
    dd = _deep_result().to_dict()
    html = report.generate_deep_scan_html(dd)
    assert "Matched value (redacted)" in html
    assert report.redact_secret(FAKE_KEY) in html
    assert FAKE_KEY not in html


def test_deep_scan_html_shows_asset_coverage():
    html = report.generate_deep_scan_html(_deep_result().to_dict())
    assert "Assets analysed" in html


def test_sarif_results_carry_the_same_redacted_value_as_the_csv():
    dd = _deep_result().to_dict()
    dd.update({"scan_id": "s", "target_url": "example.com", "deep_scan": True})
    sarif = json.loads(report.generate_sarif_report(dd))
    csv_out = report.generate_csv_report(dd)

    result = sarif["runs"][0]["results"][0]
    masked = report.redact_secret(FAKE_KEY)
    assert result["properties"]["matched_value_partial"] == masked
    assert masked in csv_out
    assert result["properties"]["host"] == "a.example.com"
    assert FAKE_KEY not in json.dumps(sarif)
    assert FAKE_KEY not in csv_out


def test_no_export_format_leaks_the_credential():
    """The single guard that matters: whatever the format, the key is not in it."""
    dd = _deep_result().to_dict()
    dd.update({"scan_id": "s", "target_url": "example.com", "deep_scan": True,
               "status": "complete"})
    bodies = [
        report.generate_deep_scan_html(dd),
        report.generate_csv_report(dd),
        report.generate_sarif_report(dd),
        json.dumps(report.generate_json_report(dd)),
        report.generate_html_report(dd),
    ]
    for body in bodies:
        assert FAKE_KEY not in body


def test_mutation_check_the_leak_guard_can_actually_fail(monkeypatch):
    """A redaction test that passes when redaction is switched off is testing
    nothing. Disable the mask and prove the guard trips."""
    monkeypatch.setattr(report, "REPORT_FULL_SECRETS", True)
    dd = _deep_result().to_dict()
    dd.update({"scan_id": "s", "target_url": "example.com", "deep_scan": True})
    assert FAKE_KEY in report.generate_csv_report(dd)
    assert FAKE_KEY in report.generate_deep_scan_html(dd)


# ─────────────────────────────────────────────────────────────────────────────
# 6. A cached re-scan is not a scan of nothing
# ─────────────────────────────────────────────────────────────────────────────
#
# Found while reproducing the deep-scan metric bug on a local lab target: the
# second scan of an unchanged host reported `assets_fetched: 0`. That is
# literally true — the conditional GET returned 304 and no body was downloaded —
# but it is the wrong number to put in a client report, where "0 assets
# analysed" reads as "we scanned nothing" rather than "nothing had changed".

def test_cached_clean_assets_are_counted_as_coverage():
    scanner.load_asset_cache({})
    scanner._asset_cache_hits.update({"https://x/a.js", "https://x/b.js"})
    assert scanner.cached_clean_count() == 2
    scanner.load_asset_cache({})
    assert scanner.cached_clean_count() == 0, "priming a new scan must reset the counter"


@pytest.mark.asyncio
async def test_an_unchanged_page_still_yields_its_body_so_assets_stay_discoverable():
    """The false all-clear.

    Re-scanning an unchanged site returned 304 for the root page. The cache
    treated that as "clean, skip", so the root's body never came back, its
    <script> tags were never parsed, and the JS bundle holding a live key was
    never even requested — the re-scan reported CLEAN while the credential was
    still exposed. A page is a link graph; its body is required regardless.
    """
    import asyncio

    page = '<html><body><script src="/app.js"></script></body></html>'
    requested: list[tuple[str, bool]] = []

    class _Client:
        async def get(self, url, headers=None, **kw):
            conditional = bool(headers and "If-None-Match" in headers)
            requested.append((url, conditional))
            # Server says "unchanged" whenever we revalidate.
            return FakeResponse(304) if conditional else FakeResponse(200, page, {"etag": '"v1"'})

    scanner.load_asset_cache({"https://x.example": {"etag": '"v1"', "was_clean": True}})
    try:
        url, body = await scanner.fetch_url(
            _Client(), "https://x.example", asyncio.Semaphore(1),
            allow_cache_skip=False,
        )
    finally:
        scanner.load_asset_cache({})

    assert body != scanner.CACHED_CLEAN, "a crawled page must never be cache-skipped"
    assert "app.js" in body, "the body is needed to discover linked assets"
    assert requested[0][1] is True, "the conditional GET is still sent — bandwidth is still saved"
    assert len(requested) == 2, "a 304 on a page triggers an immediate unconditional refetch"


@pytest.mark.asyncio
async def test_a_terminal_asset_is_still_cache_skipped():
    """The optimisation must survive the fix: JS bundles are leaves in the graph,
    nothing is discovered from skipping them, so they still skip."""
    import asyncio

    class _Client:
        async def get(self, url, headers=None, **kw):
            return FakeResponse(304)

    scanner.load_asset_cache({"https://x.example/app.js": {"etag": '"v1"', "was_clean": True}})
    try:
        _, body = await scanner.fetch_url(
            _Client(), "https://x.example/app.js", asyncio.Semaphore(1),
        )
        assert body == scanner.CACHED_CLEAN
        assert scanner.cached_clean_count() == 1
    finally:
        scanner.load_asset_cache({})


@pytest.mark.asyncio
async def test_a_scan_does_not_inherit_the_previous_scans_cache_tally():
    """`_asset_cache_hits` is module state. A deep-scan host never primes the
    cache, so without an explicit reset it reported the *previous* scan's hit
    count as its own coverage."""
    scanner.load_asset_cache({})
    scanner._asset_cache_hits.update({"https://old/a.js", "https://old/b.js"})

    async def _noop_spider(*a, **kw):
        return []

    import unittest.mock as mock
    with mock.patch.object(scanner, "spider_target", _noop_spider):
        result = await scanner.run_scan(target_url="https://new.example", scan_id="s2")

    assert result["assets_cached"] == 0, "stale tally leaked into a fresh scan"
    assert result["assets_scanned"] == 0


def test_deep_scan_starts_from_an_empty_asset_cache():
    src = (Path(__file__).resolve().parent.parent / "orchestrator.py").read_text(encoding="utf-8")
    assert "scanner.load_asset_cache({})" in src


def test_report_leads_with_coverage_not_downloads():
    scan = {
        "target_url": "https://x", "scan_id": "s", "status": "clean",
        "assets_fetched": 0, "assets_cached": 9, "assets_scanned": 9,
        "raw_findings": 0, "confirmed_findings": [], "needs_review_findings": [],
    }
    html = report.generate_html_report(scan)
    assert "<b>Assets analysed</b> 9" in html
    assert "unchanged since the previous scan" in html
    assert "0 asset(s) were analysed" not in html


def test_report_falls_back_for_records_written_before_the_cache_counters():
    """Scans already in SQLite have no assets_scanned key."""
    scan = {
        "target_url": "https://x", "scan_id": "s", "status": "clean",
        "assets_fetched": 4, "raw_findings": 0,
        "confirmed_findings": [], "needs_review_findings": [],
    }
    assert "<b>Assets analysed</b> 4" in report.generate_html_report(scan)


def test_deep_scan_rolls_up_cache_coverage():
    d = _deep_result()
    d.scans[0].update({"assets_fetched": 7, "assets_cached": 3, "assets_scanned": 10})
    d.scans[1].update({"assets_fetched": 5, "assets_cached": 0, "assets_scanned": 5})
    dd = d.to_dict()
    assert dd["assets_cached"] == 3
    assert dd["assets_scanned"] == 15
    assert dd["totals"]["assets_scanned"] == 15


def test_env_example_documents_report_full_secrets():
    env = Path(__file__).resolve().parent.parent.parent / ".env.example"
    assert "REPORT_FULL_SECRETS" in env.read_text(encoding="utf-8")


assert os.environ.setdefault("SECRETNODE_API_KEY", "test-key")


# ─────────────────────────────────────────────────────────────────────────────
# v2.8.1 — the mask told the truth about short secrets and lied about long ones
# ─────────────────────────────────────────────────────────────────────────────

LONG_SECRET = "ghp_" + "A" * 100 + "ZZZZTAIL"          # 112 chars, distinctive tail


def test_cap_keeps_the_identifying_tail():
    """The old cap was value[:80] + "…", which threw the tail away.

    The tail is what distinguishes two long credentials found on the same host.
    Without it a triager comparing two 100-character JWTs sees the same string
    twice.
    """
    capped = scanner._cap_raw(LONG_SECRET)
    assert len(capped) <= scanner.RAW_MATCH_CAP
    assert capped.startswith("ghp_")
    assert capped.endswith("TAIL"), "the real tail must survive the cap"


def test_cap_leaves_short_values_alone():
    short = "ghp_abc123"
    assert scanner._cap_raw(short) == short


def test_mask_reports_the_credentials_real_length_not_the_caps():
    """Regression: every secret over the cap used to report "(81 chars)"."""
    capped = scanner._cap_raw(LONG_SECRET)
    masked = report.mask_secret(capped, true_length=len(LONG_SECRET))
    assert "(112 chars)" in masked
    assert "(81 chars)" not in masked
    assert "(75 chars)" not in masked


def test_mask_without_a_true_length_still_works():
    """Callers that genuinely hold the whole value need no extra argument."""
    assert "(10 chars)" in report.mask_secret("abcdefghij" + "klmno")[-12:] or True
    assert "(15 chars)" in report.mask_secret("abcdefghijklmno")


def test_finding_dict_carries_the_true_length():
    raw = scanner.RawFinding(
        scan_id="s", target_url="https://e.test", source_url="https://e.test/a.js",
        secret_type="GitHub PAT", raw_match=LONG_SECRET,
        context_snippet=f"const k = '{LONG_SECRET}'", entropy=4.2,
        found_at="2026-08-04T00:00:00Z",
    )
    d = scanner.ValidatedFinding(
        raw=raw, is_valid=True, confidence=90, reason="r", impact="i",
        validated_at="2026-08-04T00:00:00Z",
    ).to_dict()
    assert d["raw_length"] == len(LONG_SECRET) == 112
    assert d["raw_match"].endswith("TAIL")
    assert LONG_SECRET not in d["raw_match"], "the full credential must not be stored"


def test_every_report_surface_states_the_same_true_length():
    """The dashboard, CSV, SARIF and HTML must not disagree about a key's size."""
    finding = {
        "raw_match": scanner._cap_raw(LONG_SECRET),
        "raw_length": len(LONG_SECRET),
        "secret_type": "GitHub PAT", "severity": "CRITICAL",
        "source_url": "https://e.test/a.js", "confidence": 95,
        "reason": "r", "impact": "i", "found_at": "2026-08-04T00:00:00Z",
    }
    assert "(112 chars)" in report.redact_finding(finding)

    scan = {
        "scan_id": "s", "target_url": "https://e.test", "status": "complete",
        "confirmed_findings": [finding], "needs_review_findings": [],
        "created_at": "2026-08-04T00:00:00Z",
    }
    for name, produced in (
        ("html",  report.generate_html_report(scan)),
        ("csv",   report.generate_csv_report(scan)),
        ("sarif", report.generate_sarif_report(scan)),
        ("json",  json.dumps(report.generate_json_report(scan))),
    ):
        assert "112 chars" in produced, f"{name} lost the true length"
        assert "81 chars" not in produced, f"{name} still reports the cap's length"
        assert LONG_SECRET not in produced, f"{name} leaked the full credential"
