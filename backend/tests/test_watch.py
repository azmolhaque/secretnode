"""
v2.9.0 — tests for the Watch continuous-monitoring delta engine.

compute_delta/classify/render_digest are pure functions, so these run with no
database and no network — the same property posture.py's tests rely on.

The tests that matter most are the coverage-anomaly ones: reporting a finding as
"resolved" when it merely wasn't looked at this run would put a false statement
into a paid client deliverable, and that is the failure mode this module is most
likely to produce.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import pytest

import watch


def _finding(fp: str, severity: str = "high", secret_type: str = "GitHub PAT", verified: str = "disabled"):
    return {
        "fingerprint": fp,
        "secret_type": secret_type,
        "severity": severity,
        "source_url": f"https://example.com/{fp}.js",
        "target_url": "https://example.com",
        "verified": verified,
    }


def _scan(scan_id: str, findings, assets: int = 10, status: str = "complete"):
    return {
        "scan_id": scan_id,
        "target_url": "https://example.com",
        "status": status,
        "assets_scanned": assets,
        "confirmed_findings": findings,
    }


# ── Core diff ────────────────────────────────────────────────────────────────

def test_first_run_reports_everything_as_new():
    d = watch.compute_delta(_scan("s1", [_finding("a"), _finding("b")]), None)
    assert d.first_run is True
    assert len(d.new) == 2
    assert d.resolved == [] and d.recurring == []
    assert d.previous_scan_id is None


def test_new_recurring_and_resolved_are_split_correctly():
    prev = _scan("s1", [_finding("a"), _finding("b")])
    cur = _scan("s2", [_finding("b"), _finding("c")])
    d = watch.compute_delta(cur, prev)

    assert [f["fingerprint"] for f in d.new] == ["c"]
    assert [f["fingerprint"] for f in d.recurring] == ["b"]
    assert [f["fingerprint"] for f in d.resolved] == ["a"]
    assert d.resolution_confirmed is True
    assert d.previous_scan_id == "s1"


def test_a_rotated_credential_reads_as_one_resolved_plus_one_new():
    # Same location, different value -> different fingerprint. That is the
    # correct reading: the old value is no longer exposed, a new one now is.
    prev = _scan("s1", [_finding("old_value_fp")])
    cur = _scan("s2", [_finding("new_value_fp")])
    d = watch.compute_delta(cur, prev)
    assert len(d.new) == 1 and len(d.resolved) == 1 and not d.recurring


def test_findings_without_a_fingerprint_are_ignored_not_crashed_on():
    prev = _scan("s1", [{"secret_type": "x"}])
    cur = _scan("s2", [{"secret_type": "x"}, _finding("a")])
    d = watch.compute_delta(cur, prev)
    assert [f["fingerprint"] for f in d.new] == ["a"]


# ── The resolution trap ──────────────────────────────────────────────────────

def test_coverage_collapse_blocks_the_resolved_claim():
    """The headline safeguard: 10 assets last run, 2 this run, a finding missing.
    It must NOT be reported as resolved."""
    prev = _scan("s1", [_finding("a"), _finding("b")], assets=10)
    cur = _scan("s2", [_finding("b")], assets=2)
    d = watch.compute_delta(cur, prev)

    assert d.resolved == []
    assert [f["fingerprint"] for f in d.unverified_disappearances] == ["a"]
    assert d.resolution_confirmed is False
    assert "coverage" in d.coverage_note.lower()


def test_a_failed_scan_never_claims_resolution():
    prev = _scan("s1", [_finding("a")], assets=10)
    cur = _scan("s2", [], assets=10, status="error")
    d = watch.compute_delta(cur, prev)

    assert d.resolved == []
    assert len(d.unverified_disappearances) == 1
    assert d.resolution_confirmed is False


def test_minor_coverage_churn_still_permits_resolution():
    # 10 -> 9 assets is ordinary churn, not an anomaly; resolution stands.
    prev = _scan("s1", [_finding("a"), _finding("b")], assets=10)
    cur = _scan("s2", [_finding("b")], assets=9)
    d = watch.compute_delta(cur, prev)
    assert [f["fingerprint"] for f in d.resolved] == ["a"]
    assert d.resolution_confirmed is True


def test_older_scans_without_assets_scanned_fall_back_not_flagged():
    # Rows written before v2.8.0 have no assets_scanned. Treating that as zero
    # coverage would flag every such comparison as an anomaly.
    prev = {"scan_id": "s1", "target_url": "https://example.com", "status": "complete",
            "assets_fetched": 10, "confirmed_findings": [_finding("a"), _finding("b")]}
    cur = _scan("s2", [_finding("b")], assets=10)
    d = watch.compute_delta(cur, prev)
    assert d.resolution_confirmed is True
    assert [f["fingerprint"] for f in d.resolved] == ["a"]


# ── Triage ───────────────────────────────────────────────────────────────────

def test_new_critical_finding_is_urgent():
    d = watch.compute_delta(_scan("s2", [_finding("a", severity="critical")]), _scan("s1", []))
    tier, reasons = watch.classify(d)
    assert tier == "URGENT" and reasons


def test_a_verified_live_credential_is_urgent_even_at_medium_severity():
    """A MEDIUM secret proven to be an active credential is a working way in.
    Severity alone understates it, and waiting a month would be indefensible."""
    d = watch.compute_delta(
        _scan("s2", [_finding("a", severity="medium", verified="verified")]),
        _scan("s1", []),
    )
    tier, reasons = watch.classify(d)
    assert tier == "URGENT"
    assert any("confirmed live" in r for r in reasons)


def test_new_low_severity_finding_is_review_not_urgent():
    d = watch.compute_delta(_scan("s2", [_finding("a", severity="low")]), _scan("s1", []))
    assert watch.classify(d)[0] == "REVIEW"


def test_a_coverage_anomaly_forces_human_review_even_with_no_new_findings():
    prev = _scan("s1", [_finding("a")], assets=10)
    cur = _scan("s2", [], assets=1)
    assert watch.classify(watch.compute_delta(cur, prev))[0] == "REVIEW"


def test_no_changes_is_routine():
    prev = _scan("s1", [_finding("a")])
    cur = _scan("s2", [_finding("a")])
    assert watch.classify(watch.compute_delta(cur, prev))[0] == "ROUTINE"


# ── Digest rendering ─────────────────────────────────────────────────────────

def test_digest_states_a_clean_period_plainly():
    prev = _scan("s1", [_finding("a")])
    cur = _scan("s2", [_finding("a")])
    md = watch.render_digest(watch.compute_delta(cur, prev), "Acme Ltd", "August 2026")
    assert "Acme Ltd" in md and "August 2026" in md
    assert "clean period is a real result" in md


def test_digest_does_not_claim_resolution_when_coverage_is_suspect():
    prev = _scan("s1", [_finding("a")], assets=10)
    cur = _scan("s2", [], assets=1)
    md = watch.render_digest(watch.compute_delta(cur, prev), "Acme Ltd", "August 2026")
    assert "resolution not confirmed" in md.lower()
    assert "not** claiming they are fixed" in md


def test_digest_marks_internal_triage_notes_for_removal():
    d = watch.compute_delta(_scan("s2", [_finding("a", severity="critical")]), _scan("s1", []))
    md = watch.render_digest(d, "Acme Ltd", "August 2026")
    assert "INTERNAL — remove before sending" in md
    # The internal block must be inside an HTML comment so it cannot render into
    # a client-facing document by accident.
    assert md.index("<!-- INTERNAL") < md.index("Triage:")
    assert md.rstrip().endswith("-->")


def test_internal_triage_never_appears_in_the_visible_body():
    """Every internal note must live inside the one HTML-comment block, so that
    deleting that block is the complete step to make the draft client-ready.
    An earlier version also printed the tier in the header, which meant a
    reviewer who removed the comment still shipped 'URGENT' to a client."""
    d = watch.compute_delta(_scan("s2", [_finding("a", severity="critical")]), _scan("s1", []))
    md = watch.render_digest(d, "Acme Ltd", "August 2026")
    visible = md.split("<!-- INTERNAL")[0]
    assert "URGENT" not in visible
    assert "triage" not in visible.lower()


def test_persistent_high_severity_findings_get_their_own_section():
    """A CRITICAL key surviving several periods is the most important fact in
    the report and the easiest for a client to stop noticing. It must not be
    absorbed into a 'still present: N' count."""
    prev = _scan("s1", [_finding("aws", severity="critical", secret_type="AWS Access Key")])
    cur = _scan("s2", [_finding("aws", severity="critical", secret_type="AWS Access Key")])
    md = watch.render_digest(watch.compute_delta(cur, prev), "Acme Ltd", "August 2026")
    assert "Still exposed from previous periods" in md
    assert "AWS Access Key" in md


def test_persistent_low_severity_findings_do_not_get_promoted():
    prev = _scan("s1", [_finding("x", severity="low")])
    cur = _scan("s2", [_finding("x", severity="low")])
    md = watch.render_digest(watch.compute_delta(cur, prev), "Acme Ltd", "August 2026")
    assert "Still exposed from previous periods" not in md


def test_digest_always_states_scope_limits():
    md = watch.render_digest(watch.compute_delta(_scan("s1", []), None), "Acme Ltd", "August 2026")
    assert "passive and read-only" in md
    assert "behind authentication" in md


# ── Roster ───────────────────────────────────────────────────────────────────

def test_roster_loads_both_shapes(tmp_path):
    entry = {"client": "Acme", "target_url": "https://acme.test", "crawl_pages": 5}
    for payload in ([entry], {"targets": [entry]}):
        p = tmp_path / "roster.json"
        p.write_text(json.dumps(payload), encoding="utf-8")
        targets = watch.load_roster(p)
        assert len(targets) == 1
        assert targets[0].client == "Acme" and targets[0].crawl_pages == 5


def test_missing_roster_raises_rather_than_running_zero_targets(tmp_path):
    """'Monitoring completed, zero targets' is the most dangerous silent failure
    a paid subscription can have."""
    with pytest.raises(FileNotFoundError):
        watch.load_roster(tmp_path / "nope.json")


def test_roster_entry_missing_required_field_is_rejected(tmp_path):
    p = tmp_path / "roster.json"
    p.write_text(json.dumps([{"client": "Acme"}]), encoding="utf-8")
    with pytest.raises(ValueError, match="target_url"):
        watch.load_roster(p)
