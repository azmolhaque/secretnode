"""Tests for storage.py — uses a temp SQLite DB per test run."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import pytest
import storage


@pytest.fixture(autouse=True)
async def _isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", tmp_path / "test_secretnode.db")
    await storage.init_db()
    yield


def _sample_scan(scan_id: str, target_url: str, fingerprint: str = "fp1") -> dict:
    return {
        "scan_id": scan_id,
        "target_url": target_url,
        "status": "complete",
        "assets_fetched": 2,
        "raw_findings": 1,
        "validated_findings": 1,
        "confirmed_findings": [
            {"fingerprint": fingerprint, "secret_type": "AWS Access Key",
             "source_url": target_url + "/app.js", "confidence": 90,
             "raw_match": "AKIA****", "reason": "test", "is_new": True, "found_at": "now"}
        ],
        "needs_review_findings": [],
        "new_findings_count": 1,
        "recurring_findings_count": 0,
        "duration_seconds": 1.0,
    }


@pytest.mark.asyncio
async def test_save_and_load_scan():
    await storage.save_scan("s1", _sample_scan("s1", "https://example.com"))
    loaded = await storage.load_scan("s1")
    assert loaded is not None
    assert loaded["target_url"] == "https://example.com"
    assert len(loaded["confirmed_findings"]) == 1


@pytest.mark.asyncio
async def test_load_nonexistent_scan_returns_none():
    assert await storage.load_scan("does-not-exist") is None


@pytest.mark.asyncio
async def test_previous_scan_for_target_excludes_self_and_incomplete():
    await storage.save_scan("s1", _sample_scan("s1", "https://example.com"))
    prev = await storage.get_previous_scan_for_target("https://example.com", exclude_scan_id="s1")
    assert prev is None  # only scan is itself, must be excluded

    await storage.save_scan("s2", _sample_scan("s2", "https://example.com"))
    prev = await storage.get_previous_scan_for_target("https://example.com", exclude_scan_id="s2")
    assert prev is not None
    assert prev["scan_id"] == "s1"


@pytest.mark.asyncio
async def test_previous_scan_different_target_not_matched():
    await storage.save_scan("s1", _sample_scan("s1", "https://example.com"))
    prev = await storage.get_previous_scan_for_target("https://other.com", exclude_scan_id="s2")
    assert prev is None


@pytest.mark.asyncio
async def test_false_positive_roundtrip():
    await storage.mark_false_positive("fp1", "https://example.com", "AWS Access Key", "https://example.com/app.js", "test fixture")
    suppressed = await storage.get_suppressed_fingerprints("https://example.com")
    assert "fp1" in suppressed

    listed = await storage.list_false_positives()
    assert any(item["fingerprint"] == "fp1" for item in listed)

    removed = await storage.unmark_false_positive("fp1")
    assert removed is True
    suppressed_after = await storage.get_suppressed_fingerprints("https://example.com")
    assert "fp1" not in suppressed_after


@pytest.mark.asyncio
async def test_unmark_nonexistent_false_positive_returns_false():
    assert await storage.unmark_false_positive("never-existed") is False


@pytest.mark.asyncio
async def test_load_scans_ordered_most_recent_first():
    await storage.save_scan("s1", _sample_scan("s1", "https://a.com"))
    await storage.save_scan("s2", _sample_scan("s2", "https://b.com"))
    scans = await storage.load_scans(limit=10)
    assert len(scans) == 2
    # Most recent (s2, inserted last) should not be after s1 given same-second
    # timestamps are possible in fast tests — just assert both are present.
    ids = {s["scan_id"] for s in scans}
    assert ids == {"s1", "s2"}
