"""
v2.8.2 — tests for verify_confirmed_findings(): live-verification of confirmed
findings runs concurrently (bounded by the shared semaphore) instead of one at
a time. No real network: verifier.verify_finding_detailed is monkeypatched.
"""

import asyncio
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import pytest

import scanner
import verifier


def _make_finding(secret_type: str, raw_match: str = "dummy") -> "scanner.ValidatedFinding":
    raw = scanner.RawFinding(
        scan_id="scan-1",
        target_url="https://example.com",
        source_url="https://example.com/app.js",
        secret_type=secret_type,
        raw_match=raw_match,
        context_snippet="...",
        entropy=4.2,
    )
    return scanner.ValidatedFinding(raw=raw, is_valid=True, confidence=95, reason="test")


async def test_verify_runs_concurrently_not_sequentially(monkeypatch):
    """Ten findings, each taking 50ms to verify, bounded by a semaphore of 10,
    should complete in ~1 verify's worth of wall-clock, not ~10x."""
    DELAY = 0.05

    async def fake_verify(secret_type, raw_value, client):
        await asyncio.sleep(DELAY)
        return verifier.VerifyResult("verified", f"identity for {raw_value}")

    monkeypatch.setattr(verifier, "verify_finding_detailed", fake_verify)

    findings = [_make_finding("GitHub PAT", f"tok-{i}") for i in range(10)]
    state = scanner.ScanState()
    semaphore = asyncio.Semaphore(10)

    t0 = time.monotonic()
    await scanner.verify_confirmed_findings(findings, client=None, state=state, semaphore=semaphore)
    elapsed = time.monotonic() - t0

    # Sequential would take ~10 * DELAY = 0.5s; concurrent should be close to 1 * DELAY.
    assert elapsed < DELAY * 5, f"verification did not run concurrently (took {elapsed:.3f}s)"
    assert all(f.verified == "verified" for f in findings)
    assert all(f.verified_detail == f"identity for tok-{i}" for i, f in enumerate(findings))


async def test_verify_bounds_concurrency_to_semaphore(monkeypatch):
    """No more than `semaphore`'s permits worth of verify calls should ever be
    in flight at once, even with many more findings than permits."""
    in_flight = 0
    max_in_flight = 0

    async def fake_verify(secret_type, raw_value, client):
        nonlocal in_flight, max_in_flight
        in_flight += 1
        max_in_flight = max(max_in_flight, in_flight)
        await asyncio.sleep(0.02)
        in_flight -= 1
        return verifier.VerifyResult("unverified", "")

    monkeypatch.setattr(verifier, "verify_finding_detailed", fake_verify)

    findings = [_make_finding("GitHub PAT", f"tok-{i}") for i in range(20)]
    state = scanner.ScanState()
    semaphore = asyncio.Semaphore(3)

    await scanner.verify_confirmed_findings(findings, client=None, state=state, semaphore=semaphore)

    assert max_in_flight <= 3


async def test_one_verify_failure_does_not_affect_the_others(monkeypatch):
    """An unexpected exception from one finding's verify call must not crash the
    batch or corrupt the results of the others — it should fall back to
    'unsupported' for that finding only."""

    async def fake_verify(secret_type, raw_value, client):
        if raw_value == "boom":
            raise RuntimeError("simulated provider client bug")
        return verifier.VerifyResult("verified", f"ok-{raw_value}")

    monkeypatch.setattr(verifier, "verify_finding_detailed", fake_verify)

    findings = [
        _make_finding("GitHub PAT", "good-1"),
        _make_finding("GitHub PAT", "boom"),
        _make_finding("GitHub PAT", "good-2"),
    ]
    state = scanner.ScanState()
    semaphore = asyncio.Semaphore(5)

    await scanner.verify_confirmed_findings(findings, client=None, state=state, semaphore=semaphore)

    assert findings[0].verified == "verified" and findings[0].verified_detail == "ok-good-1"
    assert findings[1].verified == "unsupported" and findings[1].verified_detail == ""
    assert findings[2].verified == "verified" and findings[2].verified_detail == "ok-good-2"


async def test_verify_respects_cancellation(monkeypatch):
    """A scan stopped mid-verification should raise CancelledError rather than
    silently finishing the batch."""

    async def fake_verify(secret_type, raw_value, client):
        return verifier.VerifyResult("verified", "")

    monkeypatch.setattr(verifier, "verify_finding_detailed", fake_verify)

    findings = [_make_finding("GitHub PAT", f"tok-{i}") for i in range(5)]
    state = scanner.ScanState()
    state.cancel()
    semaphore = asyncio.Semaphore(5)

    with pytest.raises(asyncio.CancelledError):
        await scanner.verify_confirmed_findings(findings, client=None, state=state, semaphore=semaphore)
