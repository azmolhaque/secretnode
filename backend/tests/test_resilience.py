"""
v2.7.5 — scan resilience: Retry-After parsing, jittered backoff, and the
adaptive per-host throttle. No real network anywhere.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

import pytest

import scanner


@pytest.fixture(autouse=True)
def _clean_throttle():
    scanner.reset_throttle()
    yield
    scanner.reset_throttle()


# ── Retry-After parsing ──────────────────────────────────────────────────────

def test_retry_after_delta_seconds():
    assert scanner._parse_retry_after("30", 99.0) == 30.0


def test_retry_after_http_date_is_parsed_not_crashed():
    """RFC 7231 allows an HTTP-date. Before v2.7.5 float() raised ValueError,
    the generic handler swallowed it, and the asset was silently dropped."""
    when = datetime.now(timezone.utc) + timedelta(seconds=45)
    secs = scanner._parse_retry_after(format_datetime(when), 99.0)
    assert 30 <= secs <= 60, secs           # ~45s, allowing clock slack


def test_retry_after_past_date_clamps_to_zero():
    when = datetime.now(timezone.utc) - timedelta(hours=1)
    assert scanner._parse_retry_after(format_datetime(when), 99.0) == 0.0


@pytest.mark.parametrize("raw", [None, "", "   ", "soon", "not-a-date", "-5"])
def test_retry_after_garbage_falls_back_and_never_raises(raw):
    val = scanner._parse_retry_after(raw, 7.0)
    assert val >= 0.0
    if raw in (None, "", "   ", "soon", "not-a-date"):
        assert val == 7.0


# ── jittered backoff ─────────────────────────────────────────────────────────

def test_backoff_is_jittered_not_deterministic():
    """Fixed 2**attempt makes every worker retry on the same tick — a thundering
    herd against a host that just asked for relief."""
    delays = {scanner._backoff_delay(3) for _ in range(40)}
    assert len(delays) > 1, "backoff produced identical delays (no jitter)"


def test_backoff_keeps_a_guaranteed_minimum_pause():
    """Equal jitter: never returns ~0, unlike full jitter."""
    ceiling = min(scanner.RETRY_BACKOFF_BASE ** 3, scanner.RETRY_MAX_BACKOFF)
    for _ in range(40):
        d = scanner._backoff_delay(3)
        assert ceiling / 2 <= d <= ceiling


def test_backoff_is_capped():
    assert scanner._backoff_delay(50) <= scanner.RETRY_MAX_BACKOFF


# ── adaptive per-host throttle ───────────────────────────────────────────────

def test_healthy_host_is_never_paced():
    """Zero cost while a host is happy — politeness must not slow normal scans."""
    assert scanner._host_delays == {}


def test_throttle_grows_on_rate_limit_and_is_capped():
    host = "api.example.com"
    first = scanner._throttle_penalise(host)
    second = scanner._throttle_penalise(host)
    assert second > first
    for _ in range(50):
        scanner._throttle_penalise(host)
    assert scanner._host_delays[host] == scanner.THROTTLE_MAX_DELAY


def test_throttle_is_per_host_not_global():
    """One noisy host must not slow the rest of the engagement."""
    scanner._throttle_penalise("slow.example.com")
    assert "fast.example.com" not in scanner._host_delays


def test_throttle_decays_and_is_forgotten_when_host_recovers():
    host = "api.example.com"
    scanner._throttle_penalise(host)
    for _ in range(10):
        scanner._throttle_reward(host)
    assert host not in scanner._host_delays


def test_reward_on_unknown_host_is_a_noop():
    scanner._throttle_reward("never.seen.example.com")
    assert scanner._host_delays == {}


@pytest.mark.asyncio
async def test_throttle_wait_is_instant_for_healthy_host():
    import time as _t
    t0 = _t.monotonic()
    await scanner._throttle_wait("healthy.example.com")
    assert _t.monotonic() - t0 < 0.05


def test_reset_throttle_clears_state():
    scanner._throttle_penalise("a.example.com")
    scanner._throttle_penalise("b.example.com")
    scanner.reset_throttle()
    assert scanner._host_delays == {}
