"""
v2.14.1 — three limits that were documented, asserted, or implied, and that
nothing enforced.

Each was found by auditing for this codebase's recurring shape: a guarantee
stated somewhere a reader will believe it, with no mechanism behind it.

  • The README credits `Semaphore(20)` with bounding RAM during deep JS
    analysis. It bounds concurrent *fetches*; every body was retained to the end
    of the scan with no aggregate cap, and the JS asset list had no cap at all.
  • `main._registry` was appended to and never pruned, so a long-running
    dashboard held every credential it had ever found in memory indefinitely.
  • `verifier.py` states it never reveals a secret anywhere but to its issuer.
    The Telegram token travels in the URL path, and an HTTPStatusError renders
    that URL into a log line.

A negative result belongs with them: WAL journaling was measured before being
proposed and made this workload 2.8x slower with zero errors either way, so it
is deliberately absent. `busy_timeout` already defaults to 5s and every call
opens its own connection, so WAL's cost lands without its benefit.
"""

from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import pytest

import scanner
import storage
import verifier


# ─────────────────────────────────────────────────────────────────────────────
# 1 · The scan's memory ceiling is the sum of what it keeps
# ─────────────────────────────────────────────────────────────────────────────

class TestAssetBudget:
    def test_bodies_are_charged_against_the_budget(self):
        b = scanner._AssetBudget(limit=100)
        assert b.take("x" * 40) is True
        assert b.used == 40

    def test_collection_stops_once_the_limit_is_reached(self):
        b = scanner._AssetBudget(limit=50)
        assert b.take("x" * 50) is True
        assert b.take("y" * 10) is False
        assert b.skipped == 1

    def test_a_skipped_asset_is_counted_not_silently_dropped(self):
        """Reading less than the operator asked for is a coverage statement, and
        a coverage statement nobody can see is the failure this tool exists to
        avoid reporting."""
        # The first body is always taken: the budget is not exhausted until
        # something has been charged against it, so a limit smaller than one
        # asset still yields one asset rather than an empty scan.
        b = scanner._AssetBudget(limit=1)
        for _ in range(4):
            b.take("body")
        assert b.used == len("body")
        assert b.skipped == 3

    def test_unusable_bodies_cost_nothing(self):
        """A cache hit or a failed fetch must not consume budget."""
        b = scanner._AssetBudget(limit=100)
        assert b.take(None) is False
        assert b.take("") is False
        assert b.take(scanner.CACHED_CLEAN) is False
        assert b.used == 0
        assert b.skipped == 0

    def test_the_limit_defaults_to_the_configured_ceiling(self):
        assert scanner._AssetBudget().limit == scanner.MAX_TOTAL_ASSET_BYTES

    def test_there_is_a_cap_on_js_assets(self):
        """Unbounded before: every <script src> across every crawled page was
        fetched in one gather."""
        assert scanner.MAX_JS_ASSETS > 0


# ─────────────────────────────────────────────────────────────────────────────
# 2 · Credentials must not be retained indefinitely
# ─────────────────────────────────────────────────────────────────────────────

class TestRegistryEviction:
    def setup_method(self):
        import main
        self.main = main
        self._saved = dict(main._registry)
        main._registry.clear()

    def teardown_method(self):
        self.main._registry.clear()
        self.main._registry.update(self._saved)

    def _add(self, scan_id: str, done: bool = True):
        class _Task:
            def __init__(self, d): self._d = d
            def done(self): return self._d
        self.main._registry[scan_id] = {
            "task": _Task(done), "state": None,
            "meta": {"scan_id": scan_id, "confirmed_findings": [{"raw_match": "AKIA…"}]},
        }

    def test_completed_scans_are_evicted_beyond_the_bound(self, monkeypatch):
        monkeypatch.setattr(self.main, "MAX_REGISTRY_ENTRIES", 3)
        for i in range(6):
            self._add(f"s{i}")
        self.main._evict_finished_scans()
        assert len(self.main._registry) == 3

    def test_the_newest_scans_are_the_ones_kept(self, monkeypatch):
        monkeypatch.setattr(self.main, "MAX_REGISTRY_ENTRIES", 2)
        for i in range(5):
            self._add(f"s{i}")
        self.main._evict_finished_scans()
        assert "s4" in self.main._registry
        assert "s0" not in self.main._registry

    def test_a_running_scan_is_never_evicted(self, monkeypatch):
        """Running entries carry live state — evicting one would orphan it."""
        monkeypatch.setattr(self.main, "MAX_REGISTRY_ENTRIES", 1)
        self._add("running", done=False)
        for i in range(5):
            self._add(f"done{i}")
        self.main._evict_finished_scans()
        assert "running" in self.main._registry

    def test_under_the_bound_nothing_is_evicted(self, monkeypatch):
        monkeypatch.setattr(self.main, "MAX_REGISTRY_ENTRIES", 10)
        for i in range(4):
            self._add(f"s{i}")
        assert self.main._evict_finished_scans() == 0
        assert len(self.main._registry) == 4


class TestScanHistoryRetention:
    @pytest.fixture(autouse=True)
    def _db(self, tmp_path, monkeypatch):
        monkeypatch.setattr(storage, "DB_PATH", tmp_path / "t.db")
        asyncio.run(storage.init_db())

    def _save(self, n: int):
        async def go():
            for i in range(n):
                await storage.save_scan(f"s{i:04d}", {
                    "target_url": "https://t.test", "status": "completed",
                    "assets_fetched": 1, "raw_findings": 0, "validated_findings": 0,
                    "confirmed_findings": [], "needs_review_findings": [],
                    "duration_seconds": 1.0,
                })
        asyncio.run(go())

    def test_history_is_pruned_to_the_limit(self):
        self._save(12)
        removed = asyncio.run(storage.prune_scan_history(limit=5))
        assert removed == 7
        assert len(asyncio.run(storage.load_scans(limit=100))) == 5

    def test_pruning_keeps_the_newest(self):
        self._save(6)
        asyncio.run(storage.prune_scan_history(limit=2))
        kept = {s["scan_id"] for s in asyncio.run(storage.load_scans(limit=100))}
        assert "s0005" in kept
        assert "s0000" not in kept

    def test_a_limit_of_zero_disables_pruning(self):
        """An operator who scans rarely must not lose history to a default."""
        self._save(4)
        assert asyncio.run(storage.prune_scan_history(limit=0)) == 0
        assert len(asyncio.run(storage.load_scans(limit=100))) == 4

    def test_pruning_under_the_limit_is_a_no_op(self):
        self._save(3)
        assert asyncio.run(storage.prune_scan_history(limit=10)) == 0


# ─────────────────────────────────────────────────────────────────────────────
# 3 · A credential must never reach a log
# ─────────────────────────────────────────────────────────────────────────────

class TestVerifierLogScrubbing:
    TOKEN = "123456789:AAFAKEfakeFAKEfakeFAKEfakeFAKEfake01"

    def test_the_literal_token_is_removed(self):
        msg = f"Client error for url 'https://api.telegram.org/bot{self.TOKEN}/getMe'"
        assert self.TOKEN not in verifier._scrub(msg, self.TOKEN)
        assert "[REDACTED]" in verifier._scrub(msg, self.TOKEN)

    def test_the_url_encoded_form_is_removed(self):
        """A token with `:` or `/` reaches an exception percent-encoded, so
        matching only the literal would let exactly those through."""
        from urllib.parse import quote
        encoded = quote(self.TOKEN, safe="")
        assert encoded not in verifier._scrub(f"url 'x/{encoded}/y'", self.TOKEN)

    def test_surrounding_diagnostic_text_survives(self):
        """Scrubbing must not cost the operator the reason it failed."""
        out = verifier._scrub(f"401 Unauthorized for {self.TOKEN}", self.TOKEN)
        assert "401 Unauthorized" in out

    def test_an_empty_secret_is_handled(self):
        assert verifier._scrub("nothing to scrub", "") == "nothing to scrub"

    def test_the_error_path_logs_no_credential(self, caplog):
        """End to end through the real failure path, on the verifier whose
        provider requires the token in the URL."""
        import httpx

        class StatusClient:
            async def get(self, url, **kw):
                httpx.Response(401, request=httpx.Request("GET", url)).raise_for_status()

        with caplog.at_level("WARNING", logger="secretnode.verifier"):
            res = asyncio.run(verifier.verify_finding_detailed(
                "Telegram Bot Token", self.TOKEN, StatusClient()))
        assert res.status == "unverified"
        assert self.TOKEN not in caplog.text
        assert "[REDACTED]" in caplog.text
