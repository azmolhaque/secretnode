"""Tests for multi-target orchestration (deep-ASM slice 2). Enumeration, the HTTP
client, and per-host scans are all injected/mocked, so these run offline and
deterministically."""

from __future__ import annotations

import httpx
import pytest

import historical
import orchestrator
import recon


class _Resp:
    def __init__(self, status_code: int = 200):
        self.status_code = status_code


class _FakeClient:
    """Async client stand-in: probes succeed unless the host matches `dead`."""
    def __init__(self, dead: tuple[str, ...] = ()):
        self.dead = set(dead)
        self.gets: list[str] = []

    async def get(self, url, **_kw):
        self.gets.append(url)
        if any(d in url for d in self.dead):
            raise httpx.ConnectError("dead host")
        return _Resp(200)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_a):
        return False


def _client_factory(dead: tuple[str, ...] = ()):
    def _factory():
        return _FakeClient(dead)
    return _factory


def _enum_returning(subs, sources=("crt.sh",), error=None):
    async def _enum(_client, domain):
        return recon.SubdomainResult(domain=domain, subdomains=list(subs),
                                     sources=list(sources), error=error)
    return _enum


def _scan_returning(confirmed=0, needs_review=0, posture=0, assets=5):
    async def _scan(*, target_url, **_kw):
        return {
            "target_url": target_url,
            "confirmed_findings": [{"x": i} for i in range(confirmed)],
            "needs_review_findings": [{"x": i} for i in range(needs_review)],
            "posture_findings": [{"x": i} for i in range(posture)],
            "assets_fetched": assets,
        }
    return _scan


@pytest.fixture(autouse=True)
def _allow_private(monkeypatch):
    """Bypass the DNS SSRF guard by default so fake hostnames aren't dropped;
    the guard itself is tested explicitly below."""
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "true")


class TestTargetIpClass:
    def test_loopback_is_private(self):
        assert orchestrator._target_ip_class("127.0.0.1") == "private"

    def test_public_ip_is_public(self):
        assert orchestrator._target_ip_class("93.184.216.34") == "public"

    def test_unresolvable_is_unresolved(self):
        # .invalid is reserved to never resolve (RFC 2606) — no network needed.
        assert orchestrator._target_ip_class("nothing.invalid") == "unresolved"


@pytest.mark.asyncio
async def test_probe_live_hosts_filters_dead():
    client = _FakeClient(dead=("b.example.com",))
    live = await orchestrator.probe_live_hosts(client, ["a.example.com", "b.example.com"])
    assert live == ["https://a.example.com"]


@pytest.mark.asyncio
async def test_deep_scan_enumerates_probes_and_aggregates():
    result = await orchestrator.run_deep_scan(
        "example.com",
        enumerate_fn=_enum_returning(["a.example.com", "b.example.com"]),
        scan_fn=_scan_returning(confirmed=1, posture=2),
        client_factory=_client_factory(),
    )
    d = result.to_dict()
    # apex + 2 subdomains, all live, all scanned.
    assert d["totals"]["subdomains"] == 2
    assert d["totals"]["live_hosts"] == 3
    assert d["totals"]["hosts_scanned"] == 3
    assert d["totals"]["confirmed"] == 3        # 1 per host × 3
    assert d["totals"]["posture_issues"] == 6   # 2 per host × 3
    assert "example.com" in result.subdomains or result.domain == "example.com"


@pytest.mark.asyncio
async def test_deep_scan_dead_host_excluded():
    result = await orchestrator.run_deep_scan(
        "example.com",
        enumerate_fn=_enum_returning(["a.example.com", "dead.example.com"]),
        scan_fn=_scan_returning(confirmed=1),
        client_factory=_client_factory(dead=("dead.example.com",)),
    )
    hosts = [h.host for h in result.hosts]
    assert "dead.example.com" not in hosts
    assert result.to_dict()["totals"]["hosts_scanned"] == 2   # apex + a


@pytest.mark.asyncio
async def test_deep_scan_respects_max_targets():
    result = await orchestrator.run_deep_scan(
        "example.com",
        enumerate_fn=_enum_returning(["a.example.com", "b.example.com", "c.example.com"]),
        scan_fn=_scan_returning(confirmed=1),
        client_factory=_client_factory(),
        max_targets=1,
    )
    assert result.to_dict()["totals"]["hosts_scanned"] == 1


@pytest.mark.asyncio
async def test_deep_scan_one_host_scan_error_is_isolated():
    calls = {"n": 0}

    async def _flaky_scan(*, target_url, **_kw):
        calls["n"] += 1
        if "a.example.com" in target_url:
            raise RuntimeError("boom")
        return {"target_url": target_url, "confirmed_findings": [],
                "needs_review_findings": [], "posture_findings": [], "assets_fetched": 1}

    result = await orchestrator.run_deep_scan(
        "example.com",
        enumerate_fn=_enum_returning(["a.example.com"]),
        scan_fn=_flaky_scan,
        client_factory=_client_factory(),
    )
    errored = [h for h in result.hosts if h.error]
    assert any("boom" in (h.error or "") for h in errored)
    # The other host still scanned — one failure does not sink the run.
    assert any(h.error is None for h in result.hosts)


@pytest.mark.asyncio
async def test_deep_scan_ip_target_falls_back_to_single_scan():
    result = await orchestrator.run_deep_scan(
        "http://93.184.216.34",
        enumerate_fn=_enum_returning(["should.not.be.used"]),
        scan_fn=_scan_returning(confirmed=1),
        client_factory=_client_factory(),
    )
    # IP has no enumerable domain → exactly one host scanned (the target itself).
    assert result.to_dict()["totals"]["hosts_scanned"] == 1
    assert result.hosts[0].url == "http://93.184.216.34"


@pytest.mark.asyncio
async def test_deep_scan_historical_seeds_routed_per_host():
    seen: dict[str, list[str]] = {}

    async def _scan(*, target_url, seed_urls=None, **_kw):
        seen[target_url] = list(seed_urls or [])
        return {"target_url": target_url, "confirmed_findings": [],
                "needs_review_findings": [], "posture_findings": [], "assets_fetched": 1}

    async def _hist(_client, domain):
        return historical.HistoricalResult(
            domain=domain,
            urls=["https://a.example.com/old.js", "https://example.com/x.js",
                  "https://example.com/page.html"],   # non-JS ignored as a seed
            sources=["wayback"],
        )

    result = await orchestrator.run_deep_scan(
        "example.com",
        include_historical=True,
        enumerate_fn=_enum_returning(["a.example.com"]),
        scan_fn=_scan,
        client_factory=_client_factory(),
        discover_historical_fn=_hist,
    )
    # Each host receives only its own archived JS bundles as seeds.
    assert seen["https://example.com"] == ["https://example.com/x.js"]
    assert seen["https://a.example.com"] == ["https://a.example.com/old.js"]
    assert result.historical_urls == 3
    assert result.to_dict()["totals"]["historical_urls"] == 3


@pytest.mark.asyncio
async def test_deep_scan_without_historical_passes_no_seeds():
    seen: dict[str, list[str]] = {}

    async def _scan(*, target_url, seed_urls=None, **_kw):
        seen[target_url] = list(seed_urls or [])
        return {"target_url": target_url, "confirmed_findings": [],
                "needs_review_findings": [], "posture_findings": [], "assets_fetched": 1}

    await orchestrator.run_deep_scan(
        "example.com",
        enumerate_fn=_enum_returning([]),
        scan_fn=_scan,
        client_factory=_client_factory(),
    )
    assert seen["https://example.com"] == []


@pytest.mark.asyncio
async def test_deep_scan_aggregates_findings_with_host_and_renders():
    import report

    async def _scan(*, target_url, seed_urls=None, **_kw):
        host = recon._host_of(target_url)
        conf = ([{"secret_type": "AWS Access Key", "severity": "CRITICAL"}]
                if host.startswith("a.") else [])
        rev = [{"secret_type": "Generic", "severity": "MEDIUM", "reason": "unclear"}]
        return {"target_url": target_url, "confirmed_findings": conf,
                "needs_review_findings": rev, "posture_findings": [], "assets_fetched": 1}

    result = await orchestrator.run_deep_scan(
        "example.com",
        enumerate_fn=_enum_returning(["a.example.com"]),
        scan_fn=_scan,
        client_factory=_client_factory(),
    )
    d = result.to_dict()
    # Confirmed finding is tagged with the host it came from.
    assert any(f["_host"] == "a.example.com" and f["secret_type"] == "AWS Access Key"
               for f in d["confirmed_findings"])
    # Needs-review aggregated across both hosts (apex + a), each host-tagged.
    assert len(d["needs_review_findings"]) == 2
    assert all("_host" in f for f in d["needs_review_findings"])
    # The combined report actually renders the detail, not just counts.
    htmlrep = report.generate_deep_scan_html(d)
    assert "Flagged for Manual Review (all hosts)" in htmlrep
    assert "AWS Access Key" in htmlrep and "a.example.com" in htmlrep


@pytest.mark.asyncio
async def test_deep_scan_always_scans_specified_host():
    # Regression: even if CT enumeration returns nothing and the typed host is a
    # subdomain (not the apex), the host the caller specified must still be scanned.
    seen: list[str] = []

    async def _scan(*, target_url, seed_urls=None, **_kw):
        seen.append(target_url)
        return {"target_url": target_url, "confirmed_findings": [],
                "needs_review_findings": [], "posture_findings": [], "assets_fetched": 1}

    await orchestrator.run_deep_scan(
        "testphp.example.com",
        enumerate_fn=_enum_returning([]),          # CT found nothing
        scan_fn=_scan,
        client_factory=_client_factory(),
    )
    assert any("testphp.example.com" in u for u in seen)


@pytest.mark.asyncio
async def test_deep_scan_historical_reveals_hosts():
    # Hostnames seen only in the archive become scan candidates, so a flaky CT
    # source no longer zeroes out the run.
    seen: list[str] = []

    async def _scan(*, target_url, seed_urls=None, **_kw):
        seen.append(recon._host_of(target_url))
        return {"target_url": target_url, "confirmed_findings": [],
                "needs_review_findings": [], "posture_findings": [], "assets_fetched": 1}

    async def _hist(_client, domain):
        return historical.HistoricalResult(
            domain=domain,
            urls=["https://testphp.example.com/x", "https://rest.example.com/b.js"],
            sources=["wayback"],
        )

    await orchestrator.run_deep_scan(
        "example.com",
        include_historical=True,
        enumerate_fn=_enum_returning([]),          # CT empty
        scan_fn=_scan,
        client_factory=_client_factory(),
        discover_historical_fn=_hist,
    )
    assert "testphp.example.com" in seen
    assert "rest.example.com" in seen


@pytest.mark.asyncio
async def test_deep_scan_ssrf_guard_skips_private_host(monkeypatch):
    # Turn the guard back on and force one host to look internal.
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "false")
    monkeypatch.setattr(
        orchestrator, "_target_ip_class",
        lambda host: "private" if host == "internal.example.com" else "public",
    )
    result = await orchestrator.run_deep_scan(
        "example.com",
        enumerate_fn=_enum_returning(["internal.example.com", "a.example.com"]),
        scan_fn=_scan_returning(confirmed=1),
        client_factory=_client_factory(),
    )
    skipped = [h for h in result.hosts if h.error and "SSRF" in h.error]
    assert any(h.host == "internal.example.com" for h in skipped)
    # The private host must never appear among the live/scanned hosts.
    assert all("internal.example.com" not in u for u in result.live_hosts)
