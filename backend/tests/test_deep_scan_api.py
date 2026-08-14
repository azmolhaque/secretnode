"""API-level tests for the domain deep-scan endpoint (deep-ASM slice 6).

Follows the same setup as the other API tests: main.py refuses to import without
SECRETNODE_API_KEY, so a shared default is set (via setdefault, so all test
modules agree) BEFORE importing main, and main is imported once. The orchestrator
is mocked so nothing touches the network."""

from __future__ import annotations

import asyncio
import os

os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import pytest
from fastapi.testclient import TestClient

import main  # noqa: E402  (must follow the env setup above)

HEADERS = {"X-API-Key": os.environ["SECRETNODE_API_KEY"]}


@pytest.fixture
def client():
    return TestClient(main.app)


@pytest.fixture
def authorized(tmp_path, monkeypatch):
    """Record a real Rules of Engagement for example.com in a throwaway ledger.

    Deliberately not a monkeypatch of `enforce`: this endpoint now refuses to
    scan anything the ledger does not cover, and a test that stubs the gate out
    would stop noticing if the gate were removed. Seeding an authorization
    exercises the same path an operator takes."""
    from datetime import date, timedelta

    from ops import ledger

    db = tmp_path / "ops.db"
    auth = ledger.Authorization(
        engagement_id="TEST-001",
        client="Example Corp",
        scope=["example.com", "*.example.com"],
        exclusions=[],
        starts_at=(date.today() - timedelta(days=1)).isoformat(),
        expires_at=(date.today() + timedelta(days=30)).isoformat(),
        recipient="security@example.com",
        roe_reference="TEST-ROE",
        # This engagement is used to test the deep-scan endpoint, so the Rules
        # of Engagement have to permit deep scanning. Scope alone does not:
        # enumerating every subdomain is a different technique from fetching
        # one page, and the ledger now says so.
        permit_deep_scan=True,
    )

    async def _seed():
        await ledger.init_db(db)
        await ledger.save_authorization(auth, db)

    asyncio.run(_seed())
    monkeypatch.setattr(ledger, "DB_PATH", db)
    return auth


def test_deep_scan_route_registered():
    paths = {route.path for route in main.app.routes}
    assert "/api/deep-scans" in paths


def test_deep_scan_requires_api_key(client):
    with client:
        r = client.post("/api/deep-scans", json={"domain": "example.com"})
    assert r.status_code == 401


def test_deep_scan_request_caps_inputs():
    req = main.DeepScanRequest(domain="example.com", crawl_pages=9999, max_targets=9999)
    assert req.crawl_pages <= main.MAX_CRAWL_PAGES_CAP
    assert req.max_targets == 100
    with pytest.raises(ValueError):
        main.DeepScanRequest(domain="   ")


def test_deep_scan_starts_and_returns_scan_id(authorized, client, monkeypatch):
    import orchestrator

    async def fake_deep(domain, **_kw):
        return orchestrator.DeepScanResult(domain=domain)

    async def _noop_save(*_a, **_k):
        return None

    monkeypatch.setattr(main.orchestrator, "run_deep_scan", fake_deep)
    monkeypatch.setattr(main, "save_scan", _noop_save)   # avoid post-teardown DB write race
    with client:
        r = client.post(
            "/api/deep-scans",
            headers=HEADERS,
            json={"domain": "example.com", "include_historical": True},
        )
    assert r.status_code == 202
    body = r.json()
    assert body["scan_id"] and body["ws_url"].endswith(body["scan_id"])
    assert body["domain"] == "example.com"
