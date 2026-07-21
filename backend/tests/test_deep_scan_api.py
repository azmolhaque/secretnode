"""API-level tests for the domain deep-scan endpoint (deep-ASM slice 6).

Follows the same setup as the other API tests: main.py refuses to import without
SECRETNODE_API_KEY, so a shared default is set (via setdefault, so all test
modules agree) BEFORE importing main, and main is imported once. The orchestrator
is mocked so nothing touches the network."""

from __future__ import annotations

import os

os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import pytest
from fastapi.testclient import TestClient

import main  # noqa: E402  (must follow the env setup above)

HEADERS = {"X-API-Key": os.environ["SECRETNODE_API_KEY"]}


@pytest.fixture
def client():
    return TestClient(main.app)


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


def test_deep_scan_starts_and_returns_scan_id(client, monkeypatch):
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
