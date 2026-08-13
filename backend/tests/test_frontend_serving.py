"""v2.8.2 — index.html is served with its build-time version placeholder ("2.7.1")
patched to the real running version, not just corrected client-side after the
page loads. Follows the same import-order convention as the other API tests:
main.py refuses to import without SECRETNODE_API_KEY, so a shared default is
set before importing main."""

from __future__ import annotations

import os

os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import pytest
from fastapi.testclient import TestClient

import main  # noqa: E402  (must follow the env setup above)
import report as report_gen  # noqa: E402


@pytest.fixture
def client():
    return TestClient(main.app)


def test_index_html_does_not_leak_the_placeholder_version(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "2.7.1" not in r.text


def test_index_html_carries_the_real_version_in_title_and_footer(client):
    r = client.get("/")
    v = report_gen._TOOL_VERSION
    assert f"SecretNode v{v}" in r.text          # <title>
    assert f"v{v} — ATTACK SURFACE MONITOR" in r.text          # #version-line
    assert f"SECRETNODE v{v} — PASSIVE ASM SCANNER" in r.text  # #footer-version


def test_index_html_served_as_html_content_type(client):
    r = client.get("/")
    assert r.headers["content-type"].startswith("text/html")


def test_spa_fallback_for_unknown_path_also_carries_the_real_version(client):
    # Any path that doesn't resolve to a real static file falls back to
    # index.html (client-side routing) — that fallback must be patched too,
    # not just the exact "/" route.
    r = client.get("/some/unknown/client-route")
    assert r.status_code == 200
    assert "2.7.1" not in r.text
    assert f"v{report_gen._TOOL_VERSION}" in r.text


def test_a_real_static_asset_is_still_served_unpatched(client):
    # Guard against the fallback swallowing real static files: a genuine file
    # under frontend/ (a font) must still be served as itself, not as index.html.
    r = client.get("/static/fonts/share-tech-mono-400.woff2")
    assert r.status_code == 200
    assert "text/html" not in r.headers["content-type"]
