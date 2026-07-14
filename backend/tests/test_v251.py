"""
SecretNode v2.5.1 — deploy-resilience regression tests.

Locks in the fix for a real Raspberry Pi incident: a flaky piwheels install left
the uvloop C-extension missing, and main.py's unconditional `import uvloop` crashed
the service on startup — the dashboard rendered as a blank page. These tests prove
(1) the app imports and serves even when uvloop is unavailable, and (2) the index +
health endpoints actually return content (so a broken build is caught by CI, not by
a blank browser tab).
"""

import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_app_imports_without_uvloop():
    """The server must start even if uvloop is missing/broken (ARM64 wheel fail)."""
    code = (
        "import builtins\n"
        "_orig = builtins.__import__\n"
        "def _blocked(name, *a, **k):\n"
        "    if name == 'uvloop' or name.startswith('uvloop.'):\n"
        "        raise ImportError('simulated missing uvloop')\n"
        "    return _orig(name, *a, **k)\n"
        "builtins.__import__ = _blocked\n"
        "import main\n"
        "assert main._HAS_UVLOOP is False, 'expected uvloop-absent path'\n"
        "assert main.app is not None\n"
        "print('OK')\n"
    )
    env = dict(os.environ, SECRETNODE_API_KEY="test-key-for-pytest")
    r = subprocess.run([sys.executable, "-c", code], cwd=BACKEND_DIR,
                       capture_output=True, text=True, env=env)
    assert r.returncode == 0, f"app failed to import without uvloop:\n{r.stderr}"
    assert "OK" in r.stdout


def _client():
    import main
    from fastapi.testclient import TestClient
    return TestClient(main.app)


def test_health_endpoint_serves():
    r = _client().get("/api/health")
    assert r.status_code == 200
    assert "gemini_configured" in r.json()


def test_index_served_and_offline():
    """Index must return the dashboard HTML with no external CDN references
    (Tailwind/Google-Fonts were removed for offline rendering)."""
    r = _client().get("/")
    assert r.status_code == 200
    body = r.text
    assert "SecretNode" in body
    for cdn in ("cdn.tailwindcss", "fonts.googleapis", "fonts.gstatic"):
        assert cdn not in body, f"unexpected external CDN reference: {cdn}"
