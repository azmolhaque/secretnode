#!/usr/bin/env python3
"""
Single source of truth for the SecretNode version string.

Every surface that stamps a version — the API banner, client reports, the
Discord alerter — reads it from here, which in turn reads pyproject.toml. The
alternative (a literal per module) is how the Discord alerter ended up still
announcing "v2.4.0" long after the tool shipped 2.7.9: nothing fails when a
hardcoded string goes stale, it just quietly misreports which build produced a
finding, and a client correlating an alert against a report sees two tools.
"""

from __future__ import annotations

from pathlib import Path

# Used only when pyproject.toml is unreadable (an odd install layout, a
# stripped container). Keep it in step with pyproject on every release.
_FALLBACK_VERSION = "2.14.1"


def read_version() -> str:
    """Parse `version = "x.y.z"` out of the project's pyproject.toml."""
    try:
        pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
        for line in pyproject.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if s.startswith("version") and "=" in s:
                return s.split("=", 1)[1].strip().strip('"').strip("'")
    except Exception:
        pass
    return _FALLBACK_VERSION


TOOL_VERSION = read_version()
