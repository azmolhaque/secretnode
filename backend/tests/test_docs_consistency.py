"""
The README's badges and counts must match the code they describe.

Every one of these drifted at some point, and each drifted silently, because a
number in a badge is read by strangers rather than by anyone who could notice it
was wrong. The tests badge sat at 805 for five releases while the suite grew past
a thousand; the pattern count has been corrected by hand at every release that
touched the registry, which is a process that works right up until it doesn't.

These are cheap and they fail loudly, which is the whole argument for them.
"""

from __future__ import annotations

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import pytest  # noqa: E402

import scanner  # noqa: E402
import version  # noqa: E402
from tests import conftest  # noqa: E402

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _readme() -> str:
    with open(os.path.join(_ROOT, "README.md"), encoding="utf-8") as fh:
        return fh.read()


def _pyproject() -> str:
    with open(os.path.join(_ROOT, "pyproject.toml"), encoding="utf-8") as fh:
        return fh.read()


def test_version_badge_matches_the_package_version():
    badge = re.search(r"badge/version-([0-9]+\.[0-9]+\.[0-9]+)-", _readme())
    assert badge, "README has no version badge"
    assert badge.group(1) == version.read_version()


def test_pyproject_version_matches_the_package_version():
    declared = re.search(r'^version = "([^"]+)"', _pyproject(), re.M)
    assert declared, "pyproject.toml has no version"
    assert declared.group(1) == version.read_version()


def test_every_stated_pattern_count_matches_the_registry():
    """The README states it in three places, and they must agree with the code."""
    n = len(scanner.SECRET_PATTERNS)
    stated = re.findall(r"\((\d+) patterns", _readme()) + re.findall(
        r"\((\d+) patterns,", _readme())
    assert stated, "README no longer states a pattern count — update this test"
    for value in stated:
        assert int(value) == n, f"README says {value} patterns, registry has {n}"


def test_tests_badge_matches_the_collected_suite():
    """Self-referential on purpose: the count comes from this very collection.

    Skipped on a narrowed run — one file, `-k`, `--lf`. The badge describes the
    whole suite, so a partial collection has nothing to say about it, and a
    check that cries wolf whenever someone runs a single file is a check that
    gets ignored.
    """
    if not conftest.COLLECTED.get("full_run"):
        pytest.skip("partial run — the badge describes the whole suite")
    collected = conftest.COLLECTED.get("count")
    if collected is None:                       # pragma: no cover - direct call
        pytest.skip("no collection count recorded")
    badge = re.search(r"badge/tests-(\d+)%20passing", _readme())
    assert badge, "README has no tests badge"
    assert int(badge.group(1)) == collected, (
        f"README badge says {badge.group(1)} tests, the suite collects {collected}")
