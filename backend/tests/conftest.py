"""Shared pytest configuration.

Records the collected test count so `test_docs_consistency.py` can check the
README badge against it. That badge claimed 805 for five releases while the
suite grew past a thousand — nobody notices a number that is only ever read by
strangers.

It also records whether this was a WHOLE-suite run, because the badge check is
only meaningful then. Running one file collects a handful of tests, and a check
that fails whenever a developer narrows their run is a check they will learn to
ignore — which is worse than not having it.
"""

from __future__ import annotations

import os

COLLECTED: dict[str, object] = {}


def _normalise(path: str) -> str:
    return os.path.normpath(path.split("::")[0])


def pytest_collection_modifyitems(session, config, items) -> None:
    COLLECTED["count"] = len(items)
    testpaths = {_normalise(p) for p in (config.getini("testpaths") or [])}
    invoked = {_normalise(a) for a in config.args}
    COLLECTED["full_run"] = bool(
        testpaths
        and invoked <= testpaths
        and not config.option.keyword
        and not config.option.markexpr
        # getattr, not attribute access: `last_failed` is supplied by the
        # cacheprovider plugin and is absent when it is disabled. The other
        # branches short-circuit before reaching it, so assuming it existed
        # failed on exactly one path — the whole-suite run this check is for.
        and not getattr(config.option, "last_failed", False)
    )
