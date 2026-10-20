"""v2.23.0 — the detector registry gets its own module.

`scanner.py` was 5,208 lines and roughly 2,000 of them were the registry: 111
detectors, their per-provider remediation, and the helpers that build them. A
long flat table that every release edits was sharing a file with HTTP fetching,
an adaptive throttle, an asset cache, AI validation and the scan orchestrator.

These tests guard the two properties that make the split worth having, because
a module boundary with nothing asserting it is a comment.
"""

from __future__ import annotations

import ast
import pathlib
import re

import patterns
import scanner

PATTERNS_SRC = pathlib.Path(patterns.__file__).read_text(encoding="utf-8")


# ── The boundary itself ──────────────────────────────────────────────────────

def test_the_registry_does_not_import_the_scanner():
    """One direction only. The registry is a declaration; the scanner reads it.
    An import the other way would make the dependency circular and invite the
    table to start reaching for fetch state."""
    tree = ast.parse(PATTERNS_SRC)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert imported == {"__future__", "re", "dataclasses"}, (
        f"patterns.py should import only re and dataclasses, got {sorted(imported)}")


def test_the_registry_is_pure():
    """No environment reads, no I/O, no async. Everything here is a constant or
    a function of its arguments, which is what makes the table safe to read end
    to end and safe to import from a benchmark."""
    for forbidden in ("os.environ", "getenv", "open(", "httpx", "asyncio",
                      "async def", "await "):
        assert forbidden not in PATTERNS_SRC, f"patterns.py contains {forbidden!r}"


def test_every_name_the_split_moved_is_still_reachable_through_scanner():
    """Callers were not asked to care that the table moved. This project's own
    tests and benchmarks reach for several of these by name, including private
    ones, so the re-export list is load-bearing rather than cosmetic."""
    for name in ("SecretPattern", "SECRET_PATTERNS", "PATTERN_BY_NAME",
                 "GENERIC_SECRET_TYPE", "_DEFAULT_REMEDIATION", "_REMEDIATION",
                 "_REGEX_META", "_contextual", "_literal_prefix",
                 "_keyword_prefilter", "_derive_prefilter",
                 "_alternation_is_nested_below"):
        assert hasattr(scanner, name), f"scanner.{name} disappeared in the split"
        assert getattr(scanner, name) is getattr(patterns, name), (
            f"scanner.{name} is not the same object as patterns.{name}")


def test_patching_the_pattern_list_through_scanner_still_takes_effect():
    """The one hazard the split could have introduced.

    Tests stub `scanner.SECRET_PATTERNS` to isolate a detector. Had
    `extract_secrets` kept reading the list through `patterns.SECRET_PATTERNS`,
    that stub would quietly do nothing and the test would still pass — defanged
    rather than failing, which is the worse outcome.
    """
    stub = [patterns.SecretPattern(
        name="Stub Detector", regex=re.compile(r"\b(STUBSTUBSTUB[A-Z0-9]{12})\b"),
        description="test only", severity="LOW")]
    real = scanner.SECRET_PATTERNS
    scanner.SECRET_PATTERNS = stub
    try:
        hits = scanner.extract_secrets(
            "t", "https://t.test", "https://t.test/a.js",
            'const v = "STUBSTUBSTUBQ7W2E9R4T6Y1";\n')
        assert [h.secret_type for h in hits] == ["Stub Detector"]
        # And the real registry must be out of the way, or the stub is additive
        # and proves nothing about isolation.
        assert scanner.extract_secrets(
            "t", "https://t.test", "https://t.test/a.js",
            'const k = "AKIAQ7W2E9R4T6Y1U3I5";\n') == []
    finally:
        scanner.SECRET_PATTERNS = real
    assert len(scanner.SECRET_PATTERNS) == 111


# ── The split changed nothing about what the registry says ───────────────────

def test_the_registry_is_fully_built_at_import_time():
    """Both post-processing passes — derived prefilters and the remediation
    backstop — must have run. Moving the table risked leaving one of them in
    the old file, which would read as a registry that is merely incomplete
    rather than as an error."""
    assert len(scanner.SECRET_PATTERNS) == 111
    assert sum(1 for p in scanner.SECRET_PATTERNS if p.prefilter) == 75
    generic = scanner.PATTERN_BY_NAME[scanner.GENERIC_SECRET_TYPE]
    assert not generic.prefilter, "the catch-all must never be prefiltered"
    # The remediation backstop: no CRITICAL or HIGH detector is left on the
    # default text, which v2.19.0 established and the split must not undo.
    defaults = [p.name for p in scanner.SECRET_PATTERNS
                if p.severity in ("CRITICAL", "HIGH")
                and p.remediation == scanner._DEFAULT_REMEDIATION]
    assert not defaults, f"generic remediation returned for {defaults[:5]}"


def test_scanner_is_meaningfully_smaller_than_it_was():
    """The point of the exercise, asserted so a future merge cannot quietly
    undo it by pasting the table back. 5,208 lines was the before."""
    lines = len(pathlib.Path(scanner.__file__).read_text(
        encoding="utf-8").splitlines())
    assert lines < 3600, f"scanner.py is back up to {lines} lines"
