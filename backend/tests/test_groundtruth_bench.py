"""
The full-coverage ground-truth corpus as a regression gate.

`bench/run_bench.py` remains the fast `make bench` check over 45 flat samples.
These assertions cover what that one cannot: that EVERY registered detector has
a specimen and fires on it, that the realistic decoys stay quiet, and that the
corpus is still a valid measuring instrument after the registry changes.

A new detector added without a specimen fails here, by design — a detector
nobody has ever seen fire is a detector nobody knows is broken.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import scanner
from bench import benchmark, groundtruth


class TestCorpusIsAValidInstrument:
    def test_build_self_validates(self):
        """build() raises if any specimen fails to match its own detector, is
        caught by the placeholder filter, or falls below its entropy floor."""
        c = groundtruth.build()
        assert c.specimens and c.decoys and c.files

    def test_every_detector_has_a_specimen(self):
        c = groundtruth.build()
        covered = {s.pattern for s in c.specimens}
        registered = {p.name for p in scanner.SECRET_PATTERNS}
        assert covered == registered, f"uncovered: {sorted(registered - covered)}"

    def test_corpus_is_deterministic(self):
        """Same seed, same bytes — otherwise runs are not comparable."""
        assert groundtruth.build().files == groundtruth.build().files

    def test_declared_values_are_actually_present_in_the_files(self):
        c = groundtruth.build()
        blob = "\n".join(c.files.values())
        for s in c.specimens:
            assert s.value in blob or s.value in json_escaped(blob), s.pattern

    def test_public_by_design_specimens_are_marked(self):
        c = groundtruth.build()
        public = {s.pattern for s in c.specimens if s.kind == "public"}
        assert public == {"Stripe Publishable Key", "Sentry DSN",
                          "PostHog Project API Key"}


def json_escaped(blob: str) -> str:
    """Source-map content is JSON-escaped, so a value inside it appears with
    backslash-escaped quotes around it rather than verbatim."""
    return blob.replace('\\"', '"')


class TestOfflineBenchmark:
    def test_every_detector_fires_on_its_own_specimen(self):
        c = groundtruth.build()
        report = benchmark._score(c, benchmark.run_offline(c))
        assert report["false_negatives"] == 0, report["missed_detectors"]
        assert report["mistyped"] == 0, report["mistyped_detectors"]

    def test_no_decoy_is_reported_as_a_secret(self):
        c = groundtruth.build()
        report = benchmark._score(c, benchmark.run_offline(c))
        assert report["false_positives"] == 0, report["false_positive_values"]

    def test_the_number_carries_its_caveat(self):
        """Recall is internal validity only. The qualifier ships with the
        number so it cannot be quoted without it."""
        c = groundtruth.build()
        report = benchmark._score(c, benchmark.run_offline(c))
        assert "INTERNAL validity" in report["validity_caveat"]

    def test_scoring_compares_on_the_capped_form(self):
        """Findings carry _cap_raw(value). Comparing against the full planted
        value scored every credential over 80 characters as both a miss and a
        false positive — seven of sixty-three."""
        c = groundtruth.build()
        long_ones = [s for s in c.specimens if len(s.value) > scanner.RAW_MATCH_CAP]
        assert long_ones, "corpus no longer exercises the cap"
        report = benchmark._score(c, benchmark.run_offline(c))
        assert report["true_positives"] == len(c.specimens)
