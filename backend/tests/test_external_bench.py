"""
The external-validity harness must be safe to run in CI, which has no network
and no business fetching a third-party repository during a test run.

These tests never touch the network. They pin the two properties that decide
whether the number the harness prints means anything: that a missing corpus is
reported as a skip rather than as a pass, and that pattern fragments are kept
out of the denominator.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

from bench import external


class TestOfflineIsASkipNotAPass:
    def test_no_corpus_and_no_network_returns_none(self, monkeypatch, tmp_path):
        monkeypatch.setattr(external, "CACHE", tmp_path / "absent.json")
        assert external.load_corpus(offline=True) is None

    def test_main_exits_cleanly_with_no_corpus(self, monkeypatch, tmp_path, capsys):
        """A skipped measurement must not fail the build — and must not be
        mistaken for a measurement that passed."""
        monkeypatch.setattr(external, "CACHE", tmp_path / "absent.json")
        monkeypatch.setattr(sys, "argv", ["external", "--offline"])
        assert external.main() == 0
        out = capsys.readouterr().out
        assert "Skipped" in out
        assert "not a pass" in out

    def test_a_corrupt_cache_does_not_raise(self, monkeypatch, tmp_path):
        bad = tmp_path / "corrupt.json"
        bad.write_text("{not json")
        monkeypatch.setattr(external, "CACHE", bad)
        assert external.load_corpus(offline=True) is None


class TestFragmentsStayOutOfTheDenominator:
    """gitleaks builds many samples from pattern fragments. Scoring
    `api_org_(?i:[a-z]{34})` as a missed credential would understate recall by
    counting something no scanner could match."""

    FILES = {
        "acme": (
            'package rules\n'
            'RuleID: "acme-key"\n'
            '\ttps := []string{"AKIAZZZZZZZZZZZZZZZZ7"}\n'                # real shape
            '\tregex := "api_org_(?i:[a-z]{34})"\n'                       # fragment
            '\tother := "[0-9]{15,25}-[a-zA-Z0-9]{20,40}"\n'              # fragment
            '\turl := "https://acme.test/docs/keys12345"\n'               # url
        ),
    }

    def test_fragments_are_dropped(self):
        values = [v for _p, _r, v in external.specimens(self.FILES)]
        assert not any("(?i" in v for v in values)
        assert not any(v.startswith("[0-9]") for v in values)

    def test_urls_are_dropped(self):
        values = [v for _p, _r, v in external.specimens(self.FILES)]
        assert not any(v.startswith("http") for v in values)

    def test_a_real_specimen_survives(self):
        values = [v for _p, _r, v in external.specimens(self.FILES)]
        assert "AKIAZZZZZZZZZZZZZZZZ7" in values

    def test_specimens_are_deduplicated(self):
        files = dict(self.FILES)
        files["acme2"] = self.FILES["acme"]
        values = [v for _p, _r, v in external.specimens(files)]
        assert len(values) == len(set(values))


class TestDetectorCoverageLookup:
    """The in-scope/no-detector split is the whole point of the report: only the
    first bucket is a defect. If the lookup is wrong, so is that distinction."""

    def test_a_covered_provider_is_recognised(self):
        assert external._has_detector("stripe")
        assert external._has_detector("openai")

    def test_an_uncovered_provider_is_recognised(self):
        assert not external._has_detector("freemius")

    def test_gcp_aliases_to_google(self):
        assert external._has_detector("gcp")
