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


class TestSampleExtraction:
    """The harness parses what gitleaks DECLARES, not whatever is quoted.

    The first version scraped every quoted string of 20+ characters from a rule
    file. Measured against the real corpus that produced ten reported "in-scope
    misses" of which three were gitleaks' own declared false positives, six were
    scraped from neither sample list, and one was a timestamp sliced out of a
    longer entry — essentially no defects at all, in the bucket the report calls
    the only one that is a defect. It also dropped every line containing
    `secrets.NewSecret`, which is where most of the corpus lives.
    """

    FILES = {
        "acme": (
            "package rules\n"
            "\nfunc AcmeKey() *config.Rule {\n"
            '\tr := config.Rule{\n'
            '\t\tRuleID: "acme-key",\n'
            '\t\tKeywords: []string{"acme_"},\n'
            "\t}\n"
            '\ttps := utils.GenerateSampleSecrets("acme", "acme_"+secrets.NewSecret(utils.Hex("32")))\n'
            "\tfps := []string{\n"
            '\t\t`acme_00000000000000000000000000000000`,\n'
            "\t}\n"
            "\treturn utils.Validate(r, tps, fps)\n"
            "}\n"
        ),
    }

    def test_true_and_false_positives_are_kept_apart(self):
        kinds = {k for _p, _r, _v, k in external.specimens(self.FILES)}
        assert kinds == {"tp", "fp"}

    def test_a_generated_sample_is_expanded_not_dropped(self):
        """`"acme_"+secrets.NewSecret(utils.Hex("32"))` must become a concrete
        37-character specimen. Dropping it as a "fragment" is what discarded
        most of the corpus."""
        tps = [v for _p, _r, v, k in external.specimens(self.FILES) if k == "tp"]
        assert len(tps) == 1
        assert tps[0].startswith("acme_")
        assert len(tps[0]) == len("acme_") + 32
        assert all(c in "0123456789abcdef" for c in tps[0][5:])

    def test_the_declared_false_positive_is_labelled_fp(self):
        fps = [v for _p, _r, v, k in external.specimens(self.FILES) if k == "fp"]
        assert fps == ["acme_00000000000000000000000000000000"]

    def test_the_keywords_field_is_not_mistaken_for_a_sample(self):
        """`Keywords: []string{"acme_"}` is a match hint, not a credential. Bare
        prefixes cannot match any detector, so each one scraped from that field
        was scored as a missed credential — 91 of them across the real corpus."""
        values = [v for _p, _r, v, _k in external.specimens(self.FILES)]
        assert "acme_" not in values

    def test_specimens_are_deduplicated(self):
        files = dict(self.FILES)
        files["acme2"] = self.FILES["acme"]
        values = [v for _p, _r, v, _k in external.specimens(files)]
        assert len(values) == len(set(values))

    def test_a_rule_with_no_samples_yields_nothing(self):
        files = {"empty": ("package rules\n\nfunc Empty() *config.Rule {\n"
                           '\tr := config.Rule{RuleID: "empty"}\n'
                           "\treturn utils.Validate(r, nil, nil)\n}\n")}
        assert external.specimens(files) == []


class TestCharClassExpansion:
    def test_a_range_class_expands_to_the_right_length(self):
        import random
        v = external._expand_class("[A-Z2-7]{16}", random.Random(0))
        assert len(v) == 16
        assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for c in v)

    def test_a_helper_call_expands(self):
        import random
        v = external._expand_atom('secrets.NewSecret(utils.AlphaNumeric("20"))',
                                  random.Random(0))
        assert v is not None and len(v) == 20

    def test_an_unresolvable_piece_voids_the_whole_expression(self):
        """A partially-expanded sample is a string no scanner could match.
        Counting it as a miss repeats the mistake this rewrite corrects."""
        import random
        assert external._expand_expr('"x"+someUnknownHelper()', random.Random(0)) is None


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
