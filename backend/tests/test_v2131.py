"""
v2.13.1 — three defects a live deep scan of pepsico.com exposed.

Every one of them is invisible to a unit test written against tidy input, and
every one of them was visible in ninety seconds of reading the actual report
next to the actual code. That is the theme worth keeping:

  • The comment stripper shipped in v2.12.6 was defeated by one regex literal,
    so the report still listed `i.test` and `caniuse.com` as the client's
    "connected infrastructure" — the exact strings that release claimed to have
    removed. It failed open and silently, on input no test had used.
  • 143 posture issues were counted in three places and itemised in none. The
    SARIF was `"results": []` and the CSV a bare header row.
  • The verdict said CLEAN "across the domain" after scanning 26 of 83 live
    hosts, alphabetically.
"""

from __future__ import annotations

import csv
import io
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import report as report_gen
import surface


# ─────────────────────────────────────────────────────────────────────────────
# 1 · The comment stripper vs. regex literals
# ─────────────────────────────────────────────────────────────────────────────

class TestStripperSurvivesRegexLiterals:
    """`/['"]/g` is ordinary in a bundle that normalises quoting. Before this
    fix, the apostrophe inside it opened a string that never closed, and every
    comment in the rest of the file survived."""

    # Deliberately the shape seen in the wild: a quote-class regex, then the
    # comments whose contents reached a client's report.
    BUNDLE = "\n".join([
        "var q = /['\"]/g;",
        "//i.test(v)",
        "//caniuse.com/flexbox",
        'var real = "https://api.real.example.com/v1";',
    ])

    def test_comments_after_a_quote_class_regex_are_still_stripped(self):
        out = surface.strip_js_comments(self.BUNDLE)
        assert "i.test" not in out
        assert "caniuse.com" not in out

    def test_the_pepsico_hosts_no_longer_appear(self):
        hosts = surface.extract_referenced_hosts(self.BUNDLE, "https://acme.test/a.js")
        assert "i.test" not in hosts
        assert "caniuse.com" not in hosts

    def test_real_hosts_in_strings_still_survive(self):
        """The fix must not buy precision by dropping genuine references."""
        hosts = surface.extract_referenced_hosts(self.BUNDLE, "https://acme.test/a.js")
        assert "api.real.example.com" in hosts

    def test_the_regex_literal_is_consumed_not_left_in_place(self):
        """v2.13.1 left the literal's text alone, reasoning that a regex is code
        rather than a comment. v2.14.2 reversed that: the literal's own escaped
        slashes were being read as a protocol-relative host. Its extent is still
        what stops a quote inside it opening a string — the length and the line
        count are unchanged."""
        src = "var re = /['\"]/g;\nvar y = 1;\n"
        out = surface.strip_js_comments(src)
        assert len(out) == len(src)
        assert out.count("\n") == src.count("\n")
        assert "var y = 1;" in out


class TestDivisionIsNotMistakenForARegex:
    """The opposite error is the expensive one: reading division as a regex
    literal blanks real code and drops hosts from the graph. Resolve toward
    division whenever the previous token can end a value."""

    def test_plain_division_still_lets_the_comment_be_stripped(self):
        out = surface.strip_js_comments("a / b //drop.example.com")
        assert "drop.example.com" not in out

    def test_division_after_a_closing_paren(self):
        out = surface.strip_js_comments("var x = (a+b)/c/d; //drop.example.com")
        assert "drop.example.com" not in out

    def test_division_after_an_index(self):
        out = surface.strip_js_comments("var p = a[0] / 2; //drop.example.com")
        assert "drop.example.com" not in out

    def test_regex_after_a_keyword_is_a_regex_not_division(self):
        """`return` ends in a letter but does not end a value."""
        out = surface.strip_js_comments('return /x"y/.test(s); //drop.example.com')
        assert "drop.example.com" not in out

    def test_division_after_a_string_literal(self):
        """A closed string is a value, so the slash after it divides. Caught by
        an edge case rather than by the suite: tracking the closing quote made
        `prev` a quote character, which the classifier read as an operator."""
        out = surface.strip_js_comments('var r = "abc" / 2; //drop.example.com')
        assert "drop.example.com" not in out

    def test_an_unterminated_slash_does_not_swallow_the_file(self):
        """A regex cannot span a line, so a misread costs one line, not the rest
        of the bundle."""
        src = "var a = 1 / 2;\n//drop.example.com\nvar u = 'https://keep.example.com/x';"
        out = surface.strip_js_comments(src)
        assert "drop.example.com" not in out
        assert "keep.example.com" in out

    def test_length_and_newlines_are_preserved(self):
        src = "a\n/* x\n   y\n*/\nb\n"
        out = surface.strip_js_comments(src)
        assert len(out) == len(src)
        assert out.count("\n") == src.count("\n")


class TestValidHostRejectsEmptyLabels:
    def test_leading_dot_is_not_a_host(self):
        """`.test` reached a client report. Only the trailing dot was checked."""
        assert not surface._valid_host(".test")

    def test_doubled_dot_is_not_a_host(self):
        assert not surface._valid_host("a..b")

    def test_trailing_dot_is_still_rejected(self):
        assert not surface._valid_host("example.com.")

    def test_ordinary_hosts_still_pass(self):
        assert surface._valid_host("api.real.example.com")


# ─────────────────────────────────────────────────────────────────────────────
# 2 · Posture findings must reach the deliverables
# ─────────────────────────────────────────────────────────────────────────────

# Field names mirror posture.PostureFinding.to_dict() exactly — `name`, not
# `issue`. Writing the fixture from the dataclass rather than from memory is the
# point: a fixture that invents a shape tests nothing the pipeline will ever see.
# `_host` is added by orchestrator._aggregate on deep scans.
POSTURE = [
    {
        "name": "Missing HSTS",
        "severity": "MEDIUM",
        "cwe": "CWE-319",
        "evidence": "no Strict-Transport-Security header",
        "remediation": "Send Strict-Transport-Security with a max-age of at least 31536000.",
        "category": "Security Posture",
        "found_at": "2026-08-21T18:00:00+00:00",
        "_host": "a.acme.test",
    },
    {
        "name": "Missing Content-Security-Policy",
        "severity": "HIGH",
        "cwe": "CWE-1021",
        "evidence": "no CSP header",
        "remediation": "Define a Content-Security-Policy.",
        "category": "Security Posture",
        "found_at": "2026-08-21T18:00:00+00:00",
        "_host": "a.acme.test",
    },
]

CLEAN_SCAN = {
    "scan_id": "s-1",
    "target_url": "acme.test",
    "confirmed_findings": [],
    "needs_review_findings": [],
    "informational_findings": [],
    "posture_findings": POSTURE,
}


class TestPostureReachesCSV:
    def rows(self, scan):
        out = report_gen.generate_csv_report(scan)
        return list(csv.DictReader(io.StringIO(out)))

    def test_posture_issues_are_written(self):
        """143 issues and a bare header row was the pepsico.com CSV."""
        rows = self.rows(CLEAN_SCAN)
        assert len(rows) == len(POSTURE)

    def test_a_posture_row_carries_its_severity_and_cwe(self):
        row = next(r for r in self.rows(CLEAN_SCAN)
                   if "Content-Security-Policy" in r["secret_type"])
        assert row["severity"] == "HIGH"
        assert row["cwe"] == "CWE-1021"

    def test_posture_rows_are_labelled_as_posture_not_as_credentials(self):
        """A client sorting by status must not read these as leaked keys."""
        for row in self.rows(CLEAN_SCAN):
            assert row["status"] == "POSTURE"

    def test_a_scan_with_no_posture_still_produces_only_a_header(self):
        rows = self.rows({**CLEAN_SCAN, "posture_findings": []})
        assert rows == []


class TestPostureReachesSARIF:
    def results(self, scan):
        return json.loads(report_gen.generate_sarif_report(scan))["runs"][0]["results"]

    def test_posture_issues_appear_as_results(self):
        """`"results": []` while the HTML claimed 143 issues is the two
        deliverables disagreeing about the same scan."""
        assert len(self.results(CLEAN_SCAN)) == len(POSTURE)

    def test_each_posture_result_names_a_declared_rule(self):
        """A result whose ruleId is not in the driver's catalog is invalid
        SARIF, and GitHub code scanning drops it."""
        sarif = json.loads(report_gen.generate_sarif_report(CLEAN_SCAN))
        run = sarif["runs"][0]
        declared = {r["id"] for r in run["tool"]["driver"]["rules"]}
        for res in run["results"]:
            assert res["ruleId"] in declared, res["ruleId"]

    def test_posture_results_carry_a_location(self):
        for res in self.results(CLEAN_SCAN):
            uri = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            assert uri

    def test_posture_severity_maps_to_a_sarif_level(self):
        for res in self.results(CLEAN_SCAN):
            assert res["level"] in {"error", "warning", "note"}


class TestPostureReachesDeepScanHTML:
    DEEP = {
        "domain": "acme.test",
        "scan_id": "d-1",
        "generated_at": "2026-08-21T18:08:17+00:00",
        "subdomains": ["a.acme.test"],
        "live_hosts": ["a.acme.test"],
        "hosts": [{
            "host": "a.acme.test", "url": "https://a.acme.test", "status": "scanned",
            "assets": 3, "confirmed": 0, "needs_review": 0, "posture_issues": 2,
            "note": "",
        }],
        "totals": {"confirmed": 0, "needs_review": 0, "posture_issues": 2, "assets": 3},
        "confirmed_findings": [],
        "needs_review_findings": [],
        "posture_findings": POSTURE,
        "takeovers": [],
        "historical_urls": [],
        "external_hosts": [],
    }

    def test_the_issues_are_itemised_not_merely_counted(self):
        """The deep-scan report showed `143` in a tile and named none of them."""
        html = report_gen.generate_deep_scan_html(self.DEEP)
        assert "Missing HSTS" in html
        assert "Missing Content-Security-Policy" in html

    def test_remediation_is_shown(self):
        html = report_gen.generate_deep_scan_html(self.DEEP)
        assert "Strict-Transport-Security" in html

    def test_evidence_is_escaped(self):
        hostile = {**self.DEEP, "posture_findings": [
            {**POSTURE[0], "evidence": "<script>alert(1)</script>"},
        ]}
        html = report_gen.generate_deep_scan_html(hostile)
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html


# ─────────────────────────────────────────────────────────────────────────────
# 3 · The verdict must state its coverage
# ─────────────────────────────────────────────────────────────────────────────

class TestVerdictStatesCoverage:
    def deep(self, live: int, scanned: int) -> dict:
        hosts = [{
            "host": f"h{i}.acme.test", "url": f"https://h{i}.acme.test",
            "status": "scanned", "assets": 1, "confirmed": 0,
            "needs_review": 0, "posture_issues": 0, "note": "",
        } for i in range(scanned)]
        return {
            "domain": "acme.test", "scan_id": "d-2",
            "generated_at": "2026-08-21T18:08:17+00:00",
            "subdomains": [f"h{i}.acme.test" for i in range(live)],
            "live_hosts": [f"h{i}.acme.test" for i in range(live)],
            "hosts": hosts,
            "totals": {"confirmed": 0, "needs_review": 0,
                       "posture_issues": 0, "assets": scanned},
            "confirmed_findings": [], "needs_review_findings": [],
            "posture_findings": [], "takeovers": [],
            "historical_urls": [], "external_hosts": [],
        }

    def test_partial_coverage_is_named_in_the_verdict(self):
        """26 of 83 hosts, and the banner said 'across the domain'."""
        html = report_gen.generate_deep_scan_html(self.deep(live=83, scanned=26))
        assert "PARTIAL" in html

    def test_partial_coverage_states_both_numbers(self):
        html = report_gen.generate_deep_scan_html(self.deep(live=83, scanned=26))
        assert "26" in html and "83" in html

    def test_partial_coverage_does_not_claim_the_whole_domain(self):
        html = report_gen.generate_deep_scan_html(self.deep(live=83, scanned=26))
        assert "No confirmed credential exposures across the domain" not in html

    def test_full_coverage_still_reads_clean(self):
        """A scan that really did cover every live host must not be hedged."""
        html = report_gen.generate_deep_scan_html(self.deep(live=12, scanned=12))
        assert "PARTIAL" not in html
        assert "CLEAN" in html

    def test_findings_still_outrank_coverage_in_the_verdict(self):
        """Partial coverage must never soften a real exposure."""
        deep = self.deep(live=83, scanned=26)
        deep["totals"]["confirmed"] = 1
        deep["confirmed_findings"] = [{
            "secret_type": "AWS Access Key", "severity": "CRITICAL",
            "source_url": "https://h1.acme.test/a.js", "raw_match": "AKIA" + "X" * 16,
            "confidence": 95, "host": "h1.acme.test",
        }]
        html = report_gen.generate_deep_scan_html(deep)
        assert "CLEAN" not in html
