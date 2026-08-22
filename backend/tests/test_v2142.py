"""
v2.14.2 — three defects from a live deep scan of a 258-subdomain estate.

The first is the interesting one, because v2.13.1 had already fixed `i.test`
reaching a client's "external hosts" list — and the new report listed it again.
The bundle the user supplied came back clean when tested directly, which ruled
out the construct that release was written for and pointed at a different one:

    /^https?:\\/\\//i.test(u)

the idiomatic absolute-URL test. v2.13.1 taught the stripper to *recognise* a
regex literal but deliberately left its text in place ("a regex is code, not a
comment"). Correct for finding comments, wrong for what runs next: that
literal's own escaped slashes and terminator spell `//i.test`, which `_ABS_URL`
reads as a protocol-relative host. The fix removed a symptom's cause and left
another cause standing.

The other two came from reading the same report against its own CSV.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import posture
import report as report_gen
import surface


# ─────────────────────────────────────────────────────────────────────────────
# 1 · A regex literal's own slashes are not a hostname
# ─────────────────────────────────────────────────────────────────────────────

class TestRegexBodiesAreBlanked:
    def test_the_absolute_url_test_yields_no_host(self):
        """`/^https?:\\/\\//i.test(u)` is in more or less every bundle, and its
        escaped slashes plus terminator spell `//i.test`."""
        src = r'var r=/^https?:\/\//i.test(u);'
        assert surface.extract_referenced_hosts(src, "https://acme.test/a.js") == set()

    def test_the_form_v2131_fixed_stays_fixed(self):
        src = 'if(/csl-left-margin/i.test(t.bib)){}'
        assert surface.extract_referenced_hosts(src, "https://acme.test/a.js") == set()

    def test_a_real_host_in_a_string_still_survives(self):
        """The fix must not buy precision by dropping genuine references."""
        src = 'var a="https://api.real.example.com/v1";var r=/x/i.test(y);'
        hosts = surface.extract_referenced_hosts(src, "https://acme.test/a.js")
        assert "api.real.example.com" in hosts

    def test_blanking_costs_nothing_that_was_extractable(self):
        """A host inside a pattern carries escaped dots, which `_valid_host`
        rejects — so it was never extractable, before or after."""
        src = r'var r=/^https:\/\/api\.example\.com/.test(u);'
        assert surface.extract_referenced_hosts(src, "https://acme.test/a.js") == set()

    def test_division_is_still_not_eaten_as_a_regex(self):
        out = surface.strip_js_comments("var p=a[0]/2; //drop.example.com")
        assert "drop.example.com" not in out

    def test_length_and_newlines_are_preserved(self):
        src = "var r=/ab/g;\nvar y=1;\n"
        out = surface.strip_js_comments(src)
        assert len(out) == len(src)
        assert out.count("\n") == src.count("\n")

    def test_markup_is_not_mistaken_for_a_regex_literal(self):
        """`strip_js_comments` runs over whole responses, so it sees HTML too,
        and `</script>` opens with a slash exactly where a literal would.
        Scanning on swallows up to the next `/` — the one inside the following
        URL — which blanked a real external host out of the graph. Harmless
        while the text was left in place; a dropped finding once it was blanked.
        Caught by a test predating all of this work."""
        html_src = ('<script src="https://cdn.jsdelivr.net/x.js"></script>'
                    '<img src="https://analytics.example.com/p.gif">')
        hosts = surface.extract_referenced_hosts(html_src, "https://site.test/")
        assert "cdn.jsdelivr.net" in hosts
        assert "analytics.example.com" in hosts

    def test_a_regex_ends_a_value_so_the_next_slash_divides(self):
        """After a literal, `/` is division — otherwise the following comment
        would be swallowed as a second literal."""
        out = surface.strip_js_comments("var q=/ab/g; //drop.example.com")
        assert "drop.example.com" not in out


# ─────────────────────────────────────────────────────────────────────────────
# 2 · Grouped posture evidence must stay attributed
# ─────────────────────────────────────────────────────────────────────────────

class TestPostureEvidenceIsNotCollapsed:
    """The real report grouped two hosts under one heading and printed
    `server: AmazonS3` for both — while the CSV showed the second was actually
    disclosing `Microsoft-IIS/10.0`. For version disclosure the evidence IS the
    finding, so collapsing it destroyed the only actionable content."""

    def _deep(self, findings):
        return {
            "domain": "acme.test", "scan_id": "d-1",
            "generated_at": "2026-08-21T20:11:00+00:00",
            "subdomains": [], "live_hosts": ["a.acme.test", "b.acme.test"],
            "hosts": [
                {"host": "a.acme.test", "url": "https://a.acme.test", "assets": 1,
                 "confirmed": 0, "needs_review": 0, "posture_issues": 1,
                 "error": None, "status": "", "note": ""},
                {"host": "b.acme.test", "url": "https://b.acme.test", "assets": 1,
                 "confirmed": 0, "needs_review": 0, "posture_issues": 1,
                 "error": None, "status": "", "note": ""},
            ],
            "totals": {"confirmed": 0, "needs_review": 0, "posture_issues": len(findings),
                       "assets": 2, "live_hosts": 2},
            "confirmed_findings": [], "needs_review_findings": [],
            "posture_findings": findings, "takeovers": [],
            "historical_urls": [], "external_hosts": [],
        }

    DIFFERING = [
        {"name": "Version disclosure via server", "severity": "LOW", "cwe": "CWE-200",
         "evidence": "server: AmazonS3", "remediation": "Remove the header.",
         "found_at": "2026-08-21T20:09:00+00:00", "_host": "a.acme.test"},
        {"name": "Version disclosure via server", "severity": "LOW", "cwe": "CWE-200",
         "evidence": "server: Microsoft-IIS/10.0", "remediation": "Remove the header.",
         "found_at": "2026-08-21T20:10:00+00:00", "_host": "b.acme.test"},
    ]

    IDENTICAL = [
        {"name": "Missing HSTS", "severity": "MEDIUM", "cwe": "CWE-319",
         "evidence": "No Strict-Transport-Security header on an HTTPS response.",
         "remediation": "Add HSTS.", "found_at": "2026-08-21T20:09:00+00:00",
         "_host": "a.acme.test"},
        {"name": "Missing HSTS", "severity": "MEDIUM", "cwe": "CWE-319",
         "evidence": "No Strict-Transport-Security header on an HTTPS response.",
         "remediation": "Add HSTS.", "found_at": "2026-08-21T20:10:00+00:00",
         "_host": "b.acme.test"},
    ]

    def test_both_pieces_of_differing_evidence_appear(self):
        html_out = report_gen.generate_deep_scan_html(self._deep(self.DIFFERING))
        assert "AmazonS3" in html_out
        assert "Microsoft-IIS/10.0" in html_out

    def test_differing_evidence_is_attributed_to_its_host(self):
        html_out = report_gen.generate_deep_scan_html(self._deep(self.DIFFERING))
        assert "b.acme.test: server: Microsoft-IIS/10.0" in html_out

    def test_identical_evidence_is_still_shown_once(self):
        """Grouping exists so one missing header across many hosts reads as one
        fix. Repeating identical evidence per host would undo that."""
        html_out = report_gen.generate_deep_scan_html(self._deep(self.IDENTICAL))
        assert html_out.count("No Strict-Transport-Security header") == 1

    def test_the_hosts_are_still_grouped_into_one_row(self):
        html_out = report_gen.generate_deep_scan_html(self._deep(self.DIFFERING))
        assert html_out.count("Version disclosure via server") == 1

    def test_evidence_is_escaped(self):
        hostile = [{**self.DIFFERING[0], "evidence": "<script>alert(1)</script>"},
                   self.DIFFERING[1]]
        html_out = report_gen.generate_deep_scan_html(self._deep(hostile))
        assert "<script>alert(1)</script>" not in html_out
        assert "&lt;script&gt;" in html_out


# ─────────────────────────────────────────────────────────────────────────────
# 3 · A product name is not a version
# ─────────────────────────────────────────────────────────────────────────────

class TestVersionDisclosureNeedsAVersion:
    def _flagged(self, server: str) -> bool:
        found = posture.analyze_security_headers({"Server": server}, "https://x.test/")
        return any("Version disclosure" in f.name for f in found)

    def test_amazons3_is_not_a_version(self):
        """The S3 in AmazonS3 is a product name. `any(c.isdigit())` called it a
        leaked version in a client report."""
        assert not self._flagged("AmazonS3")

    def test_names_without_releases_are_not_flagged(self):
        for value in ("cloudflare", "Apache", "nginx", "gws", "openresty"):
            assert not self._flagged(value), value

    def test_real_releases_are_still_flagged(self):
        for value in ("Microsoft-IIS/10.0", "nginx/1.18.0",
                      "Apache/2.4.41 (Ubuntu)", "PHP/8.2.1"):
            assert self._flagged(value), value

    def test_a_bare_dotted_version_is_flagged(self):
        """x-aspnet-version sends `4.0.30319` with no product name at all."""
        found = posture.analyze_security_headers(
            {"X-AspNet-Version": "4.0.30319"}, "https://x.test/")
        assert any("Version disclosure" in f.name for f in found)

    def test_an_absent_header_is_not_flagged(self):
        assert not self._flagged("")
