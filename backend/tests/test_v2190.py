"""
v2.19.0 — the report earns its conclusions.

Finding a credential is half the job. The output is read by someone deciding
what to do before lunch, and two things got in their way.

**79 of 111 detectors gave identical advice.** They fell back to one paragraph:
revoke at the provider, purge from history, move server-side. Sound, and it is
what a reader would have told themselves. Three of the remaining ones were
worse than unhelpful — a Stripe publishable key, a Sentry DSN and a PostHog
project key are public by design, and "treat as compromised: revoke the
credential immediately" is simply wrong about them.

**`/api/health` reported a variable's presence as a fact.** A rejected key, or a
model the key cannot call, still read `gemini_configured: true`, and the
operator found out by noticing AI verdicts missing from a finished report —
the same shape as the coverage bug v2.14.4 fixed.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import scanner  # noqa: E402
import triage  # noqa: E402


# ── Remediation ──────────────────────────────────────────────────────────

class TestRemediationIsSpecific:
    def test_no_critical_or_high_detector_ships_generic_advice(self):
        """The gate. Adding a CRITICAL detector without writing its remediation
        now fails here rather than shipping a paragraph the reader could have
        written themselves."""
        generic = [p.name for p in scanner.SECRET_PATTERNS
                   if p.severity in ("CRITICAL", "HIGH")
                   and p.remediation == scanner._DEFAULT_REMEDIATION]
        assert not generic, f"CRITICAL/HIGH detectors still on the default: {generic}"

    def test_the_only_detectors_left_on_the_default_have_no_issuer(self):
        """`Bearer Token` is an HTTP scheme and the catch-all is a shape, so
        there is no console to send anyone to. Everything else got text."""
        remaining = {p.name for p in scanner.SECRET_PATTERNS
                     if p.remediation == scanner._DEFAULT_REMEDIATION}
        assert remaining == {"Generic High-Entropy Secret", "Bearer Token"}

    @pytest.mark.parametrize("name", [
        "Stripe Publishable Key", "Sentry DSN", "PostHog Project API Key",
    ])
    def test_public_by_design_findings_are_not_told_to_revoke(self, name):
        """Wrong advice on a low-severity line teaches a reader to discount the
        CRITICAL ones. These three are classed public-by-design by the triage
        tier and were still carrying 'treat as compromised'."""
        text = scanner.PATTERN_BY_NAME[name].remediation
        assert text != scanner._DEFAULT_REMEDIATION
        assert "No action needed" in text
        assert "Treat as compromised" not in text

    def test_every_public_by_design_type_has_matching_advice(self):
        """The registry and the triage tier must agree: a type triage dismisses
        as public cannot be a type the report tells you to revoke."""
        for type_name in triage._PUBLIC_BY_TYPE:
            pattern = scanner.PATTERN_BY_NAME.get(type_name)
            if pattern is None:
                continue
            assert pattern.remediation != scanner._DEFAULT_REMEDIATION, type_name
            assert "immediately" not in pattern.remediation.lower(), type_name

    def test_the_table_names_only_real_detectors(self):
        registry = {p.name for p in scanner.SECRET_PATTERNS}
        stale = [n for n in scanner._REMEDIATION if n not in registry]
        assert not stale, f"remediation written for detectors that do not exist: {stale}"

    def test_a_pattern_that_defines_its_own_text_wins(self):
        """The table is a backstop for detectors that had nothing, never an
        override of wording already considered beside a detector."""
        own = scanner.PATTERN_BY_NAME["Mapbox Secret Token"].remediation
        assert "Mapbox account settings" in own
        assert own != scanner._REMEDIATION.get("Mapbox Secret Token", own + "x")

    @pytest.mark.parametrize("name,must_mention", [
        ("AWS Access Key", "CloudTrail"),
        ("Stripe Secret Key", "Developers -> API"),
        ("GitHub Personal Access Token", "Developer settings"),
        ("HashiCorp Vault Token", "audit device"),
        ("Supabase Secret Key", "Row Level Security"),
        ("Private Key Block", "new keypair"),
    ])
    def test_the_advice_names_where_to_go_and_what_to_check(self, name, must_mention):
        """Three questions the default could not answer: where the console is,
        what the credential reaches, and what to check for abuse afterwards."""
        assert must_mention in scanner.PATTERN_BY_NAME[name].remediation

    def test_remediation_reaches_a_finding_dict(self):
        """Written and never rendered is the defect v2.14.3 spent a release on."""
        import report
        finding = {
            "secret_type": "AWS Access Key", "severity": "CRITICAL",
            "source_url": "https://t.test/a.js", "raw_match": "AKIA****",
            "cwe": "CWE-798", "confidence": 95, "reason": "structural",
            "found_at": "2026-10-09T00:00:00Z", "fingerprint": "fp",
            "remediation": scanner.PATTERN_BY_NAME["AWS Access Key"].remediation,
        }
        page = report.generate_html_report(
            {"target_url": "https://t.test", "confirmed_findings": [finding],
             "needs_review_findings": [], "informational_findings": [],
             "posture_findings": []})
        assert "CloudTrail" in page


# ── /api/health ──────────────────────────────────────────────────────────

class TestHealthReportsAFact:
    """`bool(os.environ.get("GEMINI_API_KEY"))` is satisfied by a rejected key.

    No API call is made to answer this: a health endpoint polled by a monitor
    must not spend tokens or hit a rate limit, and the scanner already latches a
    permanent config failure the first time it meets one.
    """

    @pytest.fixture(autouse=True)
    def _clean_ai_state(self, monkeypatch):
        monkeypatch.setattr(scanner, "_ai_disabled_reason", None)
        monkeypatch.setattr(scanner, "_ai_calls_succeeded", False)
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    def _ai(self) -> dict:
        return TestClient(main.app).get("/api/health").json()["ai"]

    def test_no_key_is_reported_as_disabled_not_as_a_fault(self):
        """Offline is the documented default configuration, not an error."""
        ai = self._ai()
        assert ai["configured"] is False and ai["status"] == "disabled"
        assert "offline triage" in ai["reason"]

    def test_a_key_that_has_never_been_used_is_untested_not_ok(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "x" * 20)
        ai = self._ai()
        assert ai["configured"] is True and ai["status"] == "untested"

    def test_a_latched_config_failure_is_reported_with_its_reason(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "x" * 20)
        monkeypatch.setattr(scanner, "_ai_disabled_reason", "model not available (404)")
        ai = self._ai()
        assert ai["status"] == "failing"
        assert "404" in ai["reason"]

    def test_a_successful_call_is_what_makes_it_ok(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "x" * 20)
        monkeypatch.setattr(scanner, "_ai_calls_succeeded", True)
        assert self._ai()["status"] == "ok"

    def test_a_failure_outranks_an_earlier_success(self, monkeypatch):
        """A key that worked and then stopped is failing, not ok."""
        monkeypatch.setenv("GEMINI_API_KEY", "x" * 20)
        monkeypatch.setattr(scanner, "_ai_calls_succeeded", True)
        monkeypatch.setattr(scanner, "_ai_disabled_reason", "quota exhausted")
        assert self._ai()["status"] == "failing"

    def test_the_models_it_would_call_are_named(self, monkeypatch):
        """So an operator can see the config without reading the container's env."""
        monkeypatch.setenv("GEMINI_API_KEY", "x" * 20)
        ai = self._ai()
        assert ai["tier1_model"] == scanner.GEMINI_TIER1_MODEL
        assert ai["tier2_model"] == scanner.GEMINI_TIER2_MODEL

    def test_the_old_field_still_answers_for_existing_consumers(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "x" * 20)
        assert TestClient(main.app).get("/api/health").json()["gemini_configured"] is True
