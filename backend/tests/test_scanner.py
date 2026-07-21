"""
SecretNode v2.0 — smoke tests
Run with: pytest tests/ -v

Covers the pure/deterministic logic that's cheapest and most valuable to
pin down with tests: entropy scoring, secret redaction, scan-scope checks,
and the SSRF guard. Network-dependent code (spider_target, Gemini calls)
is intentionally out of scope for these fast unit tests — cover those with
integration tests against a local mock server if/when the suite grows.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import pytest

import scanner


class TestShannonEntropy:
    def test_low_entropy_rejected(self):
        # Repeated character = zero entropy, must fail the threshold
        assert scanner.shannon_entropy("aaaaaaaaaaaaaaaa") < scanner.MIN_ENTROPY_THRESHOLD

    def test_high_entropy_accepted(self):
        # A real-looking random API key should clear the bar
        assert scanner.shannon_entropy("aK7xQ2mN9pL4vR8sT1wY6zB3") >= scanner.MIN_ENTROPY_THRESHOLD

    def test_empty_string(self):
        assert scanner.shannon_entropy("") == 0.0


class TestRedaction:
    def test_short_secret_fully_masked(self):
        assert scanner.redact_secret("abc123") == "*" * 6

    def test_long_secret_partially_masked(self):
        secret = "EXAMPLESECRETKEY1234"
        redacted = scanner.redact_secret(secret)
        keep = min(6, len(secret) // 4)
        assert redacted != secret
        assert redacted.startswith(secret[:keep])
        assert "*" in redacted

    def test_snippet_redaction_removes_all_occurrences(self):
        secret = "test-secret-value-not-a-real-key-0123"
        snippet = f'const stripeKey = "{secret}"; // used in {secret}'
        redacted = scanner.redact_snippet(snippet, secret)
        assert secret not in redacted

    def test_snippet_redaction_handles_empty_secret(self):
        snippet = "no secret here"
        assert scanner.redact_snippet(snippet, "") == snippet


class TestScopeRestriction:
    def test_exact_domain_match(self):
        assert scanner._same_scope("example.com", "example.com")

    def test_subdomain_is_in_scope(self):
        assert scanner._same_scope("example.com", "cdn.example.com")

    def test_unrelated_domain_out_of_scope(self):
        assert not scanner._same_scope("example.com", "evil.com")

    def test_lookalike_domain_out_of_scope(self):
        # "notexample.com" must NOT match "example.com" via naive suffix check
        assert not scanner._same_scope("example.com", "notexample.com")


class TestExtractJsUrls:
    def test_same_domain_kept(self):
        html = '<script src="https://example.com/app.js"></script>'
        urls = scanner.extract_js_urls(html, "https://example.com/")
        assert "https://example.com/app.js" in urls

    def test_cross_domain_excluded_by_default(self):
        html = '<script src="https://evil-cdn.example.net/x.js"></script>'
        urls = scanner.extract_js_urls(html, "https://example.com/")
        assert urls == []

    def test_relative_url_resolved(self):
        html = '<script src="/static/bundle.js"></script>'
        urls = scanner.extract_js_urls(html, "https://example.com/page")
        assert "https://example.com/static/bundle.js" in urls

    def test_data_uri_ignored(self):
        html = '<script src="data:text/javascript;base64,abc"></script>'
        urls = scanner.extract_js_urls(html, "https://example.com/")
        assert urls == []


class TestFingerprint:
    def test_fingerprint_stable(self):
        f1 = scanner.RawFinding(
            scan_id="a", target_url="https://example.com", source_url="https://example.com/app.js",
            secret_type="AWS Access Key", raw_match="AKIAIOSFODNN7EXAMPLE",
            context_snippet="x", entropy=4.0,
        )
        f2 = scanner.RawFinding(
            scan_id="b", target_url="https://example.com", source_url="https://example.com/app.js",
            secret_type="AWS Access Key", raw_match="AKIAIOSFODNN7EXAMPLE",
            context_snippet="different context", entropy=4.0,
        )
        # Same secret_type + source_url + raw_match => same fingerprint,
        # even across different scan_ids/timestamps/context.
        assert f1.fingerprint == f2.fingerprint

    def test_fingerprint_changes_with_value(self):
        f1 = scanner.RawFinding(
            scan_id="a", target_url="https://example.com", source_url="https://example.com/app.js",
            secret_type="AWS Access Key", raw_match="AKIAIOSFODNN7EXAMPLE",
            context_snippet="x", entropy=4.0,
        )
        f2 = scanner.RawFinding(
            scan_id="a", target_url="https://example.com", source_url="https://example.com/app.js",
            secret_type="AWS Access Key", raw_match="EXAMPLESECRETKEY0000",
            context_snippet="x", entropy=4.0,
        )
        assert f1.fingerprint != f2.fingerprint


class TestExtractPageLinks:
    def test_same_domain_link_kept(self):
        html = '<a href="/about">About</a>'
        links = scanner.extract_page_links(html, "https://example.com/")
        assert "https://example.com/about" in links

    def test_cross_domain_link_excluded(self):
        html = '<a href="https://evil.com/x">x</a>'
        links = scanner.extract_page_links(html, "https://example.com/")
        assert links == []

    def test_asset_links_excluded(self):
        html = '<a href="/report.pdf">PDF</a><a href="/logo.png">logo</a>'
        links = scanner.extract_page_links(html, "https://example.com/")
        assert links == []

    def test_mailto_and_fragment_excluded(self):
        html = '<a href="mailto:a@b.com">mail</a><a href="#top">top</a>'
        links = scanner.extract_page_links(html, "https://example.com/")
        assert links == []


class TestExtractSecrets:
    def test_finds_aws_key(self):
        import secrets as _s, string as _st
        # Runtime-generated (no literal secret in source) synthetic AWS key.
        # Regenerate until it clears the entropy gate so the test is deterministic —
        # a low-entropy random draw would otherwise be filtered out ~4% of runs and
        # flake the suite.
        alphabet = _st.ascii_uppercase + "0123456789"
        while True:
            synthetic = "AKIA" + "".join(_s.choice(alphabet) for _ in range(16))
            if scanner.shannon_entropy(synthetic) >= scanner.MIN_ENTROPY_THRESHOLD:
                break
        body = f'const cfg = {{ key: "{synthetic}" }};'
        findings = scanner.extract_secrets(
            "scan1", "https://example.com", "https://example.com/app.js", body
        )
        assert "AWS Access Key" in [f.secret_type for f in findings]

    def test_documentation_example_key_allowlisted(self):
        # AWS's official example key must be treated as a benign placeholder (v2.3.0).
        body = 'const cfg = { key: "AKIAIOSFODNN7EXAMPLE" };'
        findings = scanner.extract_secrets(
            "scan1", "https://example.com", "https://example.com/app.js", body
        )
        assert "AWS Access Key" not in [f.secret_type for f in findings]

    def test_no_false_positive_on_placeholder(self):
        body = 'const key = "YOUR_API_KEY_HERE";'
        findings = scanner.extract_secrets(
            "scan1", "https://example.com", "https://example.com/app.js", body
        )
        # Low-entropy placeholder text should not pass the entropy filter
        assert findings == [] or all(f.secret_type != "AWS Access Key" for f in findings)


class TestEntropyGatingPolicy:
    """Entropy gating is a false-positive control for the *generic* keyword=value
    catch-all only. Structural/provider detectors are high-precision by shape and
    must NOT be entropy-gated — otherwise a genuinely low-entropy but well-formed
    live key (e.g. an AWS key ID whose 16 chars happen to be low-entropy) is
    silently dropped: a false negative, the worst failure mode for a scanner."""

    def test_low_entropy_structural_key_is_detected(self):
        # A correctly-shaped AWS key ID whose entropy is *below* the threshold.
        low = "AKIA6218374A3D288737"
        assert scanner.shannon_entropy(low) < scanner.MIN_ENTROPY_THRESHOLD
        body = f'const cfg = {{ key: "{low}" }};'
        findings = scanner.extract_secrets(
            "scan1", "https://example.com", "https://example.com/app.js", body
        )
        assert "AWS Access Key" in [f.secret_type for f in findings]

    def test_degenerate_structural_key_is_rejected(self):
        # All-identical chars => degenerate junk, not a real key. The low
        # structural floor still rejects it even though it matches the AWS shape.
        junk = "AKIA" + "A" * 16
        assert scanner.shannon_entropy(junk) < scanner.MIN_STRUCTURAL_ENTROPY
        body = f'k = "{junk}"'
        findings = scanner.extract_secrets(
            "scan1", "https://example.com", "https://example.com/app.js", body
        )
        assert "AWS Access Key" not in [f.secret_type for f in findings]

    def test_aws_pattern_is_not_entropy_gated(self):
        assert scanner.PATTERN_BY_NAME["AWS Access Key"].entropy_gated is False

    def test_generic_pattern_stays_entropy_gated(self):
        assert scanner.PATTERN_BY_NAME["Generic High-Entropy Secret"].entropy_gated is True

    def test_generic_low_entropy_value_is_still_dropped(self):
        # Loose keyword=value with a low-entropy (non-placeholder) value must
        # still be filtered — the generic catch-all keeps its entropy gate.
        low_val = "a" * 24
        assert scanner.shannon_entropy(low_val) < scanner.MIN_ENTROPY_THRESHOLD
        body = f'api_key = "{low_val}"'
        findings = scanner.extract_secrets(
            "scan1", "https://example.com", "https://example.com/app.js", body
        )
        assert "Generic High-Entropy Secret" not in [f.secret_type for f in findings]


class TestClassifyValidated:
    """A structural match the AI does not *confidently* dismiss must go to manual
    review, never be silently dropped (false-negative guard). The generic catch-all
    keeps aggressive filtering so 'no false positives in Confirmed' still holds."""

    def _vf(self, secret_type, is_valid, confidence):
        raw = scanner.RawFinding(
            scan_id="s", target_url="https://e.com", source_url="https://e.com/a.js",
            secret_type=secret_type, raw_match="AKIA6218374A3D288737",
            context_snippet="x", entropy=3.27,
        )
        return scanner.ValidatedFinding(raw=raw, is_valid=is_valid, confidence=confidence, reason="r")

    def test_sentinel_goes_to_review(self):
        vf = self._vf("AWS Access Key", False, scanner.NEEDS_REVIEW_SENTINEL)
        assert scanner.classify_validated(vf) == "review"

    def test_valid_high_confidence_confirmed(self):
        assert scanner.classify_validated(self._vf("AWS Access Key", True, 95)) == "confirmed"

    def test_structural_ai_uncertain_rejection_goes_to_review(self):
        # AI says not-valid but only 55% sure => a shape-anchored key must not vanish.
        assert scanner.classify_validated(self._vf("AWS Access Key", False, 55)) == "review"

    def test_structural_valid_but_low_confidence_goes_to_review(self):
        assert scanner.classify_validated(self._vf("AWS Access Key", True, 60)) == "review"

    def test_structural_ai_confident_rejection_dropped(self):
        assert scanner.classify_validated(self._vf("AWS Access Key", False, 95)) == "drop"

    def test_generic_ai_rejection_dropped_even_if_uncertain(self):
        # The generic catch-all trusts an AI 'no' and drops it, regardless of confidence.
        assert scanner.classify_validated(self._vf("Generic High-Entropy Secret", False, 55)) == "drop"


class TestSeedUrlInjection:
    """run_scan(seed_urls=...) must fetch externally-supplied assets (e.g. archived
    JS bundles) and add them to the scan set, deduped against the live crawl."""

    class _FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_a):
            return False

    def _patch(self, monkeypatch):
        async def fake_spider(client, url, sem, broadcast, max_pages=1):
            return [("https://ex.com/base.js", "const base = 1;")]

        async def fake_fetch(client, url, sem, broadcast=None):
            return (url, "// clean seed body, no secrets")

        async def fake_posture(client, url):
            return []

        monkeypatch.setattr(scanner, "spider_target", fake_spider)
        monkeypatch.setattr(scanner, "fetch_url", fake_fetch)
        monkeypatch.setattr(scanner, "build_client", lambda *a, **k: self._FakeClient())
        monkeypatch.setattr(scanner.posture, "fetch_posture", fake_posture)

    @pytest.mark.asyncio
    async def test_seed_url_is_fetched_and_added(self, monkeypatch):
        self._patch(monkeypatch)
        res = await scanner.run_scan("https://ex.com", seed_urls=["https://ex.com/old.js"])
        assert res["assets_fetched"] == 2      # base crawl asset + 1 seed

    @pytest.mark.asyncio
    async def test_seed_url_deduped_against_crawl(self, monkeypatch):
        self._patch(monkeypatch)
        # Seed already collected by the crawl → not fetched twice.
        res = await scanner.run_scan("https://ex.com", seed_urls=["https://ex.com/base.js"])
        assert res["assets_fetched"] == 1

    @pytest.mark.asyncio
    async def test_no_seeds_is_unchanged(self, monkeypatch):
        self._patch(monkeypatch)
        res = await scanner.run_scan("https://ex.com")
        assert res["assets_fetched"] == 1


class TestSurfaceExtraction:
    """run_scan mines fetched assets for referenced endpoints + external hosts,
    and fetches same-site .js endpoints one level deeper (slices 5 & 4)."""

    class _FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_a):
            return False

    def _patch(self, monkeypatch):
        # Base asset references a same-site JS endpoint and an external host.
        async def fake_spider(client, url, sem, broadcast, max_pages=1):
            body = ('fetch("/api/v1/session");'
                    'src="/static/deep.js";'
                    'x="https://cdn.thirdparty.net/lib.js";')
            return [("https://ex.com/app.js", body)]

        async def fake_fetch(client, url, sem, broadcast=None):
            return (url, "// deep bundle, no secrets")

        async def fake_posture(client, url):
            return []

        monkeypatch.setattr(scanner, "spider_target", fake_spider)
        monkeypatch.setattr(scanner, "fetch_url", fake_fetch)
        monkeypatch.setattr(scanner, "build_client", lambda *a, **k: self._FakeClient())
        monkeypatch.setattr(scanner.posture, "fetch_posture", fake_posture)

    @pytest.mark.asyncio
    async def test_endpoints_and_hosts_and_deeper_crawl(self, monkeypatch):
        self._patch(monkeypatch)
        res = await scanner.run_scan("https://ex.com")
        # Same-site endpoints discovered (session API + the deep.js path).
        assert "https://ex.com/api/v1/session" in res["discovered_endpoints"]
        assert "https://ex.com/static/deep.js" in res["discovered_endpoints"]
        # External host captured in the associated-asset graph.
        assert "cdn.thirdparty.net" in res["associated_hosts"]
        assert "ex.com" not in res["associated_hosts"]      # own host excluded
        # deep.js was fetched one level deeper → 2 assets (base + deep.js).
        assert res["assets_fetched"] == 2


class TestNeedsReviewSentinel:
    def test_sentinel_is_negative(self):
        # Must never collide with a real 0-100 confidence value
        assert scanner.NEEDS_REVIEW_SENTINEL < 0

    def test_severity_lookup_covers_all_patterns(self):
        for pattern in scanner.SECRET_PATTERNS:
            assert pattern.name in scanner.SECRET_TYPE_SEVERITY
            assert scanner.SECRET_TYPE_SEVERITY[pattern.name] in ("CRITICAL", "HIGH", "MEDIUM")


@pytest.mark.asyncio
async def test_validate_with_gemini_never_returns_none(monkeypatch):
    """Regression test for the silent-drop bug: even if Gemini is completely
    unreachable, validate_with_gemini must return a ValidatedFinding (with
    NEEDS_REVIEW_SENTINEL confidence), never None."""
    monkeypatch.setattr(scanner, "GEMINI_API_KEY", "")
    finding = scanner.RawFinding(
        scan_id="s1", target_url="https://example.com",
        source_url="https://example.com/app.js",
        secret_type="AWS Access Key", raw_match="AKIAIOSFODNN7EXAMPLE",
        context_snippet="key = AKIAIOSFODNN7EXAMPLE", entropy=4.2,
    )
    result = await scanner.validate_with_gemini(finding, broadcast=None)
    assert result is not None
    assert isinstance(result, scanner.ValidatedFinding)
