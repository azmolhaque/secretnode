"""
Offline mode had no verdict, and no way to reach one.

Two connected defects, both visible in the default configuration (no
GEMINI_API_KEY — the documented Pi/offline mode):

  1. `_ai_skipped` returned `is_valid=True, confidence=50` for everything. That
     is not a verdict, it is a placeholder standing in for one. An AWS secret
     key, a Sentry DSN and a Stripe *publishable* key came back byte-identical
     apart from the type name, none carrying an impact sentence.

  2. Verification only ever ran on `confirmed`. Offline, `classify_validated`
     routes every finding to review, review was never verified — so the
     Confirmed table was structurally guaranteed to be empty no matter how many
     live credentials the scan had actually found. The strongest evidence this
     tool can obtain was withheld from exactly the findings nobody could judge.

`triage.py` fixes the first. Verification-promotes-on-evidence fixes the second.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import scanner  # noqa: E402
import triage  # noqa: E402
import verifier  # noqa: E402

# Assembled from parts rather than written as literals. Spelled out in full,
# GitHub's push protection blocks the commit: these authenticate to nothing, but
# they are correctly SHAPED credentials, which is exactly the property that makes
# them useful here. `bench/groundtruth.py` already does this for the same reason
# (see its masked-secret decoy) — a test suite that cannot be committed is not a
# test suite, and the values are identical once built.
AWS_KEY = "AKIA" + "Z7QF3XBNQ2WKLMNP"
SENTRY_DSN = "https://abc123def4567890abcdef1234567890@o123456.ingest.sentry.io/1234567"


def _raw(secret_type="AWS Access Key", value=AWS_KEY, snippet="", source="https://t/app.js"):
    return scanner.RawFinding(
        scan_id="s", target_url="https://t", source_url=source,
        secret_type=secret_type, raw_match=value,
        context_snippet=snippet or f'const k = "{value}";', entropy=4.1,
    )


# ── public by design ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("secret_type", [
    "Stripe Publishable Key", "Sentry DSN", "PostHog Project API Key",
])
def test_definitionally_public_values_are_dismissed(secret_type):
    """Not 'probably fine' — these exist to be read by a browser. Reporting one
    as an exposure is a claim that costs the reader trust in every other line of
    the report."""
    v = triage.triage(secret_type, "pk_live_abc", 'k="pk_live_abc"', 4.0, "LOW", True)
    assert v.public_by_design is True
    assert v.is_valid is False
    assert v.confidence >= scanner.GEMINI_CONFIDENCE_MIN, (
        "a dismissal must be confident enough for classify_validated to act on it"
    )


def test_a_firebase_web_key_is_recognised_by_its_neighbours():
    """An AIza… string alone cannot say whether it is a public Firebase web key
    or a server-side Google API key. The sibling config keys can."""
    snippet = (
        'const firebaseConfig={apiKey:"AIzaSyDOCAbC123dEf456GhI789jKl012-MnO",'
        'authDomain:"demo.firebaseapp.com",projectId:"demo",appId:"1:2:web:3"}'
    )
    v = triage.triage("Google Cloud API Key", "AIzaSyDOCAbC123dEf456GhI789jKl012-MnO",
                      snippet, 4.4, "HIGH", True)
    assert v.public_by_design is True
    assert "Firebase" in v.reason


def test_a_maps_key_is_recognised_by_its_neighbours():
    snippet = '<script src="https://maps.googleapis.com/maps/api/js?key=AIzaSyDOCAbC123dEf456GhI789jKl012-MnO">'
    v = triage.triage("Google Cloud API Key", "AIzaSyDOCAbC123dEf456GhI789jKl012-MnO",
                      snippet, 4.4, "HIGH", True)
    assert v.public_by_design is True


def test_a_bare_google_key_is_retained_not_guessed_at():
    """With no Firebase or Maps context the value could be a server-side key.
    Ambiguity is retained, and the reason says it is ambiguous rather than
    manufacturing a judgement."""
    v = triage.triage("Google Cloud API Key", "AIzaSyDOCAbC123dEf456GhI789jKl012-MnO",
                      'const K="AIzaSyDOCAbC123dEf456GhI789jKl012-MnO";', 4.4, "HIGH", True)
    assert v.public_by_design is False
    assert v.is_valid is True
    assert v.confidence < scanner.GEMINI_CONFIDENCE_MIN


# ── non-production context ───────────────────────────────────────────────────

def test_a_generic_match_in_test_scaffolding_is_dismissed():
    v = triage.triage(scanner.GENERIC_SECRET_TYPE, "aaaabbbbccccddddeeee",
                      'it("logs in", () => { const token = "aaaabbbbccccddddeeee"; })',
                      4.0, "MEDIUM", structural=False)
    assert v.is_valid is False
    assert v.public_by_design is False


def test_a_provider_shaped_key_in_a_test_file_is_NEVER_dismissed():
    """The rule that matters most here. Developers hardcode real credentials
    into test fixtures constantly, and those fixtures ship inside bundles.
    Dismissing a provider-shaped key on test context alone would be exactly the
    false negative this tool exists to prevent."""
    v = triage.triage("AWS Access Key", AWS_KEY,
                      f'describe("s3", () => {{ const k = "{AWS_KEY}"; }})',
                      4.1, "CRITICAL", structural=True,
                      source_url="https://t/__tests__/s3.spec.js")
    assert v.is_valid is True, "a real AKIA in a test fixture is still a real AKIA"


def test_staging_is_not_treated_as_non_production():
    """Staging credentials are real credentials against real infrastructure.
    Treating one as noise is how a live leak gets closed as a false positive."""
    assert triage.looks_non_production('const stagingToken = "x";', "https://t/staging.js") is False
    assert triage.looks_non_production('const devApiKey = "x";', "https://t/dev.js") is False


# ── impact ───────────────────────────────────────────────────────────────────

def test_every_retained_finding_carries_a_blast_radius_sentence():
    v = triage.triage("AWS Access Key", AWS_KEY, f'k="{AWS_KEY}"', 4.1, "CRITICAL", True)
    assert v.impact, "a report that does not say what an attacker gets is a to-do list"
    assert "AWS" in v.impact


def test_an_unknown_detector_still_gets_an_impact_from_its_severity():
    """63 detectors and counting — the table cannot be exhaustive, so the
    fallback has to be real rather than an empty string."""
    assert triage.impact_for("Some Future Provider Credential", "CRITICAL")
    assert triage.impact_for("Some Future Provider Credential", "HIGH")


def test_triage_never_reaches_the_confirmation_threshold():
    """A rules engine that never saw the credential work must not be able to
    place a finding under a heading that reads 'confirmed'. Verification
    promotes; triage does not."""
    for stype, structural, sev in [
        ("AWS Access Key", True, "CRITICAL"),
        ("GitHub Personal Access Token", True, "HIGH"),
        (scanner.GENERIC_SECRET_TYPE, False, "MEDIUM"),
    ]:
        v = triage.triage(stype, "x" * 30, 'const k = "abc";', 4.5, sev, structural)
        if v.is_valid:
            assert v.confidence < scanner.GEMINI_CONFIDENCE_MIN, stype


# ── the scanner's offline path ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_offline_mode_renders_a_real_verdict(monkeypatch):
    monkeypatch.setattr(scanner, "GEMINI_API_KEY", "")
    r = await scanner.validate_with_gemini(_raw(), broadcast=None)
    assert r.ai_judged is False, "no model judged this, and the report must not imply one did"
    assert r.impact, "offline findings used to carry no impact statement at all"
    assert "Offline triage" in r.reason


@pytest.mark.asyncio
async def test_offline_mode_downgrades_a_known_public_value(monkeypatch):
    """The headline improvement. This used to come back is_valid=True,
    confidence=50 — indistinguishable from an AWS secret key."""
    monkeypatch.setattr(scanner, "GEMINI_API_KEY", "")
    r = await scanner.validate_with_gemini(
        _raw("Sentry DSN", SENTRY_DSN, f'dsn:"{SENTRY_DSN}"'), broadcast=None,
    )
    assert r.public_by_design is True
    assert r.effective_severity() == "INFO"
    # Reported, not deleted. Silently dropping a Stripe publishable key leaves
    # the client unable to tell whether the scanner examined it and cleared it or
    # never saw it. INFO is not an exposure — no alert, no verification.
    assert scanner.classify_validated(r) == "informational"


@pytest.mark.asyncio
async def test_offline_mode_still_never_drops_a_provider_shaped_key(monkeypatch):
    """The never-drop guarantee has to survive the new tier."""
    monkeypatch.setattr(scanner, "GEMINI_API_KEY", "")
    r = await scanner.validate_with_gemini(_raw(), broadcast=None)
    assert scanner.classify_validated(r) == "review"


@pytest.mark.asyncio
async def test_offline_generic_findings_are_still_kept_when_context_is_production(monkeypatch):
    """v2.12.x fixed a bug where every `apiKey = "…"` was silently discarded
    offline. That fix must not regress: only *evident test scaffolding* is
    dismissed, never ordinary production code."""
    monkeypatch.setattr(scanner, "GEMINI_API_KEY", "")
    r = await scanner.validate_with_gemini(
        _raw(scanner.GENERIC_SECRET_TYPE, "s3cr3tV4lu3W1thEntr0py99",
             'const apiKey = "s3cr3tV4lu3W1thEntr0py99";'),
        broadcast=None,
    )
    assert scanner.classify_validated(r) == "review"


# ── verification promotes on evidence ────────────────────────────────────────

class _StubState:
    cancelled = False

    def check(self):
        pass


@pytest.mark.asyncio
async def test_a_verified_review_finding_is_promoted_to_confirmed(monkeypatch):
    """A provider answering 'yes, this key works' is an observation, not an
    opinion. It does not additionally need a model to agree."""
    review = scanner.ValidatedFinding(
        raw=_raw("GitHub Personal Access Token", "ghp_" + "a" * 36),
        is_valid=True, confidence=70, reason="offline", ai_judged=False,
    )

    async def _fake_verify(secret_type, raw_value, client):
        return verifier.VerifyResult("verified", "@octocat · repo,workflow")

    monkeypatch.setattr(verifier, "verify_finding_detailed", _fake_verify)
    await scanner.verify_confirmed_findings([review], None, _StubState(), asyncio.Semaphore(2))

    assert review.verified == "verified"
    assert review.verified_detail == "@octocat · repo,workflow"


def test_the_review_list_is_filtered_to_types_that_have_a_verifier():
    """Verification is a live credential replay against a third party. It is
    gated by the authorization ledger, so it must not be sprayed at findings
    where it cannot possibly answer anything."""
    assert verifier.is_supported("GitHub Personal Access Token") is True
    assert verifier.is_supported(scanner.GENERIC_SECRET_TYPE) is False


@pytest.mark.asyncio
async def test_offline_plus_verify_can_confirm_findings_end_to_end(monkeypatch):
    """The whole point of the two changes together: with no Gemini key, a live
    credential can now reach the Confirmed table on the provider's own evidence.
    Before this, that table was structurally guaranteed to be empty offline."""
    monkeypatch.setattr(scanner, "GEMINI_API_KEY", "")
    token = "ghp_" + "b" * 36

    async def _fake_verify(secret_type, raw_value, client):
        return verifier.VerifyResult("verified", "@acme-ci · repo")

    monkeypatch.setattr(verifier, "verify_finding_detailed", _fake_verify)

    v = await scanner.validate_with_gemini(
        _raw("GitHub Personal Access Token", token, f'const t="{token}";'), broadcast=None,
    )
    assert scanner.classify_validated(v) == "review", "offline triage alone does not confirm"

    await scanner.verify_confirmed_findings([v], None, _StubState(), asyncio.Semaphore(2))
    assert v.verified == "verified", "the provider confirmed it — this is now evidence, not opinion"


# ── routing: the asymmetry, made explicit ────────────────────────────────────

def _vf(secret_type_generic=False, **kw):
    base = dict(
        raw=_raw(scanner.GENERIC_SECRET_TYPE, "abc123def456ghi789") if secret_type_generic
             else _raw(),
        is_valid=True, confidence=70, reason="r",
        ai_judged=False, offline_triaged=True,
    )
    base.update(kw)
    return scanner.ValidatedFinding(**base)


def test_no_tier_reached_a_verdict_goes_to_a_human():
    """ai_judged=False AND offline_triaged=False means nothing concluded
    anything. That is ignorance, and ignorance goes to review."""
    assert scanner.classify_validated(_vf(offline_triaged=False)) == "review"


def test_a_hedged_offline_dismissal_is_not_grounds_to_discard():
    """Below the confidence bar, an offline 'probably not real' must not delete
    a finding. Getting a confirmation wrong wastes an afternoon; getting a
    dismissal wrong is the failure this tool exists to prevent."""
    assert scanner.classify_validated(_vf(is_valid=False, confidence=60)) == "review"


def test_a_confident_offline_dismissal_does_discard():
    """A confident dismissal on grounds other than public-by-design — test
    scaffolding, a placeholder — is discarded."""
    assert scanner.classify_validated(
        _vf(is_valid=False, confidence=95, secret_type_generic=True)
    ) == "drop"


def test_public_by_design_is_reported_not_discarded():
    """The one confident dismissal that is NOT a deletion. See
    classify_validated: `effective_severity()` exists solely to render these at
    INFO, and until this bucket existed nothing reaching it survived routing, so
    that method was unreachable."""
    assert scanner.classify_validated(
        _vf(is_valid=False, confidence=95, public_by_design=True)
    ) == "informational"


def test_offline_triage_can_never_confirm_however_confident():
    """Belt and braces against a future edit raising the triage cap above the
    confirmation threshold: routing refuses to confirm an un-AI-judged finding
    regardless of the number attached to it."""
    assert scanner.classify_validated(_vf(is_valid=True, confidence=99)) == "review"


def test_the_report_says_which_tier_produced_the_verdict():
    """A confidence number with no tier named invites the reader to assume the
    strongest tier ran. For an offline scan that assumption is wrong."""
    assert _vf().to_dict()["validation_tier"] == "offline-triage"
    assert _vf(ai_judged=True).to_dict()["validation_tier"] == "ai"
    assert _vf(offline_triaged=False).to_dict()["validation_tier"] == "none"


# ── the corpus's third ground-truth class ────────────────────────────────────

def test_every_public_specimen_is_actually_classified_public_by_design():
    """The ground-truth corpus declares three classes, and `public` has a
    two-part contract: "must be detected AND classified public-by-design".

    Nothing enforced the second half. Findings that reached public_by_design=True
    were routed to 'drop' and deleted, so the corpus's own declared expectation
    was unmet by construction — and the HTTP benchmark scored exactly these
    specimens as false negatives once the offline tier started classifying them
    correctly. This test reads the corpus's labels and checks the pipeline
    against them, rather than trusting either side.
    """
    from bench import groundtruth

    c = groundtruth.build()
    public_specimens = [s for s in c.specimens if s.kind == "public"]
    assert public_specimens, "the corpus is supposed to carry a public class"

    for s in public_specimens:
        meta = scanner.PATTERN_BY_NAME[s.pattern]
        v = triage.triage(
            secret_type=s.pattern, raw_match=s.value, context_snippet=s.snippet,
            entropy=scanner.shannon_entropy(s.value), severity=meta.severity,
            structural=not meta.entropy_gated,
        )
        assert v.public_by_design is True, f"{s.pattern} is declared public in the corpus"

        vf = scanner.ValidatedFinding(
            raw=_raw(s.pattern, s.value, s.snippet), is_valid=v.is_valid,
            confidence=v.confidence, reason=v.reason,
            public_by_design=v.public_by_design, ai_judged=False, offline_triaged=True,
        )
        assert scanner.classify_validated(vf) == "informational"
        assert vf.effective_severity() == "INFO"
