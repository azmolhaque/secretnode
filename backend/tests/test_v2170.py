"""
v2.17.0 — the vendor corpus grown from 16 detectors to most of the registry.

v2.16.1 established that a detector can score 1.000 on the ground-truth corpus
and 99.1% against gitleaks while matching zero real credentials, because both
corpora derive their specimens from the same regex the detector uses. The answer
was `bench/vendorshapes.py`, built from issuer documentation. It covered 16 of
108 detectors, which left 92 sitting in exactly the blind spot that produced the
Mapbox defect.

Growing it to 96 found three disagreements. Each had to be resolved by deciding
which side was wrong — the pattern or the shape — before anything was changed,
and the three went different ways:

    Hugging Face   the pattern was too narrow
    Cloudflare     the pattern demanded a prefix the common form does not have
    Azure          the SHAPE was wrong; the detector was right all along

Plus one detector that was missing entirely: Twilio's API Key SID reached
nothing, because the only Twilio pattern here was the contextual auth token.

No literal credential appears in this file; values are assembled at runtime.
"""

from __future__ import annotations

import os
import random
import string
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import pytest  # noqa: E402

import scanner  # noqa: E402
from bench import vendorshapes  # noqa: E402

_RNG = random.Random(20261009)
ALNUM = string.ascii_letters + string.digits
HEX = "0123456789abcdef"


def r(alphabet: str, n: int) -> str:
    return "".join(_RNG.choice(alphabet) for _ in range(n))


def types(asset: str) -> list[str]:
    return [h.secret_type for h in scanner.extract_secrets(
        "t", "https://t.test", "https://t.test/app.js", asset)]


class TestHuggingFaceAlphabet:
    """Two sibling detectors disagreed about one vendor's alphabet.

    `api_org_` demanded letters only while `hf_` accepted alphanumerics. That is
    a defect whichever one is right, and it was the expensive direction: a random
    34-character alphanumeric token contains no digit at all only 0.25% of the
    time, so a letters-only class misses 99.75% of real tokens if digits occur.
    """

    def test_an_org_token_containing_digits_is_found(self):
        assert "Hugging Face Organization Token" in types(
            f'const t = "api_org_{r(ALNUM, 34)}";')

    def test_a_letters_only_org_token_is_still_found(self):
        """Widened, not swapped — the old alphabet is a subset of the new one."""
        assert "Hugging Face Organization Token" in types(
            f'const t = "api_org_{r(string.ascii_letters, 34)}";')

    def test_the_two_sibling_detectors_now_agree(self):
        org = scanner.PATTERN_BY_NAME["Hugging Face Organization Token"].regex.pattern
        user = scanner.PATTERN_BY_NAME["Hugging Face Access Token"].regex.pattern
        assert "A-Za-z0-9" in org and "A-Za-z0-9" in user

    def test_the_odds_that_justified_the_change(self):
        """0.25%, stated as a computation rather than an assertion of fact."""
        assert (52 / 62) ** 34 < 0.003


class TestCloudflareCommonForm:
    """The only Cloudflare detector demanded a `cfat_`/`cfut_`/`cfk_` prefix. A
    Cloudflare API token is 40 characters with no prefix at all, so the vendor
    corpus reported one reaching nothing but the generic catch-all."""

    def test_an_unprefixed_token_is_claimed_by_cloudflare_not_the_catch_all(self):
        got = types(f'cloudflareApiToken: "{r(ALNUM + "_", 40)}",')
        assert "Cloudflare API Token (unprefixed)" in got
        assert got != [scanner.GENERIC_SECRET_TYPE]

    def test_the_global_api_key_is_covered_and_rated_worse(self):
        assert "Cloudflare Global API Key" in types(
            f'cloudflareGlobalKey: "{r(HEX, 37)}",')
        assert scanner.PATTERN_BY_NAME["Cloudflare Global API Key"].severity == "CRITICAL"

    def test_40_characters_alone_is_not_a_cloudflare_token(self):
        """The keyword carries the whole discriminator here."""
        assert "Cloudflare API Token (unprefixed)" not in types(
            f'const nonce = "{r(ALNUM + "_", 40)}";')

    def test_the_prefixed_form_still_matches(self):
        assert "Cloudflare API Token" in types(f'const t = "cfat_{r(ALNUM, 40)}";')


class TestTwilioApiKeySid:
    """Twilio had one detector — the contextual auth token — so an API Key SID
    reached nothing at all."""

    def test_an_api_key_sid_is_found(self):
        assert "Twilio API Key SID" in types(f'const sid = "SK{r(HEX, 32)}";')

    def test_it_needs_no_neighbouring_keyword(self):
        assert "Twilio API Key SID" in types(f'["SK{r(HEX, 32)}"]')

    def test_rated_high_not_critical_because_the_sid_does_not_authenticate(self):
        pat = scanner.PATTERN_BY_NAME["Twilio API Key SID"]
        assert pat.severity == "HIGH"
        assert "Key Secret" in pat.remediation

    def test_the_auth_token_detector_still_works(self):
        assert "Twilio Auth Token" in types(f'twilioAuthToken: "{r(HEX, 32)}",')


class TestAzureShapeWasTheWrongSide:
    """Not every disagreement is a pattern defect. The Azure detector requires
    the literal `AccountKey=` because that is the only form the portal hands the
    key out in; the bare 88-character shape was the mistake."""

    def test_a_connection_string_is_matched(self):
        asset = ("DefaultEndpointsProtocol=https;AccountName=acme;AccountKey="
                 + r(ALNUM + "+/", 86) + "==;EndpointSuffix=core.windows.net")
        assert "Azure Storage Account Key" in types(asset)

    def test_a_bare_base64_blob_is_not_a_storage_key(self):
        assert "Azure Storage Account Key" not in types(
            f'const blob = "{r(ALNUM + "+/", 86)}==";')


class TestCoverageIsReported:
    """An uncovered detector is one whose pattern has never been checked against
    anything but itself. Leaving that silent is the condition the Mapbox defect
    survived in, so the gate now fails on a detector with neither a shape nor a
    recorded reason."""

    def test_every_detector_has_a_shape_or_a_recorded_reason(self):
        covered = {s.expect for s in vendorshapes.shapes()}
        unexplained = [p.name for p in scanner.SECRET_PATTERNS
                       if p.name not in covered
                       and p.name not in vendorshapes.UNDOCUMENTED]
        assert not unexplained, (
            f"no shape and no recorded reason: {unexplained}")

    def test_the_recorded_reasons_name_real_detectors(self):
        """A reason for a detector that no longer exists is stale bookkeeping."""
        registry = {p.name for p in scanner.SECRET_PATTERNS}
        stale = [n for n in vendorshapes.UNDOCUMENTED if n not in registry]
        assert not stale, f"reasons recorded for detectors that do not exist: {stale}"

    def test_every_shape_names_a_real_detector(self):
        registry = {p.name for p in scanner.SECRET_PATTERNS}
        unknown = sorted({s.expect for s in vendorshapes.shapes()} - registry)
        assert not unknown, f"shapes for detectors that do not exist: {unknown}"

    def test_the_corpus_covers_most_of_the_registry(self):
        """A floor, so coverage cannot quietly regress as detectors are added."""
        covered = {s.expect for s in vendorshapes.shapes()}
        ratio = len(covered) / len(scanner.SECRET_PATTERNS)
        assert ratio >= 0.80, f"vendor coverage fell to {ratio:.0%}"


def test_every_vendor_shape_is_detected():
    """Release-blocking in CI; asserted here so a local run catches it too."""
    failures = [(s.expect, s.source) for s in vendorshapes.shapes()
                if s.expect not in vendorshapes._detected(s)]
    assert not failures, f"patterns that cannot match a real credential: {failures}"


@pytest.mark.parametrize("name", [
    "Twilio API Key SID", "Cloudflare API Token (unprefixed)",
    "Cloudflare Global API Key",
])
def test_new_detectors_carry_their_own_remediation(name):
    assert scanner.PATTERN_BY_NAME[name].remediation != scanner._DEFAULT_REMEDIATION
