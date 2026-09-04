"""
v2.16.0 — closing the backlog, and the two defects the backlog itself carried.

v2.15.0 rebuilt the external benchmark after it turned out to be manufacturing
the misses it reported, and left what looked like a clean finite list: eleven
in-scope misses and twelve unclaimed providers. Six of the eleven were the
benchmark again, one level deeper — a Go-source extractor that deleted the very
prefix that makes a credential recognisable, and a substring test that filed a
provider with no detector at all under "the only bucket that is a defect".

The tests here lock down both, the two precision defects found the same way, and
every one of the twenty-two detectors added once the measurement was trustworthy.

No literal credential appears in this file. Values are assembled at runtime, the
same discipline `bench/groundtruth.py` follows, because a credential-shaped
literal in a committed test trips GitHub's push protection and has done so on
this repository before.
"""

from __future__ import annotations

import base64
import json
import os
import random
import re
import string
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import pytest  # noqa: E402

import scanner  # noqa: E402
import triage  # noqa: E402
from bench import external as ext  # noqa: E402

_RNG = random.Random(20260904)
ALNUM = string.ascii_letters + string.digits
HEX = "0123456789abcdef"
UPPER_NUM = string.ascii_uppercase + string.digits
URLSAFE = ALNUM + "_-"
B64 = ALNUM + "+/"
BECH32 = "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L"


def r(alphabet: str, n: int) -> str:
    return "".join(_RNG.choice(alphabet) for _ in range(n))


def types(asset: str) -> list[str]:
    return [h.secret_type for h in scanner.extract_secrets(
        "t", "https://t.test", "https://t.test/app.js", asset)]


# ── The empty PEM block ──────────────────────────────────────────────────────

class TestEmptyKeyBlocks:
    """A header with nothing behind it is not a key.

    `-----BEGIN OPENSSH PRIVATE KEY----------END…-----` was reported CRITICAL,
    because the pattern asked only for the marker. Empty blocks ship for real:
    templates that never rendered, fixtures, configs stripped for publication.
    """

    @pytest.mark.parametrize("kind", ["RSA ", "EC ", "OPENSSH ", ""])
    def test_empty_pem_block_is_not_a_key(self, kind):
        asset = f"-----BEGIN {kind}PRIVATE KEY----------END {kind}PRIVATE KEY-----"
        assert types(asset) == []

    def test_empty_pgp_block_is_not_a_key(self):
        asset = ("-----BEGIN PGP PRIVATE KEY BLOCK-----"
                 "-----END PGP PRIVATE KEY BLOCK-----")
        assert types(asset) == []

    def test_a_real_key_still_matches(self):
        body = r(B64, 96)
        asset = f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----"
        assert "Private Key Block" in types(asset)

    def test_a_key_inlined_into_a_js_string_still_matches(self):
        """The newline is a literal backslash-n once a key is inlined."""
        body = r(B64, 96)
        asset = f'const k = "-----BEGIN RSA PRIVATE KEY-----\\n{body}\\n-----END RSA PRIVATE KEY-----";'
        assert "Private Key Block" in types(asset)

    def test_an_encrypted_key_still_matches(self):
        """The case a naive lookahead breaks.

        An encrypted PEM puts `Proc-Type:` and `DEK-Info:` between the header
        and its base64. Requiring base64 IMMEDIATELY after the header would have
        fixed the empty block by breaking every encrypted key — which is why the
        lookahead scans a 300-character window instead.
        """
        body = r(B64, 96)
        asset = ("-----BEGIN RSA PRIVATE KEY-----\n"
                 "Proc-Type: 4,ENCRYPTED\n"
                 "DEK-Info: AES-128-CBC,9F2C4A1E77B03D5A\n\n"
                 f"{body}\n-----END RSA PRIVATE KEY-----")
        assert "Private Key Block" in types(asset)

    def test_a_public_key_block_is_still_not_a_private_key(self):
        body = r(B64, 96)
        asset = f"-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----"
        assert "Private Key Block" not in types(asset)


# ── The Firebase documentation allowlist ─────────────────────────────────────

class TestFirebaseDocumentationKeys:
    """gitleaks hard-codes sixteen firebase-android-sdk sample keys. This
    scanner carried three; the other thirteen were 13 of the 14 false alarms the
    entire external corpus produced."""

    def test_all_sixteen_documented_keys_are_allowlisted(self):
        aiza = [v for v in scanner._KNOWN_EXAMPLE_SECRETS if v.startswith("AIza")]
        assert len(aiza) == 16

    def test_a_documented_key_is_not_reported(self):
        for value in scanner._KNOWN_EXAMPLE_SECRETS:
            if not value.startswith("AIza"):
                continue
            assert types(f'const apiKey = "{value}";') == [], value

    def test_a_key_of_the_same_shape_that_is_not_documented_is_reported(self):
        """The allowlist must be an allowlist, not a disabled detector."""
        value = "AIza" + r(URLSAFE, 35)
        assert types(f'const apiKey = "{value}";') != []


# ── The 22 new detectors ─────────────────────────────────────────────────────

def _mapbox_token(prefix: str) -> str:
    """`<prefix>.<base64url claims>.<signature>` — Mapbox's documented shape."""
    claims = base64.urlsafe_b64encode(
        json.dumps({"u": "acme-maps", "a": r(string.ascii_lowercase + string.digits, 25)})
        .encode()).decode().rstrip("=")
    return f"{prefix}.{claims}.{r(URLSAFE, 22)}"


def _structural_cases() -> list[tuple[str, str]]:
    return [
        ("Artifactory Reference Token", "cmVmd" + r(ALNUM, 59)),
        ("age Secret Key", "AGE-SECRET-KEY-1" + r(BECH32, 58)),
        ("1Password Service Account Token", "ops_eyJ" + r(B64, 260)),
        ("1Password Secret Key",
         "A3-" + r(UPPER_NUM, 6) + "-" + r(UPPER_NUM, 11) + "-" + r(UPPER_NUM, 5)
         + "-" + r(UPPER_NUM, 5) + "-" + r(UPPER_NUM, 5)),
        ("Airtable Personal Access Token", "pat" + r(ALNUM, 14) + "." + r(HEX, 64)),
        ("Sourcegraph Access Token", "sgp_" + r(HEX, 16) + "_" + r(HEX, 40)),
        # Built from Mapbox's documented JWT structure, not from the pattern.
        # This specimen used to be `pk.` + 60 random characters, which is what
        # the v2.16.0 regex said — and no real token looks like. See
        # test_v2161.TestMapboxMatchesRealTokens and bench/vendorshapes.py.
        ("Mapbox Public Token", _mapbox_token("pk")),
        ("Mapbox Secret Token", _mapbox_token("sk")),
    ]


@pytest.mark.parametrize("expected,value", _structural_cases())
def test_structural_detectors_fire_on_their_own_shape(expected, value):
    """No neighbouring keyword: the prefix is the whole discriminator."""
    assert expected in types(f'const v = "{value}";')


def _contextual_cases() -> list[tuple[str, str, str]]:
    return [
        ("Discord Client Secret", "discordSecret", r(URLSAFE, 32)),
        ("Discord Client ID", "discordClientId", r(string.digits, 18)),
        ("Asana Client Secret", "asanaSecret", r(ALNUM, 32)),
        ("Asana Client ID", "asanaClientId", r(string.digits, 16)),
        ("LinkedIn Client Secret", "linkedInSecret", r(ALNUM, 16)),
        ("LinkedIn Client ID", "linkedInClientId", r(ALNUM, 14)),
        ("Cohere API Token", "cohereApiKey", r(ALNUM, 40)),
        ("Confluent Secret Key", "confluentSecret", r(ALNUM, 64)),
        ("Confluent Access Token", "confluentAccessToken", r(ALNUM, 16)),
        ("KuCoin Access Token", "kucoinAccessToken", r(HEX, 24)),
        ("Airtable API Key", "airtableApiKey", r(ALNUM, 17)),
        ("Sourcegraph Access Token (legacy)", "sourcegraphToken", r(HEX, 40)),
    ]


@pytest.mark.parametrize("expected,keyword,value", _contextual_cases())
def test_contextual_detectors_fire_with_their_provider_keyword(expected, keyword, value):
    assert expected in types(f'{keyword}: "{value}",')


@pytest.mark.parametrize("expected,keyword,value", _contextual_cases())
def test_contextual_detectors_also_read_the_unquoted_env_form(expected, keyword, value):
    """`KEY=value` with no quotes anywhere.

    An exposed `.env` is one of the things this scanner looks for, and gitleaks'
    own Cohere sample is `export CO_API_KEY=…`. A quote-only separator matched
    the bundle case and silently missed the file case.
    """
    assert expected in types(f"{keyword}={value}\n")


class TestContextualDetectorsRefuseIdentifiers:
    """The defect this release's own diff reported when scanned with this scanner.

    A contextual detector's value has no shape, so nothing about length or
    alphabet separates a credential from the variable that holds it — and in
    real code `linkedin_secret: linkedInSecret` is far more common than a
    literal. A credential that spells its own provider's name does not exist,
    so the name is the discriminator.
    """

    @pytest.mark.parametrize("line", [
        "linkedin_secret: linkedInClientId,",
        'linkedin_secret = "linkedInClientSecret"',
        "discord_secret: discordClientSecretValue,",
        "confluent_key = confluentAccessTokenName",
    ])
    def test_a_variable_named_after_the_provider_is_not_a_credential(self, line):
        assert types(line) == []

    def test_a_real_value_beside_the_same_keyword_still_matches(self):
        assert "LinkedIn Client Secret" in types(f'linkedin_secret: "{r(ALNUM, 16)}",')

    def test_the_guard_does_not_need_the_entropy_floor(self):
        """MIN_ENTROPY_THRESHOLD was the obvious fix and the wrong one.

        3.5 bits silently assumes a ~62-character alphabet. An 18-digit Discord
        client ID tops out at log2(10) = 3.32 and can never pass it, however
        random it is; gating these dropped four external specimens, every one
        digit- or hex-only. This is the case that proves the gate would misfire.
        """
        digits_only = r(string.digits, 32)
        assert scanner.shannon_entropy(digits_only) < 3.5
        assert "Discord Client Secret" in types(f'discordSecret: "{digits_only}",')

    def test_contextual_detectors_are_not_entropy_gated(self):
        gated = [p.name for p in scanner.SECRET_PATTERNS
                 if p.entropy_gated and p.name != scanner.GENERIC_SECRET_TYPE]
        assert gated == [], f"restricted-alphabet detectors cannot pass a 3.5-bit floor: {gated}"


def test_kucoin_secret_key_is_a_uuid_shape():
    value = (r(HEX, 8) + "-" + r(HEX, 4) + "-" + r(HEX, 4) + "-"
             + r(HEX, 4) + "-" + r(HEX, 12))
    assert "KuCoin Secret Key" in types(f'kucoinSecret: "{value}",')


class TestSourcegraphSplit:
    """gitleaks' rule offers a bare 40-hex alternative held in check by a keyword
    precondition this registry has no mechanism for. Transcribed as written it
    would match every Git SHA-1 in a source map, so the precondition was written
    into the pattern instead of dropped."""

    def test_a_bare_git_sha_is_not_a_token(self):
        sha = r(HEX, 40)
        assert types(f'const commit = "{sha}";') == []

    def test_the_same_hex_beside_the_provider_name_is(self):
        sha = r(HEX, 40)
        assert "Sourcegraph Access Token (legacy)" in types(f'sourcegraphToken: "{sha}",')

    def test_the_prefixed_form_needs_no_keyword(self):
        value = "sgp_" + r(HEX, 40)
        assert "Sourcegraph Access Token" in types(f'const v = "{value}";')


class TestGcpServiceAccountMarker:
    """One document, one finding.

    `_collapse_duplicates` cannot deduplicate these: the two detectors match
    different substrings, so they are not duplicates by its definition (same URL,
    same matched value) even though they describe one exposure. The lookahead is
    what keeps a trimmed document covered without double-reporting a whole one.
    """

    def test_a_trimmed_document_is_still_found(self):
        asset = '{"type": "service_account", "project_id": "acme-prod-1421"}'
        assert "GCP Service Account JSON" in types(asset)

    def test_a_complete_document_reports_once_via_the_key_id_detector(self):
        asset = ('{"type": "service_account", "project_id": "acme-prod",'
                 f' "private_key_id": "{r(HEX, 40)}"}}')
        found = types(asset)
        assert "GCP Service Account Key (JSON)" in found
        assert "GCP Service Account JSON" not in found


# ── OAuth client IDs are identifiers, not exposures ──────────────────────────

@pytest.mark.parametrize("secret_type", [
    "Discord Client ID", "Asana Client ID", "LinkedIn Client ID", "Mapbox Public Token",
])
def test_public_identifiers_are_dismissed_as_public_by_design(secret_type):
    """An OAuth client ID travels in every authorization URL the app builds. It
    cannot function anywhere else, so reporting it as an exposure costs the
    reader trust in every other line of the report."""
    verdict = triage.triage(
        secret_type=secret_type,
        raw_match=r(ALNUM, 18),
        context_snippet="",
        entropy=4.0,
        severity="LOW",
        structural=True,
        source_url="https://t.test/app.js",
    )
    assert verdict.public_by_design
    assert not verdict.is_valid


def test_the_secret_half_of_the_pair_is_not_dismissed():
    verdict = triage.triage(
        secret_type="Discord Client Secret",
        raw_match=r(URLSAFE, 32),
        context_snippet="",
        entropy=4.6,
        severity="HIGH",
        structural=True,
        source_url="https://t.test/app.js",
    )
    assert not verdict.public_by_design


# ── The benchmark's own defects ──────────────────────────────────────────────

class TestSampleExpressionExtraction:
    """The extractor deleted the prefix that makes a credential recognisable.

    gitleaks writes some samples as a Go concatenation. `_SAMPLE_CALL` matched
    the plural `GenerateSampleSecrets` and not the singular, so such a line fell
    through to a path that returned only the first character-class helper it
    found — the generated middle, with the literal prefix and suffix discarded.
    """

    def test_a_concatenated_sample_keeps_its_prefix_and_suffix(self):
        block = (
            'tps := []string{\n'
            '\tutils.GenerateSampleSecret("anthropic", "sk-ant-api03-"'
            '+secrets.NewSecret(utils.AlphaNumericExtendedShort("93"))+"AA"),\n'
            '}\n'
        )
        got = ext._entries(block, random.Random(1))
        assert len(got) == 1
        assert got[0].startswith("sk-ant-api03-")
        assert got[0].endswith("AA")
        assert len(got[0]) == len("sk-ant-api03-") + 93 + 2

    def test_the_plural_form_outside_a_list_still_works(self):
        block = 'tps := utils.GenerateSampleSecrets("asana", secrets.NewSecret(utils.Numeric("16")))\n'
        got = ext._entries(block, random.Random(1))
        assert len(got) == 1 and got[0].isdigit() and len(got[0]) == 16

    def test_a_sample_call_inside_a_list_is_expanded_exactly_once(self):
        """Both loops can see it; expanding it twice would inflate the corpus
        with near-copies differing only by where the shared RNG had reached."""
        block = (
            'tps := []string{\n'
            '\tutils.GenerateSampleSecret("acme", "AKIA"+secrets.NewSecret(utils.AlphaNumeric("16"))),\n'
            '}\n'
        )
        assert len(ext._entries(block, random.Random(1))) == 1


class TestHasDetectorWordBoundary:
    """`age` is a substring of "Azure StorAGE Account Key", so a plain `in` test
    filed a provider with no detector at all under the one bucket documented as
    a defect."""

    def test_a_substring_of_another_detector_name_does_not_count_as_coverage(self):
        names = [p.name for p in scanner.SECRET_PATTERNS]
        assert any("Storage" in n for n in names), "premise: a Storage detector exists"
        # `age` now has its own detector, so the boundary is checked on a
        # provider that genuinely has none but is a substring of several.
        assert not ext._has_detector("ken")     # inside "Token"
        assert not ext._has_detector("count")   # inside "Account"

    def test_a_real_provider_is_still_recognised(self):
        assert ext._has_detector("gitlab")
        assert ext._has_detector("1password")
        assert ext._has_detector("age")
        assert ext._has_detector("gcp")         # aliased to google


class TestDeclinedBucket:
    """A refusal the scanner really performs, asked directly — never a list of
    rules the benchmark has decided to excuse.

    These call `ext.declined_reason`, the function the benchmark itself runs.
    An earlier version of this file reimplemented it here, which would have
    passed happily while the real code drifted — the exact failure the external
    benchmark exists to catch, reproduced inside its own test.
    """

    def test_a_documented_example_is_declined_with_a_reason(self):
        assert ext.declined_reason("AKIAIOSFODNN7EXAMPLE") == (
            "documented example or placeholder")

    def test_filler_is_declined_as_degenerate(self):
        assert ext.declined_reason("Q" * 58) == "rejected as degenerate filler"

    def test_an_ordinary_credential_is_not_declined(self):
        assert ext.declined_reason("ghp_" + r(ALNUM, 36)) == ""

    def test_an_ordinary_numeric_id_is_not_declined(self):
        """The case the absolute entropy floor got wrong."""
        assert ext.declined_reason("884828884469342884") == ""


# ── Registry-wide invariants ─────────────────────────────────────────────────

def test_every_detector_name_is_unique():
    names = [p.name for p in scanner.SECRET_PATTERNS]
    assert len(names) == len(set(names))


def test_every_pattern_compiles_and_captures_a_group():
    for p in scanner.SECRET_PATTERNS:
        assert isinstance(p.regex, re.Pattern), p.name
        assert p.regex.groups >= 1, f"{p.name} captures nothing"


def test_the_tier_two_default_is_the_model_this_release_moved_to():
    assert scanner.GEMINI_TIER2_MODEL == "gemini-3.8-flash"
    assert scanner.GEMINI_TIER1_MODEL == "gemini-3.5-flash-lite"
