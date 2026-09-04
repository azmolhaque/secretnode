"""
v2.16.1 — a QC pass on v2.16.0, and the blind spot it exposed.

The headline finding is not any single pattern. It is that a detector could
score 1.000 on the ground-truth corpus AND 99.1% against gitleaks while matching
zero real credentials, because both corpora derive their specimens from the same
regex the detector uses. Two copies of one claim agreeing with each other is not
corroboration.

Mapbox is the proof: `pk.<60>.<22>`, transcribed faithfully, matched gitleaks'
generated samples and not the token Mapbox publishes in its own documentation.
`bench/vendorshapes.py` exists because of it, and the tests here lock down that
defect, the three others the same audit turned up, and the prefilter mechanism —
whose own soundness check found a bug in itself before it shipped.

No literal credential appears in this file: values are assembled at runtime.
"""

from __future__ import annotations

import base64
import json
import os
import random
import string
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import pytest  # noqa: E402

import scanner  # noqa: E402
from bench import external as ext  # noqa: E402
from bench import groundtruth, vendorshapes  # noqa: E402

_RNG = random.Random(20260905)
ALNUM = string.ascii_letters + string.digits
DIGITS = string.digits
URLSAFE = ALNUM + "_-"
DISCORD_EPOCH_MS = 1_420_070_400_000


def r(alphabet: str, n: int) -> str:
    return "".join(_RNG.choice(alphabet) for _ in range(n))


def types(asset: str) -> list[str]:
    return [h.secret_type for h in scanner.extract_secrets(
        "t", "https://t.test", "https://t.test/app.js", asset)]


def mapbox(prefix: str, account: str) -> str:
    """Built from Mapbox's documented structure, not from the registry."""
    claims = base64.urlsafe_b64encode(
        json.dumps({"u": account, "a": r(string.ascii_lowercase + DIGITS, 25)}).encode()
    ).decode().rstrip("=")
    return f"{prefix}.{claims}.{r(URLSAFE, 22)}"


# ── The defect: a pattern that matched everything but a real credential ──────

class TestMapboxMatchesRealTokens:
    """`pk.<60>.<22>` was transcribed from gitleaks, whose generator emits
    exactly 60 random characters. A Mapbox token is a JWT whose payload encodes
    the ACCOUNT NAME, so its length varies per customer — Mapbox's own published
    token has 62. The pattern scored 1.000 on both corpora and matched nothing.
    """

    @pytest.mark.parametrize("account", [
        "a", "mapbox", "acme-corp", "acme-corporation-maps-team",
    ])
    def test_public_tokens_of_any_account_name_are_found(self, account):
        assert "Mapbox Public Token" in types(f'accessToken: "{mapbox("pk", account)}"')

    @pytest.mark.parametrize("account", ["a", "acme-corporation-maps-team"])
    def test_secret_tokens_are_found_and_are_not_the_public_one(self, account):
        got = types(f'token = "{mapbox("sk", account)}"')
        assert "Mapbox Secret Token" in got
        assert "Mapbox Public Token" not in got

    def test_the_secret_token_is_critical_and_the_public_one_is_not(self):
        assert scanner.PATTERN_BY_NAME["Mapbox Secret Token"].severity == "CRITICAL"
        assert scanner.PATTERN_BY_NAME["Mapbox Public Token"].severity == "LOW"


class TestDiscordSnowflakeWidth:
    """A Discord id is `(ms since 2015-01-01) << 22`, so its width is a function
    of the calendar. gitleaks' fixed 18 held from about 2016 to 2021; every
    application created since 2022 has a 19-digit id and was invisible."""

    @pytest.mark.parametrize("year_ms", [
        1_451_606_400_000,   # 2016 — 18 digits
        1_577_836_800_000,   # 2020 — 18 digits
        1_756_944_000_000,   # today — 19 digits
        1_893_456_000_000,   # 2030 — still 19
    ])
    def test_ids_from_any_era_are_found(self, year_ms):
        snowflake = str(((year_ms - DISCORD_EPOCH_MS) << 22) | _RNG.randrange(1 << 22))
        assert "Discord Client ID" in types(f'discordClientId: "{snowflake}"')


def test_an_airtable_pat_reports_once_not_twice():
    """`pat` + 14 characters is exactly the 17 alphanumerics the legacy Airtable
    key pattern wants, so one credential produced two findings — and
    `_collapse_duplicates` could not merge them, because the matched substrings
    differ. `_contextual` now refuses a value that continues through a dot."""
    pat_token = "pat" + r(ALNUM, 14) + "." + r("0123456789abcdef", 64)
    assert types(f'airtableToken: "{pat_token}"') == ["Airtable Personal Access Token"]


def test_a_1password_token_survives_base64url_encoding():
    body = "".join(_RNG.choice(ALNUM + "-_") for _ in range(260))
    assert "1Password Service Account Token" in types(f'const v = "ops_eyJ{body}"')


# ── The shared gate that was measuring the wrong thing ───────────────────────

class TestDegeneracyNotAbsoluteEntropy:
    """MIN_STRUCTURAL_ENTROPY existed to reject `AKIAAAAAAAAAAAAAAAAA`. At 2.5
    absolute bits it did — and it also dropped 5.4% of genuine 16-digit ids and
    2.4% of 18-digit ones, because a decimal digit carries at most log2(10) =
    3.32 bits however random it is. Invisible until a detector matched a numeric
    value; the Discord and Asana client IDs are the first that do."""

    @pytest.mark.parametrize("junk", [
        "AKIA" + "A" * 16, "Q" * 58, "0" * 32, "ab" * 20,
    ])
    def test_filler_is_still_rejected(self, junk):
        assert scanner.looks_degenerate(junk)

    @pytest.mark.parametrize("alphabet,n", [
        (DIGITS, 16), (DIGITS, 17), (DIGITS, 18), (DIGITS, 19),
        ("0123456789abcdef", 24), ("0123456789abcdef", 40), (ALNUM, 16), (ALNUM, 32),
    ])
    def test_random_values_in_any_base_survive(self, alphabet, n):
        """The old floor dropped whole percentages of these. Over 2,000 draws
        per shape the new test must drop none: degeneracy is a property of the
        value, not of the base it happens to be written in."""
        rng = random.Random(f"{alphabet}{n}")
        dropped = sum(1 for _ in range(2000)
                      if scanner.looks_degenerate(
                          "".join(rng.choice(alphabet) for _ in range(n))))
        assert dropped == 0, f"{dropped}/2000 random {n}-char values called filler"

    def test_the_specific_id_that_was_dropped(self):
        """A real 18-digit id measuring 2.37 bits — below the old 2.5 floor."""
        assert scanner.shannon_entropy("884828884469342884") < 2.5
        assert not scanner.looks_degenerate("884828884469342884")
        assert "Asana Client ID" in types('asanaClientId: "884828884469342884"')

    def test_short_values_are_left_to_their_pattern(self):
        assert not scanner.looks_degenerate("aaa")


# ── The prefilter, and the check that keeps it honest ────────────────────────

class TestPrefilterSoundness:
    """A prefilter decides whether to RUN a regex, never whether a match counts.
    That makes an unsound one a silent false negative — the worst failure this
    scanner has — so the mechanism only earns its place with these attached.

    They are not decoration. This check found a bug in the derivation before it
    shipped: `https?://` yielded the literal `https`, because the extractor took
    the character the `?` had made optional. Every `http://user:pass@host` would
    have been skipped by the one detector that exists to find it.
    """

    def test_every_ground_truth_specimen_satisfies_its_prefilter(self):
        corpus = groundtruth.build()
        for sp in corpus.specimens:
            pat = scanner.PATTERN_BY_NAME[sp.pattern]
            if not pat.prefilter:
                continue
            hay = sp.snippet.lower()
            assert any(k in hay for k in pat.prefilter), (
                f"{sp.pattern}: prefilter {pat.prefilter} would skip its own specimen")

    def test_every_vendor_shape_satisfies_its_prefilter(self):
        for shape in vendorshapes.shapes():
            pat = scanner.PATTERN_BY_NAME.get(shape.expect)
            if pat is None or not pat.prefilter:
                continue
            hay = (shape.context + " " + shape.value).lower()
            assert any(k in hay for k in pat.prefilter), (
                f"{shape.expect}: prefilter {pat.prefilter} would skip a real credential")

    def test_no_prefilter_skips_a_pattern_that_would_have_matched(self):
        """The general statement, over every externally-authored positive."""
        files = ext.load_corpus(offline=True)
        if not files:
            pytest.skip("gitleaks corpus not cached; nothing measured")
        unsound = []
        for provider, rid, value, kind in ext.specimens(files):
            asset = f'const {provider}ApiKey = "{value}";\n'
            hay = asset.lower()
            for pat in scanner.SECRET_PATTERNS:
                if (pat.prefilter
                        and not any(k in hay for k in pat.prefilter)
                        and pat.regex.search(asset)):
                    unsound.append((pat.name, pat.prefilter, rid))
        assert not unsound, f"prefilter skipped a real match: {unsound[:5]}"

    def test_the_quantifier_case_that_broke_it(self):
        assert scanner._literal_prefix("https?://") == "http"
        assert scanner._literal_prefix("dt0c01\\.") == "dt0c01"
        assert scanner._literal_prefix("[A-Z]{4}") == ""
        assert scanner._literal_prefix("colou?r") == "colo"

    def test_alternation_is_never_prefiltered(self):
        """A branch without the literal makes the whole prefilter unsound."""
        import re as _re
        assert scanner._derive_prefilter(_re.compile(r"\b(aaaa_x|bbbb_y)\b")) == ()

    def test_a_keyword_prefilter_needs_every_branch_to_yield_one(self):
        assert scanner._keyword_prefilter("cohere|co_api_key") == ("cohere", "co_api_key")
        assert scanner._keyword_prefilter("linked[_-]?in") == ("linked",)
        assert scanner._keyword_prefilter("cohere|[a-z]{4}") == ()

    def test_the_generic_catch_all_is_never_prefiltered(self):
        assert not scanner.PATTERN_BY_NAME[scanner.GENERIC_SECRET_TYPE].prefilter


def test_prefiltering_does_not_change_what_a_scan_finds():
    """The mechanism is an optimisation. Same asset, same findings, both ways."""
    from dataclasses import replace
    asset = (
        'const a = "ghp_' + r(ALNUM, 36) + '";\n'
        'discordSecret: "' + r(URLSAFE, 32) + '",\n'
        'const u = "https://svc:' + r(ALNUM, 12) + '@internal.acme.test/v1";\n'
        'const m = "' + mapbox("pk", "acme") + '";\n'
    )
    with_prefilter = sorted(types(asset))
    original = scanner.SECRET_PATTERNS
    try:
        scanner.SECRET_PATTERNS = [replace(p, prefilter=()) for p in original]
        without = sorted(types(asset))
    finally:
        scanner.SECRET_PATTERNS = original
    assert with_prefilter == without


# ── Report quality ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("name", [
    "Discord Client ID", "Asana Client ID", "LinkedIn Client ID",
    "age Secret Key", "1Password Secret Key", "KuCoin Secret Key",
    "GCP Service Account JSON", "Mapbox Public Token", "Mapbox Secret Token",
])
def test_detectors_whose_default_advice_would_be_wrong_carry_their_own(name):
    """"Treat as compromised, revoke at the provider immediately" is not merely
    unhelpful for a published OAuth client id or an age key with no provider —
    it is wrong, and wrong advice on a LOW finding teaches a reader to skim the
    CRITICAL ones."""
    assert scanner.PATTERN_BY_NAME[name].remediation != scanner._DEFAULT_REMEDIATION


def test_the_vendor_benchmark_passes():
    """Release-blocking in CI; asserted here too so a local run catches it."""
    missed = [(s.expect, s.source) for s in vendorshapes.shapes()
              if s.expect not in vendorshapes._detected(s)]
    assert not missed, f"patterns that cannot match a real credential: {missed}"
