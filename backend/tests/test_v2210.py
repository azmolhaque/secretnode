"""v2.21.0 — the six detectors that disagreed with their own issuer.

Each test below builds a credential from the ISSUER's documented structure and
asserts the pattern can see it. That direction matters: the ground-truth corpus
generates specimens from these same regexes, so it agrees with them by
construction and cannot catch a pattern whose shape is simply wrong. Every case
here failed before this release.

Nothing in this file is a credential. Every value is assembled at runtime over
the documented alphabet, and no literal that could trip push protection is
committed.
"""

from __future__ import annotations

import base64
import random

import pytest

import scanner

ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
URLSAFE = ALNUM + "_-"
DISCORD_EPOCH_MS = 1_420_070_400_000


def found(value: str, context: str = "") -> list[str]:
    """Run a value through the real extraction path, not a bare regex."""
    asset = f'{context}: "{value}",\n' if context else f'const v = "{value}";\n'
    return [h.secret_type for h in scanner.extract_secrets(
        "t", "https://t.test", "https://t.test/app.js", asset)]


def rnd(seed: int):
    rng = random.Random(seed)
    return lambda alphabet, n: "".join(rng.choice(alphabet) for _ in range(n))


# ── PyPI: the anchor was one deployment's hostname ───────────────────────────

def _macaroon(location: str, seed: int = 1) -> str:
    """PyPI documents a token as `pypi-` + base64 of a PyMacaroon v2.

    v2 binary is a version byte, then {tag 0x01, length, location}, so the
    location lands in the first bytes. Cross-checked against the pymacaroons
    library's own serializer when this was written.
    """
    r = rnd(seed)
    ident = ("gh-oidc:" + r("0123456789abcdef", 24)).encode()
    raw = (b"\x02"
           + b"\x01" + bytes([len(location)]) + location.encode()
           + b"\x02" + bytes([len(ident)]) + ident
           + b"\x00"
           + b"\x06" + bytes([32]) + bytes(random.Random(seed).randrange(256)
                                           for _ in range(32)))
    return "pypi-" + base64.urlsafe_b64encode(raw).decode().rstrip("=")


@pytest.mark.parametrize("location", ["pypi.org", "test.pypi.org", "upload.pypi.org"])
def test_pypi_tokens_are_found_whatever_deployment_issued_them(location):
    """The pattern used to anchor on `AgEIcHlwaS` — the base64 of
    {v2, length 8, "pypi.org"}. TestPyPI encodes "test.pypi.org" instead and
    begins `AgENdGVzdC5weXBpLm9yZ`, so every one of those was invisible."""
    assert "PyPI Upload Token" in found(_macaroon(location))


def test_the_pypi_anchor_is_the_macaroon_header_not_a_hostname():
    """0x02 0x01 — "version 2, location field" — always base64s to "AgE".
    Anchoring past those three characters anchors on a hostname."""
    assert _macaroon("pypi.org")[5:8] == "AgE"
    assert _macaroon("test.pypi.org")[5:8] == "AgE"


# ── Discord bot token: the first segment is a snowflake ──────────────────────

def _bot_token(year_ms: int, seed: int = 2) -> str:
    r = rnd(seed)
    uid = str(((year_ms - DISCORD_EPOCH_MS) << 22) | random.Random(seed).randrange(1 << 22))
    seg1 = base64.urlsafe_b64encode(uid.encode()).decode().rstrip("=")
    return f"{seg1}.{r(URLSAFE, 6)}.{r(URLSAFE, 27)}"


@pytest.mark.parametrize("label,year_ms", [
    ("2016", 1_451_606_400_000),
    ("2023", 1_672_531_200_000),
    ("today", 1_756_944_000_000),
    ("2030", 1_893_456_000_000),
])
def test_discord_bot_tokens_are_found_across_every_id_width(label, year_ms):
    """A bot token's first segment is base64 of the bot's snowflake, so its
    width follows the calendar. The pattern hard-coded 24 characters, which is
    an 18-digit id — and ids crossed 19 digits in 2022, making effectively every
    live bot invisible. The Client ID detector had already been corrected for
    this exact arithmetic; the token that embeds that id had not."""
    assert "Discord Bot Token" in found(_bot_token(year_ms))


def test_a_nineteen_digit_id_base64s_to_twenty_six_characters_not_twenty_five():
    """19 bytes is six full base64 triples plus one byte, so the segment goes
    24 -> 26 and never 25. Worth asserting: a range written as {23,27} is only
    correct because the unreachable width in the middle costs nothing."""
    widths = {len(base64.urlsafe_b64encode(("1" * n).encode()).decode().rstrip("="))
              for n in (17, 18, 19, 20)}
    assert widths == {23, 24, 26, 27}


# ── Terraform Cloud: HashiCorp's own example has uppercase ───────────────────

def test_terraform_cloud_tokens_with_a_mixed_case_prefix_are_found():
    """HashiCorp's user-tokens API reference shows `6tL24nM38M7XWQ.atlasv1.…`.
    A lowercase-only prefix class rejects the issuer's published example."""
    r = rnd(3)
    token = r(ALNUM, 13) + "Q.atlasv1." + r(URLSAFE, 67)
    assert "Terraform Cloud Token" in found(token)


# ── Doppler: the documented optional label, and a missing prefix ─────────────

@pytest.mark.parametrize("token_fn,why", [
    (lambda r: "dp.st." + r(ALNUM, 43), "service token, no label"),
    (lambda r: "dp.st.prd." + r(ALNUM, 43), "service token with the documented label"),
    (lambda r: "dp.st." + r("abcdefghijklmnopqrstuvwxyz0123456789-_", 35) + "." + r(ALNUM, 40),
     "longest documented label, shortest documented body"),
    (lambda r: "dp.pt." + r(ALNUM, 44), "personal token at the documented maximum"),
    (lambda r: "dp.ct." + r(ALNUM, 40), "CLI token at the documented minimum"),
    (lambda r: "dp.said." + r(ALNUM, 42), "service-account identity token"),
    (lambda r: "dp.scim." + r(ALNUM, 41), "SCIM token"),
])
def test_every_documented_doppler_token_form_is_found(token_fn, why):
    """Doppler publishes a format per token type. Two were unreachable: a
    service token's optional label segment (`dp.st.prd.…`, the form Doppler's
    own docs use, and the shape a leaked CI token actually has), and the
    `dp.said.` prefix, which the alternation did not contain at all."""
    assert "Doppler Token" in found(token_fn(rnd(4))), why


def test_said_precedes_sa_in_the_alternation():
    """Regex alternation is leftmost-first: with `sa` listed first, `dp.said.`
    matches `sa`, then demands a `.` it cannot find before the `id`, and the
    whole match fails. Ordering is load-bearing, so it gets its own test."""
    pattern = next(p for p in scanner.SECRET_PATTERNS if p.name == "Doppler Token")
    body = pattern.regex.pattern
    assert body.index("said") < body.index("|sa|")


# ── Google OAuth: an exact width nobody published ────────────────────────────

@pytest.mark.parametrize("width", [20, 28, 35, 45])
def test_google_oauth_secrets_are_found_at_more_than_one_width(width):
    """Google states the `GOCSPX-` prefix and says nothing about length. The
    old `{28}` came from scanner samples; an unpublished fixed width is exactly
    how the Mapbox pattern came to match zero real tokens. The prefix carries
    the precision here, so the width only carried risk."""
    assert "Google OAuth Client Secret" in found("GOCSPX-" + rnd(5)(URLSAFE, width))


# ── Pinecone: the prefix the issuer actually documents ───────────────────────

def test_pinecone_keys_in_the_documented_format_are_found():
    """Pinecone's Admin API reference states "New keys will have the format
    pckey_<public-label>_<unique-key>". Only `pcsk_` was matched — a prefix that
    appears in secret-scanning rules rather than in Pinecone's own docs, so the
    documented form was the one the pattern could not see."""
    r = rnd(6)
    assert "Pinecone API Key" in found(
        "pckey_" + r("abcdefghijklmnopqrstuvwxyz0123456789", 8) + "_" + r(ALNUM, 40))


def test_the_older_pinecone_prefix_still_matches():
    """Kept deliberately. It is plausibly still live, and dropping it to chase
    the documented one would trade a silent miss for a different silent miss."""
    assert "Pinecone API Key" in found("pcsk_" + rnd(7)(ALNUM + "_", 50))


# ── The widening did not cost precision ──────────────────────────────────────

@pytest.mark.parametrize("value", [
    "pypi-AgE",                                   # prefix with no body
    "dp.st.prd.short",                            # label present, body too short
    "dp.sa",                                      # prefix fragment alone
    "GOCSPX-tooshort",                            # under the floor
    "pckey_",                                     # prefix alone
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",       # a JWT header, not a bot token
])
def test_widening_the_patterns_did_not_make_them_match_fragments(value):
    """Each fix above relaxed a constraint. A relaxed pattern that starts
    claiming fragments has traded a false negative for a false positive, which
    is the worse trade in a report a client reads."""
    # Only the six widened detectors are asserted on. A fragment caught by
    # some other pattern (the keyword catch-all, say) is that pattern's
    # business; `== []` would quietly turn this into a test of all 111.
    widened = {"PyPI Upload Token", "Doppler Token", "Terraform Cloud Token",
               "Google OAuth Client Secret", "Pinecone API Key",
               "Discord Bot Token"}
    assert widened.isdisjoint(found(value))
