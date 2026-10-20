"""v2.22.0 — a QA pass over v2.21.0, and what it turned up.

v2.21.0 fixed six detectors by comparing them to their issuers. This release
asked the obvious follow-up: where else does that class of defect live? The
answer came from one mechanical question — which patterns bound a run of DIGITS,
since an identifier is the one field that grows on its own — and there were
three. Two had already been corrected. The third had not.

Nothing here is a credential. Every value is assembled at runtime.
"""

from __future__ import annotations

import random
import re

import pytest

import scanner

DIGITS = "0123456789"
URLSAFE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"


def found(value: str) -> list[str]:
    return [h.secret_type for h in scanner.extract_secrets(
        "t", "https://t.test", "https://t.test/app.js", f'const v = "{value}";\n')]


def token(rng: random.Random, id_digits: int, secret_len: int) -> str:
    return ("".join(rng.choice(DIGITS) for _ in range(id_digits)) + ":"
            + "".join(rng.choice(URLSAFE) for _ in range(secret_len)))


# ── Telegram: both halves were wrong ─────────────────────────────────────────

def test_telegrams_own_documented_example_token_is_found():
    """The example on Telegram's Bot API page has 34 characters after the
    colon. The pattern required exactly 35, so the issuer's published token did
    not match us — the same failure as HashiCorp's mixed-case prefix in
    v2.21.0, found by the same question: does the issuer's own example match?
    """
    assert "Telegram Bot Token" in found(
        "110201543:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw")


@pytest.mark.parametrize("id_digits", [8, 9, 10, 11, 13, 16])
def test_telegram_tokens_are_found_across_the_documented_id_range(id_digits):
    """A bot id is a Telegram USER id, and Telegram documents those as "at most
    52 significant bits" while its changelog warns ids will pass 2^31-1. 52 bits
    is 16 decimal digits. The cap was 10 — a width real ids already reach, so
    this was not a future problem.
    """
    assert "Telegram Bot Token" in found(token(random.Random(id_digits), id_digits, 35))


def test_the_telegram_id_ceiling_is_telegrams_number_not_a_guess():
    """16 digits is where 52 significant bits runs out. Asserting the arithmetic
    keeps the bound traceable to the issuer instead of looking arbitrary."""
    assert len(str(2 ** 52)) == 16
    pattern = scanner.PATTERN_BY_NAME["Telegram Bot Token"].regex.pattern
    assert "[0-9]{8,16}" in pattern


@pytest.mark.parametrize("id_digits,secret_len", [(7, 35), (17, 35), (10, 33), (10, 47)])
def test_telegram_boundaries_still_hold(id_digits, secret_len):
    """Widening is only safe while the edges stay closed."""
    assert "Telegram Bot Token" not in found(
        token(random.Random(secret_len), id_digits, secret_len))


# ── The question that found it, kept as a standing check ─────────────────────

def test_every_bounded_digit_run_in_the_registry_is_accounted_for():
    """An identifier is the one field that grows without anyone shipping a
    change, so a bound on a digit-run goes stale by itself. Three detectors
    have one, and each bound traces to a published ceiling:

      Telegram    52 significant bits  -> 16 digits
      Discord     snowflakes, already widened in v2.16.0 to 17-20
      Asana       gids were 64-bit ints; signed int64 maxes at 19 digits

    A new one appearing should be a deliberate decision, not a surprise, so
    this test fails when the set changes rather than asserting each bound.
    """
    digit_run = re.compile(r"(?:\[0-9\]|\\d)\{\d+(?:,\d+)?\}")
    have = {p.name for p in scanner.SECRET_PATTERNS
            if digit_run.search(p.regex.pattern)}
    assert have == {"Telegram Bot Token", "Discord Client ID", "Asana Client ID"}, (
        "a detector gained or lost a bounded digit-run; if it is new, check the "
        "bound against the issuer's published ceiling before accepting it")


def test_asanas_bound_is_the_signed_int64_ceiling():
    """19 is not a guess — it is where a signed 64-bit integer runs out, which
    is what Asana gids were. Recorded so this bound is not mistaken for the
    arbitrary kind and 'fixed' into something wrong."""
    assert len(str(2 ** 63 - 1)) == 19
    assert "[0-9]{15,19}" in scanner.PATTERN_BY_NAME["Asana Client ID"].regex.pattern


# ── The widened patterns did not start claiming things ───────────────────────

@pytest.mark.parametrize("value", [
    "1234567890",                                  # a bare id, no secret
    "1234567890:short",                            # secret under the floor
    "2026-10-20T11:22:33",                         # a timestamp, not a token
    "12345678901234567:" + "a" * 35,               # id over the ceiling
])
def test_the_telegram_widening_did_not_make_it_claim_fragments(value):
    assert "Telegram Bot Token" not in found(value)


def test_a_long_digit_run_with_a_colon_is_not_slow():
    """The id bound went from 10 to 16 and the secret bound became a range, so
    the engine has more ways to backtrack. Bounded quantifiers keep that linear,
    but the point of a regex change is to measure rather than assume."""
    import time
    blob = ("9" * 400 + ":" + "Aa0-_" * 400) * 20
    start = time.perf_counter()
    scanner.extract_secrets("t", "https://t.test", "https://t.test/app.js", blob)
    assert time.perf_counter() - start < 2.0
