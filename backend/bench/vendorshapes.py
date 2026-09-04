#!/usr/bin/env python3
"""
Vendor-shape benchmark — the blind spot the other three share.

WHY THIS EXISTS
---------------
`bench/groundtruth.py` builds one specimen per detector and scores 108/108. The
external benchmark scores 99.1% against gitleaks. Both were green while the
Mapbox detector matched **zero real Mapbox tokens**, including the one Mapbox
publishes in its own documentation.

Neither could have caught it, and the reason is structural rather than an
oversight in either:

    ground truth   specimens are generated FROM the registry's own regexes, so a
                   pattern that says 60 characters gets a 60-character specimen
                   and matches it. The corpus cannot disagree with the pattern.

    external       gitleaks' samples come from ITS regex — and this project
                   transcribed that same regex. Two copies of one claim agreeing
                   with each other is not corroboration.

So a detector whose length is simply wrong scores 1.000 on one and 100% on the
other, and finds nothing in the field. That is the worst failure this project
can have: a scan that returns CLEAN because the pattern never could have matched.

WHAT THIS DOES DIFFERENTLY
--------------------------
Every value below is constructed from the ISSUER's documented structure, written
out as an algorithm, with the registry's pattern deliberately not consulted:

    a Discord id is `(milliseconds since 2015-01-01) << 22`  — so its width is a
    function of the calendar, and IDs minted today are 19 digits, not the 18 the
    reference rule hard-codes

    a Mapbox token is a JWT whose payload encodes the ACCOUNT NAME — so its
    length varies per customer, and no fixed width is correct

When a construction and a pattern disagree, the pattern is wrong until someone
shows otherwise. That is the whole point: this corpus owes nothing to the
regexes it tests.

NOTHING HERE IS A CREDENTIAL. Every value is assembled at runtime from a seeded
RNG over the documented alphabet. Nothing authenticates to anything, and no
literal that could trip push protection is committed.
"""

from __future__ import annotations

import base64
import json
import os
import random
import string
import sys
from dataclasses import dataclass

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "bench")

import scanner  # noqa: E402

SEED = 20260905
LOWER = string.ascii_lowercase
UPPER = string.ascii_uppercase
DIGITS = string.digits
ALNUM = string.ascii_letters + string.digits
HEX = "0123456789abcdef"
B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
URLSAFE = ALNUM + "_-"
B64 = ALNUM + "+/"
BECH32 = "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L"

# Discord's epoch, from its own developer documentation.
DISCORD_EPOCH_MS = 1_420_070_400_000


@dataclass(frozen=True)
class Shape:
    """One credential built from its issuer's documented format."""

    expect: str          # the detector that must claim it
    value: str           # constructed here, never copied from a pattern
    source: str          # where the format comes from
    context: str = ""    # keyword-anchored detectors need their keyword


def _snowflake(rng: random.Random, year_ms: int) -> str:
    """Discord/Twitter snowflake: (ms since epoch) << 22, plus worker bits."""
    return str(((year_ms - DISCORD_EPOCH_MS) << 22) | rng.randrange(1 << 22))


def _jwt_token(rng: random.Random, prefix: str, account: str) -> str:
    """Mapbox: `<prefix>.<base64url claims>.<base64url signature>`.

    The claims object carries the account name, which is why the middle segment
    has no fixed length — the property the transcribed pattern got wrong.
    """
    claims = base64.urlsafe_b64encode(
        json.dumps({"u": account, "a": "".join(rng.choice(LOWER + DIGITS) for _ in range(25))})
        .encode()).decode().rstrip("=")
    sig = "".join(rng.choice(URLSAFE) for _ in range(22))
    return f"{prefix}.{claims}.{sig}"


def shapes() -> list[Shape]:
    rng = random.Random(SEED)

    def r(alphabet: str, n: int) -> str:
        return "".join(rng.choice(alphabet) for _ in range(n))

    out: list[Shape] = [
        # ── formats derivable from a published algorithm ──────────────────
        Shape("Discord Client ID", _snowflake(rng, 1_451_606_400_000),
              "snowflake: (ms since 2015-01-01) << 22 — a 2016 application",
              context="discordClientId"),
        Shape("Discord Client ID", _snowflake(rng, 1_756_944_000_000),
              "same formula, an application created today — 19 digits",
              context="discordClientId"),
        Shape("Discord Client ID", _snowflake(rng, 1_893_456_000_000),
              "same formula, 2030 — the width keeps growing",
              context="discordClientId"),
        Shape("Mapbox Public Token", _jwt_token(rng, "pk", "a"),
              "Mapbox JWT, one-character account name (shortest payload)"),
        Shape("Mapbox Public Token", _jwt_token(rng, "pk", "mapbox"),
              "Mapbox JWT, the account name from Mapbox's own doc token"),
        Shape("Mapbox Public Token", _jwt_token(rng, "pk", "acme-corporation-maps-team"),
              "Mapbox JWT, a long account name (longest payload)"),
        Shape("Mapbox Secret Token", _jwt_token(rng, "sk", "acme-maps"),
              "Mapbox secret token — same structure, sk. prefix"),

        # ── formats documented as a fixed layout ─────────────────────────
        Shape("AWS Access Key", "AKIA" + r(B32, 16),
              "AWS: AKIA + 16 base32 characters"),
        Shape("GitHub Personal Access Token", "ghp_" + r(ALNUM, 36),
              "GitHub: ghp_ + 36 alphanumerics"),
        Shape("Stripe Secret Key", "sk_live_" + r(ALNUM, 24),
              "Stripe: sk_live_ + 24 alphanumerics"),
        Shape("Stripe Publishable Key", "pk_live_" + r(ALNUM, 24),
              "Stripe: pk_live_ + 24 alphanumerics"),
        Shape("Google Cloud API Key", "AIza" + r(URLSAFE, 35),
              "Google: AIza + 35 URL-safe characters"),
        Shape("Airtable Personal Access Token", "pat" + r(ALNUM, 14) + "." + r(HEX, 64),
              "Airtable: pat + 14 + '.' + 64 hex"),
        Shape("age Secret Key", "AGE-SECRET-KEY-1" + r(BECH32, 58),
              "age: bech32 of a 32-byte key — 52 data + 6 checksum characters"),
        Shape("1Password Secret Key",
              "A3-" + r(UPPER + DIGITS, 6) + "-" + r(UPPER + DIGITS, 11) + "-"
              + r(UPPER + DIGITS, 5) + "-" + r(UPPER + DIGITS, 5) + "-" + r(UPPER + DIGITS, 5),
              "1Password whitepaper grouping: A3-<6>-<11>-<5>-<5>-<5>"),
        Shape("Sourcegraph Access Token", "sgp_" + r(HEX, 40),
              "Sourcegraph: sgp_ + 40 hex"),
        Shape("Sourcegraph Access Token", "sgp_" + r(HEX, 16) + "_" + r(HEX, 40),
              "Sourcegraph instance-scoped: sgp_<16 hex>_<40 hex>"),
        Shape("Slack Token", "xoxb-" + r(DIGITS, 13) + "-" + r(DIGITS, 13) + "-" + r(ALNUM, 24),
              "Slack: xoxb- + numeric team/bot ids + 24-character secret"),
        Shape("GCP Service Account JSON", '"type": "service_account"',
              "Google's generated service-account JSON opens with this field"),
        Shape("Private Key Block",
              "-----BEGIN RSA PRIVATE KEY-----\n" + r(B64, 64) + "\n"
              + r(B64, 64) + "\n-----END RSA PRIVATE KEY-----",
              "RFC 7468 PEM: armour header, base64 body, armour footer"),
        Shape("GitLab Session Cookie", "_gitlab_session=" + r(HEX, 32),
              "GitLab session cookie: name=value, 32-character value"),
    ]
    return out


def _detected(shape: Shape) -> list[str]:
    """Run one shape through the real extraction path."""
    if shape.context:
        asset = f'{shape.context}: "{shape.value}",\n'
    else:
        asset = f'const v = "{shape.value}";\n'
    return [h.secret_type for h in scanner.extract_secrets(
        "vendor", "https://vendor.test", "https://vendor.test/app.js", asset)]


def main() -> int:
    print("Vendor-shape benchmark — credentials built from issuer documentation")
    print("=" * 68)
    all_shapes = shapes()
    missed: list[tuple[Shape, list[str]]] = []
    mistyped: list[tuple[Shape, list[str]]] = []

    for shape in all_shapes:
        got = _detected(shape)
        if not got:
            missed.append((shape, got))
        elif shape.expect not in got:
            mistyped.append((shape, got))

    ok = len(all_shapes) - len(missed) - len(mistyped)
    print(f"  shapes           {len(all_shapes)}")
    print(f"  detected         {ok}/{len(all_shapes)}   "
          f"({100 * ok / max(1, len(all_shapes)):.1f}%)")
    print(f"  not matched      {len(missed):>4}   <- the pattern cannot see a real credential")
    print(f"  wrong detector   {len(mistyped):>4}   matched, but attributed elsewhere")

    for label, rows in (("NOT MATCHED", missed), ("WRONG DETECTOR", mistyped)):
        if not rows:
            continue
        print()
        print(f"  {label}:")
        for shape, got in rows:
            print(f"    {shape.expect}")
            print(f"      built from: {shape.source}")
            print(f"      reported:   {got or 'nothing'}")

    print()
    print("  These values owe nothing to the registry's regexes: each is built")
    print("  from the issuer's documented structure. A pattern that disagrees")
    print("  with a construction here is wrong until someone shows otherwise —")
    print("  which is the check the other benchmarks structurally cannot make.")
    return 1 if (missed or mistyped) else 0


if __name__ == "__main__":
    raise SystemExit(main())
