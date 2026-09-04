#!/usr/bin/env python3
"""
jwtclaims.py — read what a JWT says about itself.

WHY THIS EXISTS
---------------
The registry detects a JWT by shape. Nothing opened one. That left three
questions unanswered on every JWT this scanner has ever reported, all three
answerable with no network call, no key and no cost:

    is it still valid    an `exp` in the past means the token is already dead,
                         and reporting a dead token at HIGH is a false positive
    how bad is it        a token with no expiry and an admin scope is a
                         different finding from a fifteen-minute user token
    whose is it          `iss` and `aud` name the provider that a bare
                         `eyJ…` string never reveals

The evidence that this matters came from a live scan. Against vulnweb.com the
AI tier dismissed two JWTs by *reading their payloads* — "an example payload
('user':'test') used as sample documentation". The offline tier cannot do that
at all: with no API key it has no way to separate a demonstration token from a
live session, so it retained both at full severity. Offline is the documented
default configuration, which makes that the common case rather than the corner.

WHAT IT IS NOT
--------------
This does not verify a signature and makes no claim to. Verification needs the
issuer's key, which would mean a network call to a third party using a
credential found on a target — precisely what this scanner does not do. A
decoded claim set is what the token *asserts*, not proof of anything, and every
verdict built on it is worded that way.

PRIVACY: WHAT IS DELIBERATELY NOT EXTRACTED
-------------------------------------------
A JWT payload is frequently full of personal data — `sub`, `email`, `name`,
`picture`, arbitrary profile claims. This module reads the payload and returns
only the operational claims: expiry, issued-at, issuer, audience, algorithm and
scope. Identity claims are never copied out, never reach a verdict string and
never reach a report.

That is a deliberate narrowing, not an oversight. A scanner that quietly lifted
a user's email address out of a token and printed it into a client-facing
document would have created a data-protection problem out of a security
finding. The finding does not need the subject's identity to be actionable, so
the subject's identity is not collected.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import time
from dataclasses import dataclass, field

# `eyJ` is base64url for `{"`, so a JWT's first segment always starts with it.
# Requiring it here keeps this module from trying to decode arbitrary
# dot-separated strings that the caller happened to hand over.
_JWT_SHAPE = re.compile(r"^(eyJ[A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.?([A-Za-z0-9_-]*)$")

# Claims that describe the token's own life and reach. Everything else in the
# payload — every identity and profile claim — is read past and dropped.
_OPERATIONAL = ("exp", "iat", "nbf", "iss", "aud", "scope", "scp", "permissions", "roles")

# Values that mark a token as sample material rather than a live credential.
# Matched against the operational claims only, so a real user named "test" in a
# `sub` claim cannot trigger a dismissal — that claim is never read.
_DEMO_MARKERS = ("example.com", "example.org", "localhost", "test.com",
                 "jwt.io", "your-issuer", "acme.com", "demo")


@dataclass(frozen=True)
class JwtFacts:
    """What a token asserts about itself. Never what it proves."""

    decoded: bool = False
    algorithm: str = ""
    issuer: str = ""
    audience: str = ""
    scopes: tuple[str, ...] = field(default_factory=tuple)
    expires_at: int | None = None      # epoch seconds, or None when absent
    issued_at: int | None = None
    # Set only when `exp` exists AND has passed. An absent `exp` is emphatically
    # not "expired" — it is the opposite, and the more dangerous of the two.
    expired: bool = False
    never_expires: bool = False
    unsigned: bool = False             # alg: none — the token authenticates nothing
    looks_like_sample: bool = False

    def summary(self) -> str:
        """One line for a report, built only from operational claims."""
        bits: list[str] = []
        if self.issuer:
            bits.append(f"issuer {self.issuer}")
        if self.audience:
            bits.append(f"audience {self.audience}")
        if self.expired:
            bits.append("EXPIRED")
        elif self.never_expires:
            bits.append("no expiry claim")
        elif self.expires_at:
            days = (self.expires_at - int(time.time())) / 86400
            bits.append(f"expires in {days:.0f}d" if days >= 1 else "expires within a day")
        if self.scopes:
            bits.append("scope " + ",".join(self.scopes[:4]))
        if self.unsigned:
            bits.append("alg=none (unsigned)")
        return "; ".join(bits)


def _b64url(segment: str) -> dict | None:
    """Decode one base64url segment into a JSON object, or None."""
    try:
        # JWT segments drop base64 padding; restore it before decoding.
        padded = segment + "=" * (-len(segment) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError, UnicodeEncodeError):
        return None
    try:
        obj = json.loads(raw.decode("utf-8", errors="strict"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    return obj if isinstance(obj, dict) else None


def _as_scopes(payload: dict) -> tuple[str, ...]:
    """Scope-ish claims, normalised. Providers spell this at least four ways."""
    out: list[str] = []
    for key in ("scope", "scp", "permissions", "roles"):
        v = payload.get(key)
        if isinstance(v, str):
            out.extend(v.replace(",", " ").split())
        elif isinstance(v, (list, tuple)):
            out.extend(str(x) for x in v if isinstance(x, (str, int)))
    seen: set[str] = set()
    uniq = [s for s in out if s and not (s in seen or seen.add(s))]
    return tuple(uniq[:12])


def read(token: str, *, now: int | None = None) -> JwtFacts:
    """Decode a JWT's header and payload. Never raises.

    Returns `JwtFacts(decoded=False)` for anything that is not a decodable JWT,
    which is the same answer the caller gets today and keeps every existing
    verdict path intact.
    """
    m = _JWT_SHAPE.match((token or "").strip())
    if not m:
        return JwtFacts()

    header = _b64url(m.group(1)) or {}
    payload = _b64url(m.group(2))
    if payload is None:
        return JwtFacts()

    ts = int(time.time()) if now is None else now
    alg = str(header.get("alg", "") or "")

    def _epoch(key: str) -> int | None:
        v = payload.get(key)
        # Some issuers emit float or numeric-string timestamps.
        if isinstance(v, bool):
            return None
        if isinstance(v, (int, float)):
            return int(v)
        if isinstance(v, str) and v.strip().isdigit():
            return int(v.strip())
        return None

    exp, iat = _epoch("exp"), _epoch("iat")
    aud_raw = payload.get("aud")
    audience = (", ".join(str(a) for a in aud_raw[:3])
                if isinstance(aud_raw, (list, tuple)) else str(aud_raw or ""))
    issuer = str(payload.get("iss", "") or "")

    # Sample detection reads ONLY the operational claims, never identity ones.
    haystack = f"{issuer} {audience}".lower()
    sample = any(marker in haystack for marker in _DEMO_MARKERS)

    return JwtFacts(
        decoded=True,
        algorithm=alg,
        issuer=issuer[:120],
        audience=audience[:120],
        scopes=_as_scopes(payload),
        expires_at=exp,
        issued_at=iat,
        expired=bool(exp is not None and exp < ts),
        # An `iat` with no `exp` is the signature of a token minted to last —
        # a service or API token rather than a session.
        never_expires=exp is None,
        unsigned=alg.lower() == "none",
        looks_like_sample=sample,
    )
