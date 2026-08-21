#!/usr/bin/env python3
"""
composite.py — credentials that no single regex can find (R7).

THE FALSE NEGATIVE THIS EXISTS TO CLOSE
---------------------------------------
Several detectors in the registry are *keyword-anchored*: they only match when a
provider's name sits beside the value.

    AWS Secret Access Key   (?i)aws.{0,20}secret.{0,20}['"]([A-Za-z0-9/+=]{40})['"]
    Twilio Auth Token       (?i)twilio.{0,30}['"]([0-9a-f]{32})['"]

That keyword is doing all the work, and a bundler deletes it. Minification
rewrites object keys and drops the surrounding names, so the pair that ships is:

    {a:"AKIAIOSFODNN7EXAMPLE",b:"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}

The access-key ID is found — `AKIA…` is self-describing. The secret is not: no
"aws", no "secret", nothing within twenty characters for the detector to anchor
on. So the scan reports the half that is a public identifier and misses the half
that is the actual credential. That is the worst outcome this tool has, and no
amount of tuning a single-value regex fixes it, because the information needed
is not inside the value.

It is, however, right next to it. An `AKIA…` string is essentially never a false
positive, and a 40-character base64 blob forty characters away from one is an
AWS secret key with near-certainty. That is what a composite rule encodes:
**the anchor supplies the identity the companion's own shape cannot.**

WHY ANCHORS ARE NOT DETECTORS
-----------------------------
A Twilio Account SID (`AC` + 32 hex) is a public identifier — it appears in URLs
and is not a secret. Adding it to the main registry to enable the pairing would
mean reporting it as an exposure on its own, which is the "known-public
information in a client report" failure the AI tier exists to prevent. Anchors
therefore live here and are never reported by themselves. They exist only to
give a companion value a provider identity.

PRECISION DISCIPLINE
--------------------
A rule that fires on proximity alone would be a false-positive engine — plenty
of 40-character base64 lives in a bundle. Four constraints keep it honest:

  * The anchor must be a high-precision, self-describing string (`AKIA…`,
    `AC`+32hex). If the anchor is ambiguous the rule is not worth having.
  * The window is tight and measured in characters, not lines, because minified
    code has no lines.
  * The companion still passes every existing gate — placeholder allowlist,
    entropy floor, per-pattern match cap.
  * The companion must not be the anchor itself, and a value already typed by a
    real detector wins over the composite claim (see `_collapse_duplicates` in
    scanner.py): a composite is a fallback for what the registry missed, never a
    second opinion on what it caught.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# How far from an anchor a companion may sit, in characters. Minified bundles
# have no meaningful lines, so proximity has to be measured in characters.
# 250 is roughly "the same object literal or the same call's arguments" after
# minification, and deliberately not more: the further apart two values are, the
# less their adjacency means.
DEFAULT_WINDOW = 250


@dataclass(frozen=True)
class CompositeRule:
    """An anchor that lends its identity to a nearby value."""

    name: str                 # secret_type assigned to the companion when it fires
    anchor: re.Pattern[str]   # high-precision, self-describing, never reported alone
    companion: re.Pattern[str]  # the value that becomes findable once anchored
    severity: str
    window: int = DEFAULT_WINDOW
    rationale: str = ""       # goes into the finding's context, so a report can
                              # explain WHY a shapeless string was called a credential
    # Require the companion to use upper case, lower case AND digits.
    #
    # This is not a tuning knob, it is the fix for the first false positive the
    # ground-truth benchmark found. A 40-character git SHA is the same LENGTH as
    # an AWS secret key and appears in essentially every build, so `AKIA…` plus
    # any commit hash within the window produced a CRITICAL finding on a value
    # that is public by definition.
    #
    # An AWS secret key is 40 characters drawn from a 64-symbol base64 alphabet.
    # The probability that 40 such draws contain no uppercase letter is
    # (38/64)^40 — about 1 in 10^9. So demanding all three classes costs no real
    # recall, while a hex digest (one case, one class) can never satisfy it.
    require_mixed_alphabet: bool = False


COMPOSITE_RULES: list[CompositeRule] = [
    CompositeRule(
        name="AWS Secret Access Key",
        anchor=re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        # 40 chars of AWS's secret alphabet, quote-delimited so a slice of a
        # longer blob cannot masquerade as one.
        companion=re.compile(r"['\"]([A-Za-z0-9/+=]{40})['\"]"),
        severity="CRITICAL",
        require_mixed_alphabet=True,
        rationale=(
            "40-character AWS secret-key value found beside an AKIA access-key ID. "
            "The keyword-anchored detector cannot see this one — minification "
            "removed the 'aws'/'secret' names it needs."
        ),
    ),
    CompositeRule(
        name="Twilio Auth Token",
        anchor=re.compile(r"\bAC[0-9a-fA-F]{32}\b"),
        companion=re.compile(r"['\"]([0-9a-fA-F]{32})['\"]"),
        severity="HIGH",
        # A Twilio auth token IS 32 hex characters, so the mixed-alphabet test
        # that saves the AWS rule is unavailable here — an MD5 digest and a real
        # token are indistinguishable by shape. Proximity therefore has to carry
        # the whole weight, so the window is tightened to roughly "the same
        # object literal" rather than "the same region of the file".
        window=120,
        rationale=(
            "32-hex auth token found beside a Twilio Account SID (AC…). A bare "
            "32-hex string is indistinguishable from an MD5 digest; the adjacent "
            "SID is what identifies it as a credential."
        ),
    ),
]

# NOT a composite rule: OAuth client_secret.
#
# It was written as one and does not belong here. The test that every rule names
# a registry type caught it: the companion pattern requires the literal
# `client_secret` keyword, so it anchors itself and never consults the
# `client_id` beside it. A rule whose companion carries its own keyword is an
# ordinary keyword-anchored detector wearing a composite's clothes, and it
# belongs in the registry where its severity, CWE and remediation live. It is
# now `OAuth Client Secret` in scanner.SECRET_PATTERNS.
#
# The distinction is the whole point of this module: a composite rule earns its
# place only when the companion's own shape carries NO provider signal and the
# anchor is the sole source of identity. Both rules above meet that bar — a bare
# 40-char base64 blob and a bare 32-hex string are nothing on their own.


@dataclass(frozen=True)
class CompositeMatch:
    secret_type: str
    value: str
    start: int
    end: int
    severity: str
    rationale: str


def _mixed_alphabet(value: str) -> bool:
    """True if `value` uses upper case, lower case and digits.

    The discriminator between a base64 secret and a hex digest. See
    `require_mixed_alphabet` for why it costs no meaningful recall.
    """
    return (any(c.isupper() for c in value)
            and any(c.islower() for c in value)
            and any(c.isdigit() for c in value))


def find_composites(text: str, max_per_rule: int = 25) -> list[CompositeMatch]:
    """Every companion value that a nearby anchor identifies.

    `max_per_rule` bounds the work on a hostile or pathological blob, mirroring
    the per-pattern match cap the main scanner applies. It is a defence-in-depth
    bound, not a tuning knob: a page with more than 25 AWS secret keys beside
    their IDs has bigger problems than a truncated list.
    """
    out: list[CompositeMatch] = []
    for rule in COMPOSITE_RULES:
        anchors = [m.span() for m in rule.anchor.finditer(text)]
        if not anchors:
            # No anchor, no rule. This is the cheap exit that keeps the pass
            # affordable on every asset — anchors are rare by construction.
            continue

        found = 0
        for cm in rule.companion.finditer(text):
            if found >= max_per_rule:
                break
            value = cm.group(1) if cm.lastindex else cm.group(0)
            c_start, c_end = cm.span(1) if cm.lastindex else cm.span()

            if rule.require_mixed_alphabet and not _mixed_alphabet(value):
                continue

            near = False
            for a_start, a_end in anchors:
                # Overlapping spans mean the "companion" IS the anchor — an
                # AKIA ID is not its own secret key, and a Twilio SID is not its
                # own auth token. Without this the rule reports the public
                # identifier as the credential.
                if c_start < a_end and a_start < c_end:
                    continue
                distance = a_start - c_end if a_start > c_end else c_start - a_end
                if distance <= rule.window:
                    near = True
                    break
            if not near:
                continue

            found += 1
            out.append(CompositeMatch(
                secret_type=rule.name,
                value=value,
                start=c_start,
                end=c_end,
                severity=rule.severity,
                rationale=rule.rationale,
            ))
    return out
