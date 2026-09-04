#!/usr/bin/env python3
"""
triage.py — a verdict that needs no API key, no network and no model.

WHY THIS MODULE EXISTS
----------------------
With no `GEMINI_API_KEY`, every finding came back identically:

    is_valid=True, confidence=50, ai_judged=False, impact="", public_by_design=False

which is not a verdict, it is the absence of one. `classify_validated` reads
`ai_judged=False` and routes the lot to manual review, so an AWS secret key, a
Sentry DSN and a Stripe *publishable* key arrive in the operator's queue looking
exactly alike, none of them carrying a sentence about blast radius.

That is the DEFAULT configuration. The README documents offline operation on a
Pi as a first-class mode, and `_ai_skipped` exists precisely because running
without a key is expected. So the most common way to run this tool was also the
way that produced the least usable output.

WHAT THIS IS AND IS NOT
-----------------------
It is a deterministic triage tier: provider knowledge, context inspection and
the pattern registry, applied by rules. Same input, same verdict, every time —
which is worth stating because it is the property an AI tier cannot offer and
the one that makes an offline verdict auditable.

It is **not** a replacement for AI validation, and it does not pretend to be.
Its confidence values are capped below the confirmation threshold on purpose:
nothing here confirms a credential. Offline, the only thing that *proves* a
finding is `verifier.py` asking the provider whether the key still works — real
evidence, not an opinion — and that path is what promotes a finding to
confirmed. Triage's job is to make the queue mean something in the meantime:
drop what is known-public, drop generic noise from evidently non-production
code, and attach an impact sentence to everything that survives.

THE ASYMMETRY THAT DRIVES THE RULES
-----------------------------------
A dismissal and a confirmation are not equally costly. Confirming a false
positive wastes an analyst's afternoon. Dismissing a live credential is the
failure this whole tool exists to prevent. So every dismissal rule below has to
clear a much higher bar than every retention rule, and where a signal is
ambiguous the finding is retained.

The clearest case is test context. `key = "AKIA..."` inside `config.test.js` is
NOT evidence of a fake key — developers hardcode real credentials into test
fixtures constantly, and those fixtures ship in bundles. So a non-production
path dismisses a *generic keyword=value* match (which is what test scaffolding
mostly produces) and deliberately does **not** dismiss a provider-shaped one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import jwtclaims

# Confidence ceiling for anything this module says is real. It sits below
# GEMINI_CONFIDENCE_MIN (80) by construction: a rules engine that never saw the
# credential work should not be able to place a finding in a report section
# headed "confirmed". Verification promotes; triage does not.
MAX_RETAIN_CONFIDENCE = 75

# Confidence for a dismissal this module is genuinely sure of — a value whose
# type alone makes it public. Above the confirmation threshold so
# `classify_validated` treats it as a confident dismissal, exactly as it treats
# the same call from the AI tier.
CERTAIN_DISMISSAL_CONFIDENCE = 95


@dataclass(frozen=True)
class OfflineVerdict:
    """Mirrors the fields of GeminiVerdict so both tiers flow into
    ValidatedFinding through the same shape."""

    is_valid: bool
    confidence: int
    public_by_design: bool
    impact: str
    reason: str


# ── Public-by-design: the type alone settles it ──────────────────────────────
#
# These are not "probably fine" — they are values whose entire purpose is to be
# read by a browser. Reporting one as an exposure is not a harmless extra line
# in a report; it is a claim that costs the reader trust in every other line.
_PUBLIC_BY_TYPE: dict[str, str] = {
    "Stripe Publishable Key": (
        "A pk_ key is designed to ship in client code — it can create payment "
        "tokens and nothing else. The secret half (sk_) is what carries risk."
    ),
    "Sentry DSN": (
        "A DSN is an ingest endpoint meant to be embedded in the client. It "
        "permits sending events, not reading them."
    ),
    "PostHog Project API Key": (
        "A phc_ project key is a write-only ingest identifier intended for "
        "browser use; it grants no read access to captured data."
    ),
}

# ── Public-by-design: only in the right context ──────────────────────────────
#
# An AIza… value is a Firebase Web config key (public) or a server-side Google
# API key (not public), and the string alone cannot tell you which. The
# surrounding keys can: a Firebase web config always travels with its siblings.
_FIREBASE_WEB_CONTEXT = re.compile(
    r"(?i)\b(authDomain|projectId|storageBucket|messagingSenderId|appId|"
    r"measurementId|databaseURL)\b|firebaseapp\.com|firebaseio\.com"
)
_MAPS_CONTEXT = re.compile(
    r"(?i)maps\.googleapis\.com|maps\.google\.com|google\.maps|recaptcha"
)

# ── Non-production context ───────────────────────────────────────────────────
#
# Deliberately narrow. `staging` and `dev` are absent on purpose: staging
# credentials are real credentials against real infrastructure, and treating a
# staging key as noise is how a live leak gets closed as a false positive.
_NONPROD_CONTEXT = re.compile(
    r"(?i)\b(mock|dummy|fixture|sample|faker?|stub|lorem|"
    r"example[_-]?(?:key|token|secret|value)|test[_-]?(?:key|token|secret|value|data)|"
    r"describe|it\(|expect\(|assert)"
)
_NONPROD_PATH = re.compile(
    r"(?i)(^|[/._-])(tests?|__tests__|spec|specs|mocks?|__mocks__|fixtures?|"
    r"examples?|samples?|stories|storybook|e2e|cypress|jest|karma)([/._-]|$)"
)

# ── Impact: blast radius, offline ────────────────────────────────────────────
#
# The AI tier writes this sentence per finding. Offline it comes from provider
# knowledge keyed on the detector name, because a report that says what an
# attacker *gets* is the difference between a finding and a to-do item. Keys are
# matched as substrings so a family (every "… API Key") can share one entry
# without duplicating it per provider.
_IMPACT_BY_TYPE: list[tuple[str, str]] = [
    ("AWS Access Key", "Programmatic access to the AWS account as this IAM identity — "
                       "every resource its policies allow, billable to the account owner."),
    ("AWS Secret Access Key", "The signing half of an AWS credential pair; with the "
                              "matching key ID it authenticates as that IAM identity."),
    ("GCP Service Account", "Full API access as the service account, including every "
                            "IAM role bound to it — commonly storage and compute."),
    ("Private Key Block", "The private half of a key pair: decrypts traffic, signs as "
                          "the owner, or grants SSH access, depending on where it is used."),
    ("PGP Private Key", "Decrypts anything encrypted to this key and signs messages as "
                        "its owner."),
    ("Database Connection URI", "Direct authenticated access to the database, including "
                                "every record it holds."),
    ("Basic-Auth URL", "Credentials embedded in a URL authenticate directly to whatever "
                       "service that URL fronts."),
    ("Stripe Secret Key", "Live payment operations on the account: reading customers and "
                          "charges, issuing refunds, moving money."),
    ("GitHub", "Repository access as this account — source code, and where the token's "
               "scopes allow, pushes and CI secrets."),
    ("GitLab", "Repository and CI access as this account, including pipeline variables."),
    ("Slack", "Read and post access to the workspace's channels and their history."),
    ("Discord Bot Token", "Control of the bot account: reading and posting in every guild "
                          "it has joined."),
    ("Telegram Bot Token", "Control of the bot: reading its messages and posting as it."),
    ("SendGrid", "Sending mail as the account's verified domains — phishing with the "
                 "client's own deliverability reputation."),
    ("Mailgun", "Sending mail as the account's domains, and reading delivery logs."),
    ("Twilio", "Sending SMS and placing calls billed to the account, and reading message "
               "history."),
    ("OpenAI", "Inference billed to the account, and access to whatever the key's project "
               "scope covers."),
    ("Anthropic", "Inference billed to the account under this key's workspace."),
    ("API Key", "Authenticated API access to the provider as this account, billable and "
                "scoped to whatever the key permits."),
    ("Token", "Authenticated access to the provider as whoever this token represents."),
]

_IMPACT_FALLBACK = {
    "CRITICAL": "Direct authenticated access to the provider as this identity — treat as "
                "a live credential until proven rotated.",
    "HIGH":     "Authenticated access to the provider as this identity, scoped to whatever "
                "the credential permits.",
    "MEDIUM":   "Possible authenticated access; the value's scope cannot be determined "
                "from the client code alone.",
    "LOW":      "Limited or indirect access; review in context.",
    "INFO":     "",
}


def impact_for(secret_type: str, severity: str) -> str:
    """A blast-radius sentence for a secret type, with no model involved."""
    for needle, sentence in _IMPACT_BY_TYPE:
        if needle.lower() in secret_type.lower():
            return sentence
    return _IMPACT_FALLBACK.get(severity.upper(), _IMPACT_FALLBACK["MEDIUM"])


def looks_non_production(context_snippet: str, source_url: str) -> bool:
    """True if the surrounding code or the file's own path marks it as test,
    mock or example scaffolding.

    Used ONLY to dismiss generic keyword=value matches. See the module docstring:
    a provider-shaped key in a test fixture is very often a real key, and
    dismissing it on path alone would be the exact false negative this tool
    exists to prevent.
    """
    return bool(_NONPROD_CONTEXT.search(context_snippet or "")
                or _NONPROD_PATH.search(source_url or ""))


def triage(
    secret_type: str,
    raw_match: str,
    context_snippet: str,
    entropy: float,
    severity: str,
    structural: bool,
    source_url: str = "",
) -> OfflineVerdict:
    """Render a deterministic verdict for one finding.

    `structural` is the registry's own distinction: True for a high-precision
    provider/shape detector (AKIA…, ghp_…, PEM), False for the loose generic
    keyword=value catch-all. It is passed in rather than looked up so this
    module stays free of a circular import back into `scanner`.
    """
    snippet = context_snippet or ""

    # 1. Public by type. No context needed and none consulted — a pk_ key is a
    #    pk_ key wherever it appears.
    for type_name, why in _PUBLIC_BY_TYPE.items():
        if type_name.lower() in secret_type.lower():
            return OfflineVerdict(
                is_valid=False,
                confidence=CERTAIN_DISMISSAL_CONFIDENCE,
                public_by_design=True,
                impact="",
                reason=f"Public by design — {why}",
            )

    # 2. Public in context. A Google API key sitting in a Firebase web config or
    #    a Maps embed is an identifier. The same string with no such neighbours
    #    could be a server-side key, and is kept.
    if "google cloud api key" in secret_type.lower():
        if _FIREBASE_WEB_CONTEXT.search(snippet):
            return OfflineVerdict(
                is_valid=False,
                confidence=CERTAIN_DISMISSAL_CONFIDENCE,
                public_by_design=True,
                impact="",
                reason=(
                    "Public by design — a Firebase Web config apiKey, identified by the "
                    "authDomain/projectId/appId keys beside it. It is a project "
                    "identifier; risk lives in the Firebase Security Rules instead."
                ),
            )
        if _MAPS_CONTEXT.search(snippet):
            return OfflineVerdict(
                is_valid=False,
                confidence=CERTAIN_DISMISSAL_CONFIDENCE,
                public_by_design=True,
                impact="",
                reason=(
                    "Public by design — a browser Google Maps/reCAPTCHA key, which must "
                    "ship in client code. Restrict it by HTTP referrer rather than hiding it."
                ),
            )
        # No context either way: retained, and the reason says why it is
        # ambiguous rather than pretending to a judgement.
        return OfflineVerdict(
            is_valid=True,
            confidence=55,
            public_by_design=False,
            impact=impact_for(secret_type, severity),
            reason=(
                "Google API key with no Firebase/Maps config beside it — cannot be "
                "distinguished from a server-side key offline. Retained for review."
            ),
        )

    # 2b. A JWT that says what it is.
    #
    # Until v2.15.0 this tier could only see a JWT's shape, so it treated a
    # fifteen-minute session token, a token that expired in 2023, and an
    # unsigned admin token as one finding at one severity. The payload answers
    # all three questions with no network call and no key — see `jwtclaims`,
    # which reads only operational claims and never identity ones.
    #
    # The evidence this was needed came from a live scan: against vulnweb.com
    # the AI tier dismissed two JWTs by reading their payloads, and this tier
    # retained both, because with no API key it had no way to tell a
    # demonstration token from a live session.
    if "jwt" in secret_type.lower():
        facts = jwtclaims.read(raw_match)
        if facts.decoded:
            detail = facts.summary()

            # A token whose issuer is example.com is sample material. This is the
            # one JWT rule that dismisses outright, and it is safe because the
            # marker is in an operational claim the issuer chose, not in a
            # heuristic about the value.
            if facts.looks_like_sample:
                return OfflineVerdict(
                    is_valid=False,
                    confidence=CERTAIN_DISMISSAL_CONFIDENCE,
                    public_by_design=False,
                    impact="",
                    reason=(f"Demonstration token — the payload names a sample "
                            f"issuer or audience ({detail}). Not a live credential."),
                )

            # Expired: dismissed as an active credential, deliberately NOT
            # dropped. Confidence sits below the drop threshold on purpose, so
            # this routes to review rather than deletion — the token cannot be
            # used, but its presence still shows that tokens reach the bundle,
            # and a reader who sees nothing cannot tell which happened.
            if facts.expired:
                return OfflineVerdict(
                    is_valid=False,
                    confidence=MAX_RETAIN_CONFIDENCE,
                    public_by_design=False,
                    impact=("Already expired, so not usable as-is. Worth a look "
                            "anyway: a bundle that ships one token ships others, "
                            "and refresh tokens often sit beside access tokens."),
                    reason=f"JWT claims say it is expired ({detail}).",
                )

            # An unsigned token authenticates nothing — anyone can mint one with
            # any claims. That is a worse finding than the leak itself.
            if facts.unsigned:
                return OfflineVerdict(
                    is_valid=True,
                    confidence=MAX_RETAIN_CONFIDENCE,
                    public_by_design=False,
                    impact=("Header declares alg=none, so the signature is not "
                            "checked — anyone can forge a token with any claims, "
                            "including elevated scope. Reject alg=none server-side."),
                    reason=f"Unsigned JWT ({detail}).",
                )

            privileged = any(
                w in s.lower()
                for s in facts.scopes
                for w in ("admin", "write", "root", "superuser", "*", "full")
            )
            if facts.never_expires:
                return OfflineVerdict(
                    is_valid=True,
                    confidence=MAX_RETAIN_CONFIDENCE,
                    public_by_design=False,
                    impact=(("No expiry claim and a privileged scope: this is a "
                             "service token, usable until revoked at the issuer.")
                            if privileged else
                            ("No expiry claim — this token stays usable until it "
                             "is revoked at the issuer, not until it times out.")),
                    reason=f"JWT with no expiry ({detail}).",
                )

            return OfflineVerdict(
                is_valid=True,
                confidence=MAX_RETAIN_CONFIDENCE,
                public_by_design=False,
                impact=("A live-looking session token. Anyone holding it can act "
                        "as its subject until it expires."),
                reason=f"JWT decoded ({detail}).",
            )

    # 3. Non-production context, generic detector only.
    if not structural and looks_non_production(snippet, source_url):
        return OfflineVerdict(
            is_valid=False,
            confidence=CERTAIN_DISMISSAL_CONFIDENCE,
            public_by_design=False,
            impact="",
            reason=(
                "Generic keyword=value match inside evident test/mock scaffolding — "
                "the shape carries no provider signal and the context is not production code."
            ),
        )

    # 4. Retained. Confidence reflects how much the shape alone is worth, and is
    #    capped below the confirmation threshold: nothing offline is confirmed
    #    without the provider itself saying the key works.
    if structural:
        confidence = MAX_RETAIN_CONFIDENCE if entropy >= 3.5 else MAX_RETAIN_CONFIDENCE - 15
        reason = (
            f"Provider-shaped credential ({secret_type}); matched by structure, which is "
            f"high-precision. Not AI-validated and not verified — deterministic triage only."
        )
    else:
        confidence = 45
        reason = (
            "Generic keyword=value match in production-looking code. The shape carries no "
            "provider signal, so it cannot be judged further offline."
        )

    return OfflineVerdict(
        is_valid=True,
        confidence=confidence,
        public_by_design=False,
        impact=impact_for(secret_type, severity),
        reason=reason,
    )
