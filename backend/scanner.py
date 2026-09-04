"""
SecretNode v2.0 — scanner.py
Async passive scanning engine: spider → regex → entropy → Gemini → Discord
Optimised for Raspberry Pi 5 / Linux ARM64 with uvloop
"""

from __future__ import annotations

import asyncio
import functools
import hashlib
import json
import logging
import math
import os
import random
import re
import time
import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Callable, Coroutine
from urllib.parse import urljoin, urlparse

import httpx
from google import genai
from google.genai import errors as genai_errors, types
from pydantic import BaseModel, Field, ValidationError

import composite
import netguard
import posture
import surface
import triage
import verifier
import version

logger = logging.getLogger("secretnode.scanner")

# ── Environment ────────────────────────────────────────────────────────────────
GEMINI_API_KEY: str        = os.environ.get("GEMINI_API_KEY", "")
DISCORD_WEBHOOK_URL: str   = os.environ.get("DISCORD_WEBHOOK_URL", "")
VERIFY_SECRETS: bool       = os.environ.get("VERIFY_SECRETS", "false").lower() == "true"

# ── Gemini two-tier validation engine (google-genai SDK) ────────────────────────
# Tier 1 (pre-filter): a fast, cheap model with minimal reasoning strips obvious
# structural noise, mocks and placeholders. Tier 2 (deep validation): a stronger
# model with high reasoning confirms genuine, high-severity exposures. Model IDs
# and thinking levels are env-overridable so the engine tracks Google's lineup
# without a code change. A legacy single-model GEMINI_MODEL override, if present,
# is honoured as the Tier-1 model so existing deployments keep working.
#
# Defaults track Google's current lineup: Tier 1 on 3.5 Flash-Lite (fastest /
# most cost-effective 3.5-class, ideal for the high-volume pre-filter) and Tier 2
# on 3.8 Flash (stronger reasoning workhorse).
#
# Tier 2 moved 3.6 Flash -> 3.8 Flash in v2.16.0. Both bill at $0.75 / $3.75 per
# million tokens, so this is strictly more capability at identical cost, and the
# call was verified against a real key before the default changed rather than
# read off a price list. Tier 1 stays on 3.5 Flash-Lite: the pre-filter's job is
# to be cheap and high-volume, and it is not the tier that renders a verdict on
# a critical finding.
#
# This comment used to recommend the security-specialised "Flash Cyber" model
# for Tier 2 "once your key can call it". No ordinary key ever will: the Cyber
# models are not published to the public API at any tier, and access is an
# organisational grant under Google's Fairwind Program. Worse, taking that
# advice does not merely fail one call — the 404 is a permanent config error,
# so _describe_ai_config_error latches _ai_disabled_reason and AI validation is
# off for the ENTIRE scan, silently demoting every finding to offline triage.
# See .env.example for the full note.
_LEGACY_MODEL              = os.environ.get("GEMINI_MODEL", "").strip()
GEMINI_TIER1_MODEL: str    = os.environ.get("GEMINI_TIER1_MODEL", _LEGACY_MODEL or "gemini-3.5-flash-lite")
GEMINI_TIER2_MODEL: str    = os.environ.get("GEMINI_TIER2_MODEL", "gemini-3.8-flash")
GEMINI_TIER1_THINKING: str = os.environ.get("GEMINI_TIER1_THINKING", "minimal")
GEMINI_TIER2_THINKING: str = os.environ.get("GEMINI_TIER2_THINKING", "high")
# Severities that ALWAYS escalate to the deep tier, even if the cheap pre-filter
# would reject them — we never let a low-cost model be the last word on a critical
# secret (cloud keys, DB URIs, private keys). Comma-separated, case-insensitive.
GEMINI_ESCALATE_SEVERITIES: frozenset[str] = frozenset(
    s.strip().upper()
    for s in os.environ.get("GEMINI_ESCALATE_SEVERITIES", "CRITICAL").split(",")
    if s.strip()
)

# Lazily-constructed singleton client — built on first use, not at import, so the
# module imports cleanly with no key present (tests, CLI, CI) and a missing/invalid
# key degrades to needs-review instead of crashing the process at startup.
_genai_client: "genai.Client | None" = None


def _get_client() -> "genai.Client":
    global _genai_client
    if _genai_client is None:
        _genai_client = genai.Client(api_key=GEMINI_API_KEY)
    return _genai_client

# ── Tuning Constants (all overridable via environment variables) ────────────────
def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


CONCURRENCY_LIMIT       = _env_int("CONCURRENCY_LIMIT", 20)
FETCH_TIMEOUT           = _env_float("FETCH_TIMEOUT", 20.0)
RETRY_ATTEMPTS          = _env_int("RETRY_ATTEMPTS", 3)
RETRY_BACKOFF_BASE      = _env_float("RETRY_BACKOFF_BASE", 2.0)
MIN_ENTROPY_THRESHOLD   = _env_float("MIN_ENTROPY_THRESHOLD", 3.5)
MIN_STRUCTURAL_ENTROPY  = _env_float("MIN_STRUCTURAL_ENTROPY", 2.5)  # low anti-degenerate
                                     # floor for high-precision structural detectors: rejects
                                     # obvious junk (e.g. "AKIAAAAAAAAAAAAAAAAA", ~0.6 bits) while
                                     # still catching genuinely modest-entropy live keys that the
                                     # full generic bar would wrongly drop (false-negative guard).
CONTEXT_WINDOW_CHARS    = _env_int("CONTEXT_WINDOW_CHARS", 120)
MAX_ASSET_BYTES         = _env_int("MAX_ASSET_BYTES", 5 * 1024 * 1024)   # 5 MB
GEMINI_CONFIDENCE_MIN   = _env_int("GEMINI_CONFIDENCE_MIN", 80)
NEEDS_REVIEW_SENTINEL   = -1        # confidence value marking "AI validation failed — human must decide"
MAX_RAW_FINDINGS_PER_SCAN = _env_int("MAX_RAW_FINDINGS_PER_SCAN", 500)  # safety cap: stop a runaway scan
                                     # (e.g. a minified bundle full of high-entropy noise) from
                                     # generating unbounded Gemini calls / RAM use on the Pi
MAX_MATCHES_PER_PATTERN = _env_int("MAX_MATCHES_PER_PATTERN", 100)  # R3 defence-in-depth: bound the
                                     # matches examined for ANY single pattern on ANY single text, so a
                                     # crafted blob cannot spawn millions of matches for one detector.
# Every fetched body is held in one list until the scan ends, so the ceiling on
# a scan's memory is the SUM of what it collects, not the per-asset cap. The
# README credits CONCURRENCY_LIMIT with "bounds RAM on Pi 5 during deep JS
# analysis"; it bounds concurrent *fetches*, which is a different thing and does
# nothing about accumulation. Nothing capped the total, and js_urls is not capped
# either — every <script src> across every crawled page is fetched — so a site
# with many large bundles could push a 16 GB Pi into swap or the OOM killer, and
# a scan that dies is worth less than a scan that says what it could not read.
MAX_TOTAL_ASSET_BYTES = _env_int("MAX_TOTAL_ASSET_BYTES", 256 * 1024 * 1024)  # 256 MB
MAX_JS_ASSETS = _env_int("MAX_JS_ASSETS", 400)

MAX_SEED_URLS = _env_int("MAX_SEED_URLS", 200)  # cap externally-supplied seed assets fetched per scan
                                     # (e.g. historical JS bundles from public archives) — bounds the
                                     # extra fetches a deep scan does beyond the live crawl.
EXTRACT_SURFACE = os.environ.get("EXTRACT_SURFACE", "true").lower() == "true"  # slice 5/4:
                                     # mine fetched JS/HTML for referenced endpoints + external hosts
MAX_ENDPOINT_SEEDS = _env_int("MAX_ENDPOINT_SEEDS", 50)   # same-site .js endpoints to fetch (deeper crawl)
MAX_DISCOVERED_ENDPOINTS = _env_int("MAX_DISCOVERED_ENDPOINTS", 300)  # cap endpoints stored in report

# ── Type alias for the broadcaster callback ────────────────────────────────────
Broadcaster = Callable[[dict[str, Any]], Coroutine[Any, Any, None]]


# ─────────────────────────────────────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────────────────────────────────────

_DEFAULT_REMEDIATION = (
    "Treat as compromised: revoke/rotate the credential at the provider "
    "immediately, purge it from the asset and version-control history, and "
    "serve it from a server-side secret manager or environment variable "
    "instead of shipping it in client-side code."
)


@dataclass
class SecretPattern:
    name: str
    regex: re.Pattern[str]
    description: str
    severity: str = "HIGH"
    cwe: str = "CWE-798"                       # Use of Hard-coded Credentials
    remediation: str = _DEFAULT_REMEDIATION
    # Entropy handling differs by detector class:
    #   • Structural/provider detectors (AKIA…, ghp_…, sk_live_…, PEM blocks,
    #     fixed-format hex/UUID tokens) are high-precision by shape. They are
    #     asked only whether the value is degenerate filler — see
    #     looks_degenerate() — which rejects "AKIAAAAAAAAAAAAAAAAA" while still
    #     catching genuinely modest-entropy live keys, because gating these on
    #     the full generic bar silently drops real credentials (a false negative,
    #     the worst failure). That test replaced an absolute 2.5-bit floor, which
    #     did the same job for alphanumerics and dropped 2-5% of real NUMERIC ids
    #     for no reason but the base they are written in.
    #   • The generic keyword=value catch-all matches loosely and needs the full
    #     MIN_ENTROPY_THRESHOLD randomness signal to stay quiet; it opts in below.
    #   • The provider keyword-anchored detectors (`_contextual`) deliberately do
    #     NOT opt in, and the reason is worth recording. They have the same
    #     looseness, so the entropy gate was the obvious answer — and it is the
    #     wrong one. MIN_ENTROPY_THRESHOLD is 3.5 bits, which silently assumes a
    #     ~62-character alphabet: an 18-digit Discord client ID tops out at
    #     log2(10) = 3.32 and can never pass, however random it is. Gating them
    #     dropped four external specimens, every one of them digit- or hex-only.
    #     An absolute bit floor is a category error on a restricted alphabet.
    #     `_contextual` refuses identifiers by shape instead — see its docstring.
    entropy_gated: bool = False
    # Literal substrings, lowercased, of which AT LEAST ONE must appear in an
    # asset for this pattern to have any chance of matching. A necessary
    # condition, never a sufficient one: it decides whether to RUN the regex,
    # never whether a match counts.
    #
    # 108 patterns each make a full pass over every asset, which measured at
    # ~11 ms per pattern per megabyte — and on a real bundle almost none of the
    # provider names are present, so almost every one of those passes is a scan
    # of a megabyte to find nothing. gitleaks carries the same idea in its
    # `Keywords` field for the same reason.
    #
    # Soundness is not taken on trust: `test_prefilters_are_necessary_conditions`
    # asserts that every ground-truth specimen for a prefiltered detector
    # contains one of its literals. An unsound prefilter is a silent false
    # negative, which is the worst failure this scanner has, so the mechanism
    # only earns its place with that check attached.
    prefilter: tuple[str, ...] = ()


@dataclass
class RawFinding:
    scan_id: str
    target_url: str
    source_url: str
    secret_type: str
    raw_match: str
    context_snippet: str
    entropy: float
    found_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def fingerprint(self) -> str:
        """Stable identity for this exact secret at this exact location,
        independent of scan_id/timestamp. Used to detect recurring findings
        across scans and to support marking a finding as a false positive
        so it stops re-alerting on future scans of the same target."""
        raw = f"{self.secret_type}|{self.source_url}|{self.raw_match}"
        return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:16]


RAW_MATCH_CAP = 80


def _cap_raw(value: str) -> str:
    """Bound what gets persisted without destroying what identifies it.

    The old cap was `value[:80] + "…"`, which discarded the credential's tail —
    the very thing that distinguishes two long secrets found on the same host.
    Worse, the mask applied downstream then reported `value[-4:]` of the capped
    string, so a 112-character key surfaced as `ghp_AA…******…AAA…  (81 chars)`:
    a fabricated length and a tail made of padding and an ellipsis.

    Keeping the head *and* the real tail costs nothing and makes the mask
    truthful. The true length travels separately, in `raw_length`.
    """
    if len(value) <= RAW_MATCH_CAP:
        return value
    return f"{value[:RAW_MATCH_CAP - 5]}…{value[-4:]}"


@dataclass
class ValidatedFinding:
    raw: RawFinding
    is_valid: bool
    confidence: int
    reason: str
    validated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    is_new: bool = True   # set False by run_scan if this fingerprint was seen in a prior scan
    # False when the AI never rendered a verdict on this finding (no key, rejected
    # key, missing model). Distinct from "the AI said it is fake": there is no
    # verdict to trust, so routing must not act as though there were one.
    ai_judged: bool = True
    # True when `triage` rendered a deterministic verdict for this finding.
    # Distinct from ai_judged, and both can be False: that combination means no
    # tier reached a conclusion at all, which is the only case that must go to a
    # human on the grounds of ignorance rather than on the grounds of evidence.
    offline_triaged: bool = False
    verified: str = "disabled"  # live-verification status: verified/unverified/unsupported/disabled
    verified_detail: str = ""   # identity/scope of a VERIFIED credential (R1) — never the secret itself
    impact: str = ""            # AI blast-radius statement: what an attacker could actually do
    public_by_design: bool = False  # True for identifiers meant to be public (Firebase web key, pk_ …)

    def effective_severity(self) -> str:
        """Impact-aware severity. A value the AI judged public-by-design (a Firebase web
        apiKey, a publishable pk_ key, a Sentry DSN, …) is an identifier, not a secret —
        it is downgraded to INFO regardless of the pattern's registry severity, so the
        report leads with real impact instead of inflating known-public information."""
        if self.public_by_design:
            return "INFO"
        return self._meta().severity

    def to_dict(self) -> dict[str, Any]:
        # The surrounding code snippet is masked here, at the point the finding
        # leaves the dataclass, because every consumer of this dict is a place
        # the credential must not appear verbatim: the dashboard renders it in
        # the finding-detail modal, the JSON export writes it to a file the
        # client keeps, and SQLite persists it. Masking downstream is not
        # equivalent — only here is the *full* raw value still available to
        # match against, so a snippet holding a >80-char secret still gets
        # fully masked rather than partially.
        raw_value = self.raw.raw_match
        return {
            "fingerprint":    self.raw.fingerprint,
            "scan_id":        self.raw.scan_id,
            "target_url":     self.raw.target_url,
            "source_url":     self.raw.source_url,
            "secret_type":    self.raw.secret_type,
            "raw_match":      _cap_raw(raw_value),
            # The credential's real length, captured before the cap above throws
            # it away. Without this every long secret masks as "(81 chars)".
            "raw_length":     len(raw_value),
            "context_snippet": redact_snippet(self.raw.context_snippet, raw_value)[:400],
            "entropy":        self.raw.entropy,
            "is_valid":       self.is_valid,
            "confidence":     self.confidence,
            "reason":         self.reason,
            "impact":         self.impact,
            "public_by_design": self.public_by_design,
            "found_at":       self.raw.found_at,
            "validated_at":   self.validated_at,
            "is_new":         self.is_new,
            "verified":       self.verified,
            "verified_detail": self.verified_detail,
            "severity":       self.effective_severity(),
            "cwe":            self._meta().cwe,
            "remediation":    self._meta().remediation,
            # Which tier actually reached this verdict. A report that shows a
            # confidence number without saying who produced it invites the
            # reader to assume the strongest available tier ran, and for an
            # offline scan that assumption is wrong. Naming the tier is the
            # difference between a measurement and an unlabelled number.
            "validation_tier": self.validation_tier(),
        }

    def validation_tier(self) -> str:
        """'ai', 'offline-triage', or 'none'."""
        if self.ai_judged:
            return "ai"
        return "offline-triage" if self.offline_triaged else "none"

    def _meta(self) -> "SecretPattern":
        """Look up the registry metadata (severity/CWE/remediation) for this
        finding's secret type. Falls back to a safe MEDIUM/CWE-798 default for
        any type not in the registry."""
        meta = PATTERN_BY_NAME.get(self.raw.secret_type)
        if meta is not None:
            return meta
        return SecretPattern(
            name=self.raw.secret_type,
            regex=re.compile(r"(?!x)x"),  # never-matching placeholder
            description="unknown",
            severity="MEDIUM",
        )


# ─────────────────────────────────────────────────────────────────────────────
# Secret Pattern Registry
# ─────────────────────────────────────────────────────────────────────────────

# The loose keyword=value catch-all. Named here because the de-duplication pass
# needs to know which detector is the fallback: when a provider-specific detector
# has already typed a credential, the generic claim on the same value is dropped.
GENERIC_SECRET_TYPE = "Generic High-Entropy Secret"

def _contextual(keyword: str, value: str) -> "re.Pattern[str]":
    """`keyword … = value`, for providers whose value carries no shape at all.

    Asana, Confluent, KuCoin and the rest issue plain runs of alphanumerics.
    Nothing about `a7Fk…` says "Asana", so the provider name within thirty
    characters is the entire discriminator — the same construction as the
    Datadog and Heroku patterns above, factored out because this batch needed
    it eleven times.

    The separator class accepts the quoted form a JS bundle uses AND the bare
    `KEY=value` of a `.env` file or a shell export. Both reach this scanner: an
    exposed `.env` is one of the things it looks for, and gitleaks' own sample
    for Cohere is `export CO_API_KEY=…` with no quotes anywhere. A quote-only
    separator matched the bundle case and silently missed the file case.

    The lookahead refuses a value that CONTAINS the provider keyword, because
    that is a variable name and not a credential. Scanning this release's own
    diff with this scanner reported `linkedInClientId` as a LinkedIn client
    secret: sixteen alphanumerics, sitting exactly where a value goes, and in
    real code an assignment reads `linkedin_secret: linkedInSecret` far more
    often than it holds a literal. Nothing about the length or the alphabet
    separates the two — but a credential that spells its own provider's name
    does not exist, so the name is the discriminator.

    The trailing class also refuses a value that CONTINUES through `.`, `_` or
    `-`. Capturing the front of a longer credential is always wrong, and it
    happened: an Airtable personal access token is `pat` + 14 characters + `.` +
    64 hex, whose first segment is exactly the 17 alphanumerics the legacy
    Airtable key pattern wants. One credential produced two findings, and
    `_collapse_duplicates` could not merge them because the matched substrings
    differ — which is precisely the double-count it exists to prevent.
    """
    return re.compile(
        rf"(?i)(?:{keyword}).{{0,30}}?['\"=:\s](?!\w{{0,40}}?(?:{keyword}))"
        rf"({value})(?![A-Za-z0-9]|[._-][A-Za-z0-9])"
    )


_REGEX_META = set(".^$*+?{}[]\\|()")


def _literal_prefix(alternative: str) -> str:
    """The leading run of ordinary characters in one regex alternative.

    `linked[_-]?in` -> `linked`. Everything from the first metacharacter on is
    dropped, because only the plain prefix is guaranteed to appear verbatim in
    any string the alternative can match.
    """
    out: list[str] = []
    i = 0
    for i, ch in enumerate(alternative):
        if ch in _REGEX_META:
            break
        out.append(ch)
    else:
        i = len(alternative)
    # The last literal character may be the target of the quantifier that
    # stopped the walk, in which case it is optional and must not be required.
    # `https?://` yields `http`, not `https` — the soundness check caught this
    # by finding that the Basic-Auth URL detector would have skipped every
    # `http://user:pass@host`, which is precisely the credential it exists for.
    # `+` is left alone: one-or-more still requires the character once.
    if out and i < len(alternative) and alternative[i] in "?*{":
        out.pop()
    return "".join(out).lower()


def _keyword_prefilter(keyword: str) -> tuple[str, ...]:
    """Literals for a `_contextual` keyword, or () when none is safe.

    The keyword may be an alternation (`cohere|co_api_key`). EVERY branch has to
    yield a literal, because a single branch without one means the pattern can
    match text containing none of the others — and skipping that text would be a
    false negative. All or nothing is the only safe rule here.
    """
    parts = [_literal_prefix(a) for a in keyword.split("|")]
    return tuple(parts) if all(len(part) >= 3 for part in parts) else ()


SECRET_PATTERNS: list[SecretPattern] = [
    SecretPattern(
        name="AWS Access Key",
        # AKIA is only one of the prefixes AWS issues. ASIA is a temporary STS
        # credential and is *more* common in shipped frontend code than a
        # long-lived key, because that is exactly what a browser-side
        # credential-vending flow hands out — so matching only AKIA missed the
        # case most likely to appear on the surface this scanner reads.
        # Measured against gitleaks' corpus, which is where the gap showed up.
        regex=re.compile(r"\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"),
        description="AWS IAM Access Key ID (long-lived, temporary/STS, or service-specific)",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="AWS Bedrock API Key",
        # A 2025 credential type: a long base64 blob prefixed ABSK. Nothing in
        # the AKIA-shaped detectors comes close to matching it.
        regex=re.compile(r"\b((?:ABSK|AXSK)[A-Za-z0-9+/]{109,269}={0,2})"),
        description="Amazon Bedrock long-lived API key",
        severity="CRITICAL",
        remediation=(
            "Delete this Bedrock API key in the AWS console and issue a "
            "replacement held server-side. A leaked key bills model inference to "
            "your account and reaches every foundation model the associated "
            "identity may invoke; never ship one to a browser."
        ),
    ),
    SecretPattern(
        name="AWS Secret Access Key",
        regex=re.compile(
            r"(?i)aws.{0,20}secret.{0,20}['\"]([A-Za-z0-9/+=]{40})['\"]"
        ),
        description="AWS IAM Secret Access Key",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="Google Cloud API Key",
        regex=re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        description="Google Cloud / Firebase API Key",
        severity="HIGH",
    ),
    # Google's CURRENT key format, and the one that actually matters.
    #
    # AI Studio now issues `AQ.`-prefixed keys instead of `AIzaSy…`, and the
    # legacy format is being retired. That inverted this scanner's value on
    # Google: the `AIza` keys it reliably catches are, in real web bundles,
    # overwhelmingly Firebase *web config* keys — public by design, correctly
    # downgraded to INFO — while the `AQ.` keys it could not see at all are live
    # credentials with billing attached. It found the harmless ones and was blind
    # to the dangerous ones.
    #
    # Kept separate from the `AIza` detector rather than folded into it, because
    # the two differ in the way that decides a report: an `AIza` value may be
    # public by design and routinely is, an `AQ.` key never is. One severity and
    # one remediation cannot serve both.
    #
    # SIZING, honestly: Google has published no specification for this format.
    # The bound comes from an observed key — `AQ.` plus 50 base64url characters,
    # mixed case and digits — widened deliberately rather than pinned to that
    # length. Pinning an observed length is exactly what left the OpenAI pattern
    # demanding twenty characters before `T3BlbkFJ` and blind to every `sk-proj-`
    # key Google's counterpart issues today. The 30-character floor is what keeps
    # the short `AQ.` prefix from matching ordinary text; the ceiling is slack.
    #
    # `\b` before `AQ` is load-bearing, not decoration. It is what stops a JWT
    # whose segment happens to end in `AQ` from reading as a key: in
    # `…HUzI1NiAQ.eyJzdWI…` the `A` follows a word character, so no boundary
    # exists and no match is attempted. A real JWT can never open with `AQ.`
    # either — its first segment is base64 of `{"`, always `eyJ`.
    SecretPattern(
        name="Google AI Studio API Key",
        regex=re.compile(r"\b(AQ\.[A-Za-z0-9_-]{30,200})\b"),
        description="Google AI Studio / Gemini API key (AQ. format)",
        severity="CRITICAL",
        remediation=(
            "Delete this key at https://aistudio.google.com/apikey and issue a "
            "replacement held server-side. Unlike a Firebase web apiKey, an AI "
            "Studio key is never public by design: it bills model inference to "
            "the owning project and reaches every model the project can call. "
            "Proxy Gemini calls through your own backend so the key never enters "
            "a browser bundle."
        ),
    ),
    SecretPattern(
        name="Slack Webhook",
        regex=re.compile(
            r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+)"
        ),
        description="Slack Incoming Webhook URL",
        severity="HIGH",
    ),
    SecretPattern(
        name="JWT Token",
        regex=re.compile(
            r"\b(eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=+/]*)\b"
        ),
        description="JSON Web Token",
        severity="HIGH",
    ),
    SecretPattern(
        name="GitHub Personal Access Token",
        regex=re.compile(r"\b(ghp_[A-Za-z0-9]{36})\b"),
        description="GitHub PAT (classic)",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="GitHub OAuth Token",
        regex=re.compile(r"\b(gho_[A-Za-z0-9]{36})\b"),
        description="GitHub OAuth Access Token",
        severity="HIGH",
    ),
    SecretPattern(
        name="Stripe Secret Key",
        # Stripe issues restricted keys (rk_) alongside secret keys, and labels
        # the live environment both `live` and `prod`. Matching only sk_live_
        # missed a restricted key, which is a real credential with a real scope.
        regex=re.compile(r"\b((?:sk|rk)_(?:live|prod)_[0-9a-zA-Z]{24,})\b"),
        description="Stripe Live Secret Key",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="Stripe Test Key",
        regex=re.compile(r"\b((?:sk|rk)_test_[0-9a-zA-Z]{24,})\b"),
        description="Stripe test-mode secret/restricted key",
        severity="LOW",
        remediation=(
            "Roll this test key in the Stripe dashboard and keep it server-side. "
            "It cannot move real money, so this is not an emergency — but it "
            "reveals account structure and is often committed beside the live "
            "key it was copied from, which is the reason to look."
        ),
    ),
    SecretPattern(
        name="Stripe Publishable Key",
        regex=re.compile(r"\b(pk_live_[0-9a-zA-Z]{24,})\b"),
        description="Stripe Live Publishable Key",
        severity="MEDIUM",
    ),
    SecretPattern(
        name="SendGrid API Key",
        regex=re.compile(r"\b(SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43})\b"),
        description="SendGrid API Key",
        severity="HIGH",
    ),
    SecretPattern(
        name="Twilio Auth Token",
        regex=re.compile(r"(?i)twilio.{0,20}['\"]([0-9a-f]{32})['\"]"),
        description="Twilio Account Auth Token",
        severity="HIGH",
    ),
    SecretPattern(
        name="Private Key Block",
        regex=re.compile(
            r"(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)"
            # A header with nothing behind it is not a key. Empty PEM blocks ship
            # for real — templates that never rendered, fixtures, configs stripped
            # before publication — and each one was reported CRITICAL, because the
            # pattern asked only for the marker. Found by measuring this scanner
            # against gitleaks' declared non-secrets, where the empty OPENSSH block
            # is listed for exactly this reason.
            #
            # The lookahead demands real key material without capturing it: the
            # reported value stays the header alone, so masking, fingerprints and
            # memory are unchanged. The window is 300 characters rather than zero
            # because an encrypted key puts `Proc-Type:` and `DEK-Info:` between
            # the header and its base64, and those must still be found.
            r"(?=[\s\S]{0,300}?[A-Za-z0-9+/]{32})"
        ),
        description="PEM Private Key Block",
        severity="CRITICAL",
        cwe="CWE-321",   # Use of Hard-coded Cryptographic Key
    ),
    SecretPattern(
        name="Heroku API Key",
        regex=re.compile(
            r"(?i)heroku.{0,30}['\"]([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})['\"]"
        ),
        description="Heroku API Key",
        severity="HIGH",
    ),
    SecretPattern(
        name=GENERIC_SECRET_TYPE,
        regex=re.compile(
            r"(?i)(?:api[_-]?key|secret|token|password|passwd|auth)\s*[=:]\s*['\"]([A-Za-z0-9\-_.~+/]{20,80})['\"]"
        ),
        description="Generic credential assignment",
        severity="MEDIUM",
        entropy_gated=True,   # loose keyword=value match — entropy keeps it quiet
    ),
    # A secret hiding behind a build-time "public" prefix.
    #
    # Every SPA bundler inlines a whitelisted env prefix into the shipped bundle:
    # NEXT_PUBLIC_ (Next.js), REACT_APP_ (CRA), VITE_ (Vite), VUE_APP_ (Vue CLI),
    # NUXT_PUBLIC_, GATSBY_, EXPO_PUBLIC_, PUBLIC_ (SvelteKit). The prefix IS the
    # opt-in — it means "ship this to every browser" — and the failure this
    # catches is a developer reading it as a naming convention and putting a real
    # secret behind it. `NEXT_PUBLIC_STRIPE_SECRET_KEY` is not a hypothetical
    # shape; it is the single most common way a live key reaches a bundle today.
    #
    # The name is the whole signal, so this is keyword-anchored and lives here
    # rather than in composite.py — per that module's own rule, a companion
    # carrying its own keyword is an ordinary detector wearing a composite's
    # clothes.
    #
    # WHERE IT IS ACTUALLY FINDABLE, honestly: a fully minified Next.js bundle
    # has already substituted the literal for `process.env.NEXT_PUBLIC_…`, so the
    # name is gone and only the value ships. This detector fires on the forms
    # where the name survives — Angular `environment.ts` object literals compiled
    # verbatim, source maps' `sourcesContent`, unminified and dev builds, served
    # `.env` files, and any config object that enumerates the vars rather than
    # dereferencing them one by one. That is a real and large share of what a
    # crawler meets, but it is not all of it, and claiming otherwise would be the
    # kind of overstatement the benchmark caveat exists to prevent.
    #
    # Only names that DECLARE a secret qualify. `NEXT_PUBLIC_MAPBOX_TOKEN` and
    # `NEXT_PUBLIC_POSTHOG_KEY` are public by design and correctly ignored —
    # matching on "TOKEN" or "KEY" alone would turn this into a false-positive
    # engine on exactly the values the informational bucket exists to clear.
    SecretPattern(
        name="Framework Public Env Secret",
        regex=re.compile(
            r"(?:NEXT_PUBLIC|REACT_APP|VUE_APP|VITE|NUXT_PUBLIC|GATSBY|EXPO_PUBLIC|PUBLIC)"
            r"_[A-Z0-9_]{0,40}"
            r"(?:SECRET|PRIVATE|PASSWORD|PASSWD|SERVICE_ROLE|CLIENT_SECRET)"
            r"[A-Z0-9_]{0,40}"
            # Value charset excludes only quotes, whitespace and angle brackets
            # rather than allowlisting base64: a `_PASSWORD` is routinely full of
            # punctuation, and `hunter2Correct!Horse9Battery` was invisible while
            # this allowlisted `[A-Za-z0-9-_.~+/=]`. The name anchor is strong
            # enough to carry a permissive value — a bundle does not casually
            # contain `REACT_APP_..._SECRET=` beside something harmless.
            r"['\"]?\s*[=:]\s*['\"]([^'\"\s<>]{12,200})['\"]"
        ),
        description="Secret-named value behind a framework's public env prefix",
        severity="HIGH",
        remediation=(
            "This value is inlined into the browser bundle by the build — the "
            "NEXT_PUBLIC_/REACT_APP_/VITE_ prefix is precisely the instruction to "
            "publish it, so every visitor already has it. Treat it as compromised: "
            "rotate it at the provider, then move the call server-side (an API "
            "route or backend-for-frontend) and re-introduce the value WITHOUT the "
            "public prefix so the bundler cannot inline it again."
        ),
    ),
    SecretPattern(
        name="OAuth Client Secret",
        regex=re.compile(
            r"(?i)client[_-]?secret['\"]?\s*[=:]\s*['\"]([A-Za-z0-9\-_.~+/]{16,80})['\"]"
        ),
        description="OAuth 2.0 client secret",
        severity="HIGH",
        remediation=(
            "An OAuth client secret in browser-delivered code lets anyone "
            "impersonate the application to the identity provider and complete "
            "the authorization-code exchange. Rotate the secret at the provider, "
            "and move the exchange server-side — a public SPA client should use "
            "PKCE with no secret at all."
        ),
    ),
    SecretPattern(
        name="Mailgun API Key",
        regex=re.compile(r"\b(key-[0-9a-zA-Z]{32})\b"),
        description="Mailgun API Key",
        severity="HIGH",
    ),
    SecretPattern(
        name="Shopify Access Token",
        regex=re.compile(r"\b(shpat_[A-Za-z0-9]{32})\b"),
        description="Shopify Private App Access Token",
        severity="HIGH",
    ),
    # ── v2.2.0: expanded modern-provider coverage ──────────────────────────
    SecretPattern(
        name="GitHub Fine-Grained PAT",
        regex=re.compile(r"\b(github_pat_[0-9A-Za-z_]{82})\b"),
        description="GitHub fine-grained personal access token",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="GitLab Token (non-PAT)",
        # GitLab issues a whole family beyond glpat-: deploy, feed, runner,
        # pipeline-trigger, OAuth-app, SCIM, agent, incoming-mail, feature-flag,
        # CI job and runner-registration tokens. Only glpat- was matched, so a
        # runner or deploy token — each of which grants real repository or CI
        # access — read as an unrecognised string.
        regex=re.compile(
            r"\b((?:gldt|glft|glrt|glptt|gloas|glsoat|glagent|glimt|glffct|glcbt)"
            r"-[0-9A-Za-z_\-]{20,64}|GR1348941[0-9A-Za-z_\-]{20})\b"
        ),
        description="GitLab deploy / feed / runner / trigger / OAuth / SCIM token",
        severity="HIGH",
        remediation=(
            "Revoke this token in GitLab (Settings → Access Tokens, or the "
            "project's CI/CD settings for runner and deploy tokens) and issue a "
            "replacement stored in a masked CI variable. Depending on type it "
            "grants repository read/write, runner registration, or CI pipeline "
            "execution — none of which belongs in browser-delivered code."
        ),
    ),
    SecretPattern(
        name="GitLab Personal Access Token",
        regex=re.compile(r"\b(glpat-[0-9A-Za-z_\-]{20})\b"),
        description="GitLab personal access token",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="OpenAI API Key",
        # `T3BlbkFJ` is base64 "OpenAI" and sits inside every issued key — it is
        # the discriminator, so the segments around it carry no length promise.
        # Pinning them to exactly 20 was true of the original key format and is
        # not true of the current ones: an `sk-proj-` key runs to ~164
        # characters and an `sk-admin-` key to ~133, so both — the formats
        # OpenAI issues today, and the most commonly leaked AI credential —
        # went undetected. Found by measuring against gitleaks' corpus, whose
        # specimens carry the real marker.
        #
        # The lookahead keeps service-account keys with the detector that names
        # them; without it both would fire on one value and the report would
        # double-count a single credential.
        regex=re.compile(
            r"\b(sk-(?!svcacct-)(?:proj-|admin-)?[A-Za-z0-9_\-]{20,}"
            r"T3BlbkFJ[A-Za-z0-9_\-]{20,})\b"
        ),
        description="OpenAI API key (project or user)",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="Anthropic API Key",
        regex=re.compile(r"\b(sk-ant-[A-Za-z0-9_\-]{20,})\b"),
        description="Anthropic (Claude) API key",
        severity="CRITICAL",
    ),
    # ── AI / ML provider keys ────────────────────────────────────────────────
    # Modern AI stacks leak these constantly: the key is shipped to the browser
    # because a frontend calls the provider directly instead of proxying through
    # a backend. Each pattern below is structural (distinctive prefix + fixed
    # length), so it stays high-precision without the generic entropy gate.
    SecretPattern(
        name="ElevenLabs API Key",
        regex=re.compile(r"\b(sk_[a-f0-9]{48})\b"),
        description="ElevenLabs text-to-speech API key",
        severity="HIGH",
        remediation=(
            "Revoke this key in the ElevenLabs dashboard and issue a replacement. A leaked key "
            "lets anyone consume the account's character quota and credits, generate audio, and "
            "reach private/cloned voice models. Never ship it to the browser: proxy "
            "text-to-speech calls through your own backend so the key stays server-side."
        ),
    ),
    SecretPattern(
        name="Groq API Key",
        regex=re.compile(r"\b(gsk_[A-Za-z0-9]{52})\b"),
        description="Groq inference API key",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="Hugging Face Organization Token",
        # api_org_ is an organisation-wide token; hf_ (below) is per-user. The
        # organisation one has the wider blast radius and was the uncovered one.
        regex=re.compile(r"\b(api_org_[A-Za-z]{34})\b"),
        description="Hugging Face organization API token",
        severity="HIGH",
        remediation=(
            "Revoke this organization token in the Hugging Face settings and "
            "issue a replacement held server-side. It reaches every private "
            "model, dataset and Space the organization owns."
        ),
    ),
    SecretPattern(
        name="Hugging Face Access Token",
        regex=re.compile(r"\b(hf_[A-Za-z0-9]{34,40})\b"),
        description="Hugging Face user access token",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="Replicate API Token",
        regex=re.compile(r"\b(r8_[A-Za-z0-9]{37,45})\b"),
        description="Replicate model-inference API token",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="Perplexity API Key",
        regex=re.compile(r"\b(pplx-[A-Za-z0-9]{32,64})\b"),
        description="Perplexity AI API key",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="xAI API Key",
        regex=re.compile(r"\b(xai-[A-Za-z0-9]{64,100})\b"),
        description="xAI (Grok) API key",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="OpenRouter API Key",
        regex=re.compile(r"\b(sk-or-v1-[a-f0-9]{64})\b"),
        description="OpenRouter aggregated-inference API key",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="LangSmith API Key",
        regex=re.compile(r"\b(lsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10})\b"),
        description="LangSmith / LangChain tracing API key",
        severity="HIGH",
    ),
    SecretPattern(
        name="Pinecone API Key",
        regex=re.compile(r"\b(pcsk_[A-Za-z0-9_]{40,90})\b"),
        description="Pinecone vector-database API key",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="Slack Token",
        regex=re.compile(r"\b(xox[baprs]-[0-9A-Za-z\-]{12,72})\b"),
        description="Slack API token (bot/user/app/refresh)",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="npm Access Token",
        regex=re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"),
        description="npm registry access token",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="PyPI Upload Token",
        regex=re.compile(r"\b(pypi-AgEIcHlwaS[A-Za-z0-9_\-]{50,})\b"),
        description="PyPI API upload token",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="DigitalOcean PAT",
        regex=re.compile(r"\b(dop_v1_[a-f0-9]{64})\b"),
        description="DigitalOcean personal access token",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="HashiCorp Vault Token",
        regex=re.compile(r"\b(hvs\.[A-Za-z0-9_\-]{24,})\b"),
        description="HashiCorp Vault service token",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="Google OAuth Client Secret",
        regex=re.compile(r"\b(GOCSPX-[A-Za-z0-9_\-]{28})\b"),
        description="Google OAuth 2.0 client secret",
        severity="HIGH",
    ),
    SecretPattern(
        name="Square Access Token",
        regex=re.compile(r"\b(sq0atp-[A-Za-z0-9_\-]{22}|EAAA[A-Za-z0-9_\-]{60})\b"),
        description="Square API access token",
        severity="HIGH",
    ),
    SecretPattern(
        name="Postman API Key",
        regex=re.compile(r"\b(PMAK-[a-f0-9]{24}-[a-f0-9]{34})\b"),
        description="Postman API key",
        severity="HIGH",
    ),
    SecretPattern(
        name="Databricks Token",
        regex=re.compile(r"\b(dapi[a-f0-9]{32})\b"),
        description="Databricks personal access token",
        severity="HIGH",
    ),
    SecretPattern(
        name="Telegram Bot Token",
        regex=re.compile(r"\b([0-9]{8,10}:[A-Za-z0-9_\-]{35})\b"),
        description="Telegram Bot API token",
        severity="HIGH",
    ),
    SecretPattern(
        name="Discord Bot Token",
        regex=re.compile(r"\b([MNO][A-Za-z0-9_\-]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,38})\b"),
        description="Discord bot token",
        severity="HIGH",
    ),
    SecretPattern(
        name="Datadog API Key",
        regex=re.compile(r"(?i)datadog.{0,20}['\"]([a-f0-9]{32})['\"]"),
        description="Datadog API key (contextual)",
        severity="HIGH",
    ),
    SecretPattern(
        name="Azure Storage Account Key",
        regex=re.compile(r"AccountKey=([A-Za-z0-9+/=]{88})"),
        description="Azure Storage account key (connection string)",
        severity="CRITICAL",
        cwe="CWE-798",
    ),
    SecretPattern(
        name="Database Connection URI",
        regex=re.compile(
            r"\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://"
            r"[^:@/\s]+:[^@/\s]{3,}@[^\s'\"<>]+)"
        ),
        description="Database URI with embedded username:password",
        severity="CRITICAL",
        cwe="CWE-522",   # Insufficiently Protected Credentials
    ),
    SecretPattern(
        name="Basic-Auth URL Credentials",
        # The character classes exclude JS/JSON string boundaries, not just
        # whitespace. Excluding only `/` and space let a match start inside one
        # string literal and finish inside another:
        #
        #   {"homepage":"https://acme.com","author":"dev@acme.com"}
        #    -> https://acme.com","author":"dev@acme.com   [HIGH, fabricated]
        #
        # That is the shape of every package.json, and any path-less base URL in
        # a config object followed by a support email does the same. A `/` in the
        # URL's path happened to break the run, which is why this survived — the
        # false positive needs a base URL with no path, which is the commonest
        # form a config object holds.
        #
        # RFC 3986 userinfo is unreserved / pct-encoded / sub-delims / ":", so
        # quotes, angle brackets, braces and backslash are excluded by the spec
        # anyway. Comma and semicolon are sub-delims in principle; in shipped
        # JavaScript they mean "the string ended" far more often than they mean
        # "part of a password", and that trade buys back the whole false positive.
        regex=re.compile(
            r"\b(https?://[^:@/\s'\"<>{},;\\]+:[^@/\s'\"<>{},;\\]{3,}@[^\s'\"<>{},;\\]+)"
        ),
        description="Credentials embedded in an HTTP(S) URL",
        severity="HIGH",
        cwe="CWE-522",
    ),
    SecretPattern(
        name="Firebase Cloud Messaging Key",
        regex=re.compile(r"\b(AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140})\b"),
        description="Firebase Cloud Messaging server key",
        severity="HIGH",
    ),
    SecretPattern(
        name="Bearer Token",
        regex=re.compile(r"(?i)bearer\s+([A-Za-z0-9_\-\.=]{24,})"),
        description="HTTP Authorization bearer token (contextual)",
        severity="MEDIUM",
    ),
    SecretPattern(
        name="PGP Private Key Block",
        regex=re.compile(
            r"(-----BEGIN PGP PRIVATE KEY BLOCK-----)"
            # Same empty-block guard as the PEM detector above. A PGP armor
            # header may be followed by `Version:`/`Comment:` lines before the
            # base64 begins, which the 300-character window accommodates.
            r"(?=[\s\S]{0,300}?[A-Za-z0-9+/]{32})"
        ),
        description="PGP private key block",
        severity="CRITICAL",
        cwe="CWE-321",   # Use of Hard-coded Cryptographic Key
        remediation=(
            "Revoke this PGP key, generate a new keypair, and never commit "
            "private key material to a public asset or repository."
        ),
    ),
    # ── v2.3.0: additional modern detectors ────────────────────────────────
    SecretPattern(
        name="Slack App-Level Token",
        regex=re.compile(r"\b(xapp-[0-9]-[A-Z0-9]+-[0-9]+-[a-f0-9]{32,})\b"),
        description="Slack app-level token",
        severity="HIGH",
    ),
    SecretPattern(
        name="GitHub Server/Refresh Token",
        regex=re.compile(r"\b((?:ghs|ghr|ghu)_[A-Za-z0-9]{36})\b"),
        description="GitHub server-to-server / refresh / user-to-server token",
        severity="HIGH",
    ),
    SecretPattern(
        name="OpenAI Service Account Key",
        regex=re.compile(r"\b(sk-svcacct-[A-Za-z0-9_\-]{20,})\b"),
        description="OpenAI service-account API key",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="New Relic API Key",
        regex=re.compile(r"\b(NRAK-[A-Z0-9]{27}|NRAA-[a-f0-9]{27})\b"),
        description="New Relic user / admin API key",
        severity="HIGH",
    ),
    SecretPattern(
        name="Grafana Cloud Access Token",
        # glc_ is Grafana Cloud's access-policy token; glsa_ (below) is a
        # self-hosted service account. Different products, different prefixes —
        # matching only glsa_ left the hosted product uncovered.
        regex=re.compile(r"\b(glc_[A-Za-z0-9+/]{32,400}={0,3})"),
        description="Grafana Cloud access-policy token",
        severity="HIGH",
        remediation=(
            "Revoke this access policy token in Grafana Cloud and issue a "
            "replacement held server-side. It can read and write metrics, logs "
            "and traces for the stacks its policy covers."
        ),
    ),
    SecretPattern(
        name="Grafana Legacy API Key",
        # Base64 of {"k":"… — a JWT-shaped token with no dots, so the JWT
        # detector (which requires the header.payload.signature form) cannot see
        # it. Still issued by older self-hosted installations.
        regex=re.compile(r"\b(eyJrIjoi[A-Za-z0-9+/]{60,400}={0,3})"),
        description="Grafana legacy API key",
        severity="HIGH",
        remediation=(
            "Delete this API key in Grafana and replace it with a service "
            "account token held server-side. Legacy keys carry a fixed role "
            "(Viewer/Editor/Admin) over the whole organisation."
        ),
    ),
    SecretPattern(
        name="Grafana Service Account Token",
        regex=re.compile(r"\b(glsa_[A-Za-z0-9]{32}_[a-f0-9]{8})\b"),
        description="Grafana service-account token",
        severity="HIGH",
    ),
    SecretPattern(
        name="Terraform Cloud Token",
        regex=re.compile(r"\b([a-z0-9]{14}\.atlasv1\.[A-Za-z0-9_\-]{60,})\b"),
        description="HCP Terraform (Terraform Cloud) API token",
        severity="CRITICAL",
    ),
    # ── v2.4.0: current-generation providers (GitHub/GitGuardian 2026 patterns) ──
    SecretPattern(
        name="Supabase Access Token",
        regex=re.compile(r"\b(sbp_[a-f0-9]{40})\b"),
        description="Supabase personal/management access token",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="Supabase Secret Key",
        regex=re.compile(r"\b(sb_secret_[A-Za-z0-9_\-]{24,})\b"),
        description="Supabase service-role secret key (service_role replacement)",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="Sentry DSN",
        regex=re.compile(
            r"(https://[0-9a-f]{32}@(?:o\d+\.ingest\.)?[a-z0-9.\-]*sentry\.io/\d+)"
        ),
        description="Sentry DSN (allows event/error injection into the project)",
        severity="MEDIUM",
    ),
    SecretPattern(
        name="Linear API Key",
        regex=re.compile(r"\b(lin_api_[A-Za-z0-9]{40})\b"),
        description="Linear API key",
        severity="HIGH",
    ),
    SecretPattern(
        name="Notion Integration Token",
        regex=re.compile(r"\b((?:ntn_|secret_)[A-Za-z0-9]{43,50})\b"),
        description="Notion internal integration token",
        severity="HIGH",
    ),
    SecretPattern(
        name="Doppler Token",
        regex=re.compile(r"\b(dp\.(?:pt|st|ct|sa|scim|audit)\.[A-Za-z0-9]{40,44})\b"),
        description="Doppler service/personal/CLI token",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="PostHog Project API Key",
        regex=re.compile(r"\b(ph[cx]_[A-Za-z0-9]{43})\b"),
        description="PostHog project API key",
        severity="MEDIUM",
    ),
    SecretPattern(
        name="Figma Personal Access Token",
        regex=re.compile(r"\b(figd_[A-Za-z0-9_\-]{40,})\b"),
        description="Figma personal access token",
        severity="HIGH",
    ),
    SecretPattern(
        name="Cloudflare Origin CA Key",
        # A distinct credential from the cfat/cfut/cfk API tokens: it issues
        # origin certificates for any zone on the account.
        regex=re.compile(r"\b(v1\.0-[0-9a-f]{24}-[0-9a-f]{146})\b"),
        description="Cloudflare Origin CA key",
        severity="CRITICAL",
        remediation=(
            "Revoke this Origin CA key in the Cloudflare dashboard and issue a "
            "replacement server-side. It can mint origin certificates for zones "
            "on the account, which enables impersonating your origin."
        ),
    ),
    SecretPattern(
        name="Cloudflare API Token",
        regex=re.compile(r"\b((?:cfat|cfut|cfk)_[A-Za-z0-9_\-]{32,})\b"),
        description="Cloudflare API token (2026 prefixed format)",
        severity="HIGH",
    ),
    SecretPattern(
        name="GCP Service Account Key (JSON)",
        regex=re.compile(
            r'"private_key_id"\s*:\s*"([0-9a-f]{40})"'
        ),
        description="Google Cloud service-account JSON key (private_key_id)",
        severity="CRITICAL",
        cwe="CWE-798",
        remediation=(
            "A leaked service-account JSON key grants API access as that "
            "service account. Disable/delete the key in the GCP console "
            "immediately, rotate to a new key stored server-side, and audit "
            "the account's IAM roles for least privilege."
        ),
    ),

    # ── Providers added from gitleaks' rule definitions (v2.15.0) ────────────
    #
    # Every pattern below is transcribed from gitleaks' own published regex for
    # that provider, not inferred from a single observed sample. That distinction
    # is the whole reason these are safe to add in a batch: the shape is
    # documented by a second project that maintains it, so none of them encodes a
    # length this repository guessed at.
    #
    # They close the largest part of the "provider never claimed" bucket in
    # `make bench-external` — a bucket that is a coverage decision rather than a
    # defect, and was simply never decided.
    SecretPattern(
        name="Adobe Client Secret",
        regex=re.compile(r"\b(p8e-[A-Za-z0-9]{32})\b"),
        description="Adobe OAuth client secret",
        severity="HIGH",
    ),
    SecretPattern(
        name="Alibaba Access Key ID",
        regex=re.compile(r"\b(LTAI[A-Za-z0-9]{20})\b"),
        description="Alibaba Cloud access key ID",
        severity="HIGH",
    ),
    SecretPattern(
        name="Artifactory API Key",
        regex=re.compile(r"\b(AKCp[A-Za-z0-9]{69})\b"),
        description="JFrog Artifactory API key",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="Atlassian API Token",
        regex=re.compile(r"\b(ATATT3xFfGF0[A-Za-z0-9_\-=]{100,250})\b"),
        description="Atlassian (Jira/Confluence) API token",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="Defined Networking API Token",
        regex=re.compile(r"\b(dnkey-[A-Za-z0-9=_\-]{26}-[A-Za-z0-9=_\-]{52})\b"),
        description="Defined Networking API token",
        severity="HIGH",
    ),
    SecretPattern(
        name="Dynatrace API Token",
        regex=re.compile(r"\b(dt0c01\.[A-Za-z0-9]{24}\.[A-Za-z0-9]{64})\b"),
        description="Dynatrace API token",
        severity="HIGH",
    ),
    SecretPattern(
        name="Intra42 Client Secret",
        regex=re.compile(r"\b(s-s4t2(?:ud|af)-[A-Fa-f0-9]{64})\b"),
        description="42 Intra OAuth client secret",
        severity="HIGH",
    ),
    SecretPattern(
        name="PlanetScale API Token",
        regex=re.compile(r"\b(pscale_tkn_[A-Za-z0-9=\.\-_]{32,64})\b"),
        description="PlanetScale API token",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="PlanetScale OAuth Token",
        regex=re.compile(r"\b(pscale_oauth_[A-Za-z0-9=\.\-_]{32,64})\b"),
        description="PlanetScale OAuth token",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="PlanetScale Password",
        regex=re.compile(r"\b(pscale_pw_[A-Za-z0-9=\.\-_]{32,64})\b"),
        description="PlanetScale database password",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="RubyGems API Token",
        regex=re.compile(r"\b(rubygems_[a-f0-9]{48})\b"),
        description="RubyGems push/API token",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="Brevo (Sendinblue) API Token",
        regex=re.compile(r"\b(xkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16})\b"),
        description="Brevo / Sendinblue transactional-email API key",
        severity="HIGH",
    ),

    # ── Providers added from gitleaks' rule definitions (v2.16.0) ────────────
    #
    # The remainder of the "provider never claimed" bucket, plus the four rules
    # this scanner claimed a provider for and still missed. Same rule as the
    # v2.15.0 batch: every shape below is transcribed from gitleaks' published
    # regex rather than inferred from one observed sample.
    #
    # Two deliberate departures from the reference are marked at their pattern.
    # A transcription is not an obligation to copy a pattern this scanner would
    # not otherwise accept.

    # Structure-anchored: a distinctive prefix carries the whole match, so these
    # need no neighbouring keyword and stay high-precision on minified bundles.
    SecretPattern(
        name="Artifactory Reference Token",
        # `cmVmd` is base64 for `refe…` — the token's own prefix, encoded.
        # Separate from the AKCp API key above because Artifactory issues both
        # and they share no shape.
        regex=re.compile(r"\b(cmVmd[A-Za-z0-9]{59})\b"),
        description="JFrog Artifactory reference token",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="GitLab Session Cookie",
        # Not an API token: a live browser session. Anyone holding it acts as
        # the signed-in user until it expires, with no key to revoke.
        regex=re.compile(r"(?i)(_gitlab_session=[0-9a-z]{32})"),
        description="GitLab session cookie",
        severity="CRITICAL",
        cwe="CWE-539",   # Use of Persistent Cookies Containing Sensitive Information
        remediation=(
            "Terminate the session in GitLab (Settings -> Active Sessions) "
            "rather than rotating a key — there is no key. Then find why a "
            "session cookie reached a public asset; it is usually a captured "
            "request pasted into a fixture or a debug log."
        ),
    ),
    SecretPattern(
        name="age Secret Key",
        # Bech32 charset, so the body excludes 1/b/i/o by construction.
        regex=re.compile(r"\b(AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58})\b"),
        description="age file-encryption private key",
        severity="CRITICAL",
        cwe="CWE-321",
        remediation=(
            # The default advice — revoke at the provider — has no meaning here.
            # There is no provider and no revocation: an age key is a local
            # asymmetric key, so exposure is permanent for everything it has
            # already encrypted.
            "There is nothing to revoke: age keys are local, so every file this "
            "key can decrypt must be treated as readable by anyone who saw it. "
            "Generate a new keypair, re-encrypt that data to it, and rotate any "
            "secrets the old ciphertext contained."
        ),
    ),
    SecretPattern(
        name="1Password Service Account Token",
        # `-_` as well as `+/`: gitleaks' class is base64 only, and the same blob
        # travels base64url-encoded wherever it passes through a URL or an env
        # file. A token holding one `-` would otherwise be truncated at it, or
        # dropped outright if the truncation fell short of 250 characters. The
        # `ops_eyJ` prefix is the discriminator, so widening the body costs
        # nothing in precision.
        regex=re.compile(r"\b(ops_eyJ[A-Za-z0-9+/_-]{250,}={0,3})"),
        description="1Password service-account token",
        severity="CRITICAL",
        remediation=(
            "Revoke the service account in 1Password. This token reads every "
            "vault the account was granted, so treat all secrets in those "
            "vaults as exposed and rotate them too."
        ),
    ),
    SecretPattern(
        name="1Password Secret Key",
        # The hyphens are readability only and 1Password strips them at login,
        # but every exported or copied key carries one of these two groupings.
        regex=re.compile(
            r"\b(A3-[A-Z0-9]{6}-(?:[A-Z0-9]{11}|[A-Z0-9]{6}-[A-Z0-9]{5})"
            r"-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5})\b"
        ),
        description="1Password account secret key",
        severity="CRITICAL",
        remediation=(
            "The Secret Key is one of the two factors that derive the account's "
            "encryption key; it cannot be rotated on its own. Change the account "
            "password, which reissues the Secret Key, then re-download the "
            "Emergency Kit. Until that is done, treat every item in the account's "
            "vaults as exposed to anyone who also has the password."
        ),
    ),
    SecretPattern(
        name="Airtable Personal Access Token",
        regex=re.compile(r"\b(pat[A-Za-z0-9]{14}\.[a-f0-9]{64})\b"),
        description="Airtable personal access token",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="Sourcegraph Access Token",
        # DEPARTURE 1, and it is a split rather than a refusal. gitleaks' rule
        # offers three alternatives in one pattern, the third being a bare
        # 40-character hex string. Transcribed as written it would match every
        # Git SHA-1, every sha1 digest and every 40-hex id in a bundle — a rule
        # that fires on every commit hash in a source map costs more trust than
        # the tokens it recovers.
        #
        # But gitleaks does not apply that alternative bare either: its rule
        # carries a `sourcegraph`/`sgp_` keyword precondition and an entropy
        # floor, and this registry has no keyword mechanism of its own. So the
        # two halves are separated instead — the sgp_ forms here, unconditional
        # because the prefix is the discriminator, and the legacy bare-hex form
        # below with the keyword written into the pattern. Same coverage as the
        # reference, same precondition, expressed where this scanner can see it.
        regex=re.compile(
            r"\b(sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}|sgp_[a-fA-F0-9]{40})\b"
        ),
        description="Sourcegraph access token",
        severity="HIGH",
    ),
    SecretPattern(
        name="Sourcegraph Access Token (legacy)",
        regex=_contextual("sourcegraph", r"[a-fA-F0-9]{40}"),
        description="Sourcegraph legacy access token (contextual)",
        severity="HIGH",
        prefilter=_keyword_prefilter("sourcegraph"),
    ),
    # DEPARTURE 2, in the other direction: matched WITHOUT the `mapbox` keyword
    # gitleaks requires, because the `pk.eyJ` / `sk.eyJ` prefix is unambiguous on
    # its own and a bundled map widget rarely names its vendor nearby.
    #
    # The LENGTHS here are this project's, not gitleaks'. Transcribing its
    # `pk\.[a-z0-9]{60}\.[a-z0-9]{22}` literally produced a detector that matched
    # gitleaks' generated samples, scored 100% on both benchmarks, and matched
    # ZERO real tokens — including the one Mapbox publishes in its own
    # documentation, whose payload is 62 characters rather than 60.
    #
    # A Mapbox token is a JWT: `pk.<base64url payload>.<base64url signature>`,
    # and the payload encodes the account name, so its length varies with the
    # account — 59 to 92 across ordinary usernames. A fixed 60 is a snapshot of
    # one generator's output, not a format. Ranges here, with `eyJ` (base64 for
    # `{"`) carrying the precision the fixed length was only pretending to.
    SecretPattern(
        name="Mapbox Public Token",
        regex=re.compile(r"\b(pk\.eyJ[A-Za-z0-9_-]{20,400}\.[A-Za-z0-9_-]{20,86})\b"),
        description="Mapbox public access token (client-side by design)",
        severity="LOW",
        remediation=(
            "A pk. token is Mapbox's client-side token and has to ship in the "
            "browser for a map to render — rotating it is not the fix. Check its "
            "URL restrictions and scopes in the Mapbox account settings so it "
            "cannot be lifted and billed against another site."
        ),
    ),
    SecretPattern(
        name="Mapbox Secret Token",
        # The half gitleaks' rule does not cover, and the one that matters. An
        # sk. token carries account-management scopes — it can read, create and
        # DELETE other tokens — and must never leave a server.
        regex=re.compile(r"\b(sk\.eyJ[A-Za-z0-9_-]{20,400}\.[A-Za-z0-9_-]{20,86})\b"),
        description="Mapbox secret access token",
        severity="CRITICAL",
        remediation=(
            "Delete this token in the Mapbox account settings immediately — a "
            "secret token can enumerate and revoke your other tokens and bills "
            "usage to the account. Issue a replacement held server-side, and "
            "ship a URL-restricted pk. token to the browser instead."
        ),
    ),
    SecretPattern(
        name="GCP Service Account JSON",
        # The `private_key_id` detector above needs that field to be present.
        # This marker survives a JSON that was trimmed to its useful fields, and
        # a service-account document in a shipped bundle is the finding whether
        # or not the key id came with it. HIGH rather than CRITICAL: the marker
        # proves the document, the private_key detector proves the key.
        # Only when the document does NOT also carry a private_key_id. Google's
        # generated JSON opens with `"type"` and reaches `private_key_id` a
        # couple of fields later, so on a complete file the key-id detector
        # above claims it and this one stays silent — one document, one finding.
        # `_collapse_duplicates` cannot do that job here: the two detectors match
        # different substrings, so they are not duplicates by its definition
        # (same URL, same matched value) even though they describe one exposure.
        # The lookahead is what keeps a trimmed document covered without
        # double-reporting a whole one.
        regex=re.compile(
            r'("type"\s*:\s*"service_account")(?![\s\S]{0,600}?"private_key_id")'
        ),
        description="Google Cloud service-account JSON document",
        severity="HIGH",
        cwe="CWE-798",
        remediation=(
            "This marker says a service-account key document is present, whether "
            "or not its private_key survived the trim. Find the account in the "
            "GCP console, delete every key issued to it, and audit its IAM roles "
            "— a service account in a browser bundle usually has far broader "
            "scope than the one call the frontend needed."
        ),
    ),

    # Keyword-anchored. These providers issue values with no distinguishing
    # shape — 16 to 64 alphanumerics — so the provider name within 30 characters
    # is what separates a credential from any other string of that length. Same
    # construction as the Datadog and Heroku patterns above.
    SecretPattern(
        name="Discord Client Secret",
        regex=_contextual("discord", r"[A-Za-z0-9_\-]{32}"),
        description="Discord OAuth client secret (contextual)",
        severity="HIGH",
        prefilter=_keyword_prefilter("discord"),
    ),
    SecretPattern(
        name="Discord Client ID",
        # 17-20, not 18. A Discord ID is a snowflake — `(ms since 2015) << 22` —
        # so its width grows with the calendar and is not a property of the
        # format. gitleaks' 18 held from roughly 2016 to 2021; IDs minted since
        # 2022 are 19 digits, so the transcribed pattern missed every Discord
        # application created in the last four years. Found by computing
        # snowflakes for known dates, not by stumbling on one.
        regex=_contextual("discord", r"[0-9]{17,20}"),
        description="Discord OAuth client ID (public identifier)",
        severity="LOW",
        remediation=(
            # The default text — "treat as compromised, revoke immediately" — is
            # not merely unhelpful here, it is wrong, and wrong advice on a LOW
            # finding is how a reader learns to skim the CRITICAL ones.
            "An OAuth client ID is published in every authorization URL the "
            "application builds — it is not a leak and there is nothing to "
            "revoke. Treat it as a pointer: confirm the matching client SECRET "
            "is not in the same bundle, and that the redirect URIs registered "
            "for this client are restricted to hosts you control."
        ),
        prefilter=_keyword_prefilter("discord"),
    ),
    SecretPattern(
        name="Asana Client Secret",
        regex=_contextual("asana", r"[A-Za-z0-9]{32}"),
        description="Asana OAuth client secret (contextual)",
        severity="HIGH",
        prefilter=_keyword_prefilter("asana"),
    ),
    SecretPattern(
        name="Asana Client ID",
        # A range for the same reason as Discord above: an Asana gid is an
        # allocated numeric id that has been getting longer, so a fixed width is
        # a snapshot of when the reference rule was written. Kept narrower than
        # Discord's, because the growth here is observed rather than derivable
        # from a documented formula.
        regex=_contextual("asana", r"[0-9]{15,19}"),
        description="Asana OAuth client ID (public identifier)",
        severity="LOW",
        remediation=(
            # The default text — "treat as compromised, revoke immediately" — is
            # not merely unhelpful here, it is wrong, and wrong advice on a LOW
            # finding is how a reader learns to skim the CRITICAL ones.
            "An OAuth client ID is published in every authorization URL the "
            "application builds — it is not a leak and there is nothing to "
            "revoke. Treat it as a pointer: confirm the matching client SECRET "
            "is not in the same bundle, and that the redirect URIs registered "
            "for this client are restricted to hosts you control."
        ),
        prefilter=_keyword_prefilter("asana"),
    ),
    SecretPattern(
        name="LinkedIn Client Secret",
        regex=_contextual("linked[_-]?in", r"[A-Za-z0-9]{16}"),
        description="LinkedIn OAuth client secret (contextual)",
        severity="HIGH",
        prefilter=_keyword_prefilter("linked[_-]?in"),
    ),
    SecretPattern(
        name="LinkedIn Client ID",
        regex=_contextual("linked[_-]?in", r"[A-Za-z0-9]{14}"),
        description="LinkedIn OAuth client ID (public identifier)",
        severity="LOW",
        remediation=(
            # The default text — "treat as compromised, revoke immediately" — is
            # not merely unhelpful here, it is wrong, and wrong advice on a LOW
            # finding is how a reader learns to skim the CRITICAL ones.
            "An OAuth client ID is published in every authorization URL the "
            "application builds — it is not a leak and there is nothing to "
            "revoke. Treat it as a pointer: confirm the matching client SECRET "
            "is not in the same bundle, and that the redirect URIs registered "
            "for this client are restricted to hosts you control."
        ),
        prefilter=_keyword_prefilter("linked[_-]?in"),
    ),
    SecretPattern(
        name="Cohere API Token",
        regex=_contextual("cohere|co_api_key", r"[A-Za-z0-9]{40}"),
        description="Cohere API token (contextual)",
        severity="CRITICAL",
        prefilter=_keyword_prefilter("cohere|co_api_key"),
    ),
    SecretPattern(
        name="Confluent Secret Key",
        regex=_contextual("confluent", r"[A-Za-z0-9]{64}"),
        description="Confluent Cloud secret key (contextual)",
        severity="CRITICAL",
        prefilter=_keyword_prefilter("confluent"),
    ),
    SecretPattern(
        name="Confluent Access Token",
        regex=_contextual("confluent", r"[A-Za-z0-9]{16}"),
        description="Confluent Cloud access token (contextual)",
        severity="HIGH",
        prefilter=_keyword_prefilter("confluent"),
    ),
    SecretPattern(
        name="KuCoin Secret Key",
        regex=_contextual(
            "kucoin",
            r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
        ),
        description="KuCoin API secret key (contextual)",
        severity="CRITICAL",
        remediation=(
            "Delete this API key in the KuCoin account settings now, then review "
            "trade and withdrawal history for activity you did not initiate — an "
            "exchange credential can move funds, so rotation alone is not the end "
            "of the incident. Reissue with the narrowest permissions and an IP "
            "allowlist, and never ship one to a browser."
        ),
        prefilter=_keyword_prefilter("kucoin"),
    ),
    SecretPattern(
        name="KuCoin Access Token",
        regex=_contextual("kucoin", r"[a-f0-9]{24}"),
        description="KuCoin API access token (contextual)",
        severity="CRITICAL",
        prefilter=_keyword_prefilter("kucoin"),
    ),
    SecretPattern(
        name="Airtable API Key",
        regex=_contextual("airtable", r"[A-Za-z0-9]{17}"),
        description="Airtable legacy API key (contextual)",
        severity="HIGH",
        prefilter=_keyword_prefilter("airtable"),
    ),
]

def _derive_prefilter(pattern: re.Pattern[str]) -> tuple[str, ...]:
    """A mandatory literal read off a prefix-anchored pattern, or ().

    Deliberately timid, because an unsound prefilter is a silent false negative
    and this runs over the whole registry. Three conditions, all required:

      * no `|` anywhere in the source — an alternation could offer a branch that
        does not contain the prefix, and skipping text for a literal only SOME
        branches need is exactly the mistake worth being afraid of here;
      * the pattern opens with the usual `(?i)? \b? (` scaffolding and then at
        least four ordinary characters;
      * those characters are not themselves a character class or quantifier.

    Everything else keeps an empty prefilter and is scanned as before. A
    detector losing a speed-up costs milliseconds; a detector losing a match
    costs the entire point of the tool.
    """
    src = pattern.pattern
    if "|" in src:
        return ()
    i = 0
    if src.startswith("(?i)"):
        i = 4
    while i < len(src) and src[i] in "(^":
        if src.startswith("(?:", i) or src.startswith("(?=", i) or src.startswith("(?!", i):
            return ()
        i += 1
    if src.startswith("\\b", i):
        i += 2
    while i < len(src) and src[i] in "(":
        i += 1
    literal = _literal_prefix(src[i:])
    return (literal,) if len(literal) >= 4 else ()


# Fill in prefilters for the prefix-anchored patterns that did not declare one.
# Keyword-anchored detectors set theirs explicitly via `_keyword_prefilter`.
SECRET_PATTERNS = [
    p if (p.prefilter or p.name == GENERIC_SECRET_TYPE)
    else replace(p, prefilter=_derive_prefilter(p.regex))
    for p in SECRET_PATTERNS
]

# Fast name -> pattern lookup (severity / CWE / remediation metadata).
PATTERN_BY_NAME: dict[str, SecretPattern] = {p.name: p for p in SECRET_PATTERNS}


# ─────────────────────────────────────────────────────────────────────────────
# Shannon Entropy
# ─────────────────────────────────────────────────────────────────────────────

def shannon_entropy(data: str) -> float:
    """Return Shannon entropy (bits/char) of the given string."""
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(data)
    return round(
        -sum((c / length) * math.log2(c / length) for c in freq.values()),
        4,
    )


def passes_entropy_check(value: str) -> bool:
    return shannon_entropy(value) >= MIN_ENTROPY_THRESHOLD


def redact_secret(value: str) -> str:
    """Partially mask a secret: keep a short prefix, mask the rest."""
    if len(value) <= 8:
        return "*" * len(value)
    keep = min(6, len(value) // 4)
    return value[:keep] + "*" * (len(value) - keep)


def redact_snippet(snippet: str, secret_value: str) -> str:
    """Replace every occurrence of the raw secret inside a text snippet with
    its redacted form. This MUST be applied before any snippet is sent to an
    external destination (Discord, logs) — the un-redacted snippet previously
    leaked the full secret even though the standalone 'matched value' field
    was masked."""
    if not secret_value:
        return snippet
    return snippet.replace(secret_value, redact_secret(secret_value))


# ─────────────────────────────────────────────────────────────────────────────
# HTTP Client
# ─────────────────────────────────────────────────────────────────────────────
#
# Real-world lesson (v2.4.0): a "compatible; SecretNode-bot" User-Agent gets an
# instant HTTP 403 from Cloudflare/Akamai/AWS-WAF-fronted sites, so the scanner
# could not even fetch the root of a WAF-protected target you legitimately own.
# An authorized ASM scanner must look like a normal browser to reach the same
# surface an attacker would — every serious scanner (Burp, ZAP, nuclei) ships a
# browser UA. We present a current Chrome fingerprint (UA + Client-Hints +
# Sec-Fetch metadata + HTTP/2) and rotate the UA on a WAF challenge. This is
# resilience for authorized testing, not evasion: scope, SSRF guard, passive-only
# behaviour and the authorization gate (SECURITY.md) are unchanged.

# A small pool of current, real desktop browser User-Agents. On a WAF block we
# retry with the next one before giving up.
_USER_AGENTS: tuple[str, ...] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
)
# Operator override (e.g. to match a client's approved test-agent string).
_UA_OVERRIDE = os.environ.get("SECRETNODE_USER_AGENT", "").strip()

# HTTP status codes that usually mean "a WAF/CDN edge challenged this automated
# request" rather than "this resource is truly gone" — worth one more try with a
# different browser fingerprint before we treat the asset as unreachable.
_WAF_BLOCK_CODES = frozenset({401, 403, 406, 429, 503})


# ── Politeness: adaptive per-host throttle (v2.7.5) ──────────────────────────
#
# Being a good guest on a client's infrastructure is part of the engagement, not
# an afterthought: an authorized scan that trips rate limiting looks like an
# attack to their SOC and gets the scanner blocked mid-assessment. Two mechanics:
#
#   • Jittered backoff. A deterministic 2**attempt makes every concurrent worker
#     retry on the same tick — a thundering herd that keeps the host saturated
#     exactly when it asked for relief. Randomising the delay spreads retries out.
#   • Adaptive throttle. When a host answers 429/503 we start pacing subsequent
#     requests to *that host only*, growing the pace while it keeps complaining
#     and decaying it as it recovers. Cost is zero while a host is healthy.

THROTTLE_MAX_DELAY = _env_float("THROTTLE_MAX_DELAY", 5.0)
THROTTLE_STEP      = _env_float("THROTTLE_STEP", 0.5)
RETRY_MAX_BACKOFF  = _env_float("RETRY_MAX_BACKOFF", 30.0)

# host -> current politeness delay in seconds. Module-level so every worker
# sharing the event loop cooperates on the same host budget.
_host_delays: dict[str, float] = {}


def reset_throttle() -> None:
    """Clear all learned per-host pacing (used between scans and in tests)."""
    _host_delays.clear()


def _throttle_penalise(host: str) -> float:
    """Record a rate-limit signal from `host`; return the new delay."""
    delay = min(_host_delays.get(host, 0.0) + THROTTLE_STEP, THROTTLE_MAX_DELAY)
    _host_delays[host] = delay
    return delay


def _throttle_reward(host: str) -> None:
    """A clean response — relax pacing for `host`, forgetting it once healthy."""
    current = _host_delays.get(host)
    if current is None:
        return
    relaxed = current - (THROTTLE_STEP / 2)
    if relaxed <= 0:
        _host_delays.pop(host, None)
    else:
        _host_delays[host] = relaxed


async def _throttle_wait(host: str) -> None:
    """Pace a request to a host that has recently rate-limited us."""
    delay = _host_delays.get(host, 0.0)
    if delay > 0:
        await asyncio.sleep(delay)


# ── R10 · conditional fetch (asset caching) ──────────────────────────────────
#
# Re-scanning a target refetched every asset from scratch. Most assets do not
# change between engagements and most contain nothing, so that is wasted
# bandwidth on the client's servers and wasted CPU on ours.
#
# We send If-None-Match / If-Modified-Since and act on a 304 as follows:
#   • asset was clean last time  -> skip it entirely (unchanged + previously
#     clean means still clean), returning CACHED_CLEAN.
#   • asset had a finding        -> refetch unconditionally, so the finding is
#     reproduced rather than silently vanishing from the report. A finding that
#     disappears reads as "resolved", which would be a dangerous lie.
#
# No response body is ever cached: a client's JavaScript can hold live
# credentials and we do not keep copies of it. Only validators + a content hash.

ASSET_CACHE_ENABLED = os.environ.get("ASSET_CACHE", "true").lower() == "true"

# Sentinel distinguishing "unchanged, previously clean, skip" from a real body
# and from a failure (None).
CACHED_CLEAN = "\x00__SECRETNODE_CACHED_CLEAN__"

# Scan-scoped cache state. Module-level for the same reason _host_delays is:
# every fetch in a scan shares it without threading a parameter through
# spider_target and its six call sites.
_asset_cache_in: dict[str, dict[str, Any]] = {}
_asset_cache_out: dict[str, dict[str, Any]] = {}

# URLs the server confirmed unchanged and that were clean last time, so no body
# was re-downloaded. They are still *covered* by the scan — the tool checked
# them and knows their content has not changed — but they never enter the asset
# list, so counting only downloads makes a fully-cached re-scan report
# "0 assets", which reads to a client as "nothing was scanned".
_asset_cache_hits: set[str] = set()

# final URL -> the URL originally requested, for assets that redirected.
#
# The cache is keyed on the URL we *ask for*, because that is the stable key
# across scans: it is what discovery produces, and it is what the next scan will
# look up. But `fetch_url` now returns the URL that actually answered (see the
# redirect guard), so `mark_asset_dirty` is called with the final URL — and
# without this map it would find no entry and mark nothing.
#
# That silent miss is the dangerous direction. An asset that redirected and held
# a credential would stay recorded as `was_clean=True`, so the next scan's 304
# would skip it and the finding would vanish from the report. A finding that
# disappears reads as "resolved". This map is what keeps the two keyings in step.
_asset_redirect_alias: dict[str, str] = {}


def load_asset_cache(entries: dict[str, dict[str, Any]]) -> None:
    """Prime the conditional-GET cache for a scan."""
    _asset_cache_in.clear()
    _asset_cache_in.update(entries or {})
    _asset_cache_out.clear()
    _asset_cache_hits.clear()
    _asset_redirect_alias.clear()


def cached_clean_count() -> int:
    """How many assets this scan skipped as unchanged-and-previously-clean."""
    return len(_asset_cache_hits)


def drain_asset_cache() -> dict[str, dict[str, Any]]:
    """Validators observed during this scan, for persisting afterwards."""
    return dict(_asset_cache_out)


def extract_headers_without_validators(headers: dict[str, str] | None) -> dict[str, str] | None:
    """Strip conditional-request headers so a refetch actually returns a body."""
    if not headers:
        return None
    stripped = {k: v for k, v in headers.items()
                if k.lower() not in ("if-none-match", "if-modified-since")}
    return stripped or None


def _usable_body(body: str | None) -> bool:
    """A real, scannable body — not a failure and not a cache hit."""
    return bool(body) and body != CACHED_CLEAN


def mark_asset_dirty(url: str) -> None:
    """Record that `url` yielded a finding, so a future 304 refetches it
    instead of skipping — a finding must never silently vanish.

    `url` may be either the URL requested or the URL that answered after a
    redirect, because callers hold the latter. Resolve through the alias map so
    a redirected asset's entry is marked too.
    """
    key = url if url in _asset_cache_out else _asset_redirect_alias.get(url, url)
    if key in _asset_cache_out:
        _asset_cache_out[key]["was_clean"] = False


def _backoff_delay(attempt: int) -> float:
    """Exponential backoff with equal jitter, capped.

    Equal jitter (half fixed, half random) keeps a guaranteed minimum pause while
    still de-synchronising concurrent workers, which full jitter alone does not.
    """
    ceiling = min(RETRY_BACKOFF_BASE ** attempt, RETRY_MAX_BACKOFF)
    return (ceiling / 2) + random.uniform(0, ceiling / 2)


def _parse_retry_after(raw: str | None, fallback: float) -> float:
    """Parse a Retry-After header into seconds. Never raises.

    RFC 7231 allows either delta-seconds *or* an HTTP-date. Before v2.7.5 this was
    parsed with a bare float(), so a spec-compliant date raised ValueError, hit the
    generic handler, and made the scanner abandon the asset outright — a false
    negative caused by the server behaving correctly.
    """
    if not raw:
        return fallback
    raw = raw.strip()
    try:
        return max(0.0, float(raw))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(raw)
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())
    except Exception:  # noqa: BLE001 — a malformed header must never break a scan
        return fallback


def _browser_headers(user_agent: str) -> dict[str, str]:
    """A realistic modern-Chrome header set. Client-Hints + Sec-Fetch-* are what
    modern WAFs look for; sending them lets an authorized scan reach a
    WAF-protected target instead of eating an immediate 403."""
    is_chrome = "Chrome/" in user_agent
    headers = {
        "User-Agent": user_agent,
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "application/javascript,text/javascript,*/*;q=0.8"
        ),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Cache-Control": "max-age=0",
    }
    if is_chrome:
        headers.update({
            "sec-ch-ua": '"Chromium";v="126", "Google Chrome";v="126", "Not;A=Brand";v="24"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        })
    return headers


def build_client(user_agent: str | None = None) -> httpx.AsyncClient:
    ua = _UA_OVERRIDE or user_agent or _USER_AGENTS[0]
    # HTTP/2 makes the client behave like a real browser to CDNs; fall back to
    # HTTP/1.1 transparently if the optional `h2` package isn't installed.
    try:
        import h2  # noqa: F401
        http2 = True
    except Exception:  # pragma: no cover - env without h2
        http2 = False
    return httpx.AsyncClient(
        timeout=httpx.Timeout(FETCH_TIMEOUT, connect=10.0),
        # Redirects are followed by `_get_following_redirects`, one hop at a
        # time, with every hop validated. httpx's own follow_redirects=True
        # resolves and connects internally, which leaves no seam to check an
        # address at — so a 302 to 169.254.169.254 was simply followed, and the
        # instance-metadata response was scanned for credentials. See netguard.
        follow_redirects=False,
        http2=http2,
        limits=httpx.Limits(max_connections=40, max_keepalive_connections=20),
        headers=_browser_headers(ua),
        verify=True,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Resilient Fetch
# ─────────────────────────────────────────────────────────────────────────────

def _looks_scannable(content_type: str) -> bool:
    """True for text-ish content worth scanning. Binary assets (images, fonts,
    archives) are skipped early to save bandwidth/CPU on the Pi."""
    if not content_type:
        return True  # unknown → let it through; body-size cap still applies
    ct = content_type.split(";", 1)[0].strip().lower()
    if ct.startswith("text/"):
        return True
    return ct in {
        "application/javascript", "application/x-javascript", "text/javascript",
        "application/json", "application/manifest+json", "application/ld+json",
        "application/xml", "application/xhtml+xml", "image/svg+xml",
        "application/octet-stream", "",
    }


_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})


async def _get_following_redirects(
    client: httpx.AsyncClient,
    url: str,
    headers: dict[str, str] | None,
    broadcast: Broadcaster | None = None,
) -> tuple[httpx.Response, str]:
    """GET `url`, following redirects one validated hop at a time.

    Returns ``(response, final_url)``. Raises `netguard.BlockedTarget` if any hop
    is refused — the caller turns that into a logged, non-fatal skip for that
    asset, because one refused redirect must not abort a whole scan.

    Hops are walked here rather than by httpx because httpx resolves and
    connects internally: with ``follow_redirects=True`` there is no point at
    which the next hop's address can be inspected before the request goes out.
    Checking the chain afterwards is not equivalent — by then the request has
    already been made, which for an internal address is the entire harm.

    A 303, and a 301/302 answering anything other than GET/HEAD, become a GET by
    specification. Everything this scanner issues is already a GET, so the rule
    is noted rather than implemented: there is no method to downgrade.
    """
    current = url
    for hop in range(netguard.MAX_REDIRECTS + 1):
        response = await client.get(current, headers=headers)
        if response.status_code not in _REDIRECT_CODES:
            return response, current

        location = response.headers.get("location")
        if not location:
            # A redirect status with no Location is a broken server, not a
            # redirect. Hand back the response as-is and let the ordinary
            # status handling deal with it.
            return response, current

        # Resolve against the hop we are on, which is what a browser does.
        # Scope, though, is judged against the URL originally requested — see
        # check_redirect_hop for why chaining scope hop-to-hop is unsafe.
        nxt = urljoin(current, location.strip())
        netguard.check_redirect_hop(url, nxt, enforce_scope=SCOPE_SAME_DOMAIN)

        if hop >= netguard.MAX_REDIRECTS:
            raise netguard.BlockedTarget(
                f"Redirect chain exceeded {netguard.MAX_REDIRECTS} hops starting at {url} "
                "— treating as a loop."
            )
        if broadcast:
            await broadcast({
                "type": "log", "level": "INFO",
                "message": f"Redirect {response.status_code}: {current} → {nxt}",
            })
        current = nxt

    # Unreachable: the loop either returns a response or raises. Kept explicit
    # so a future edit to the bounds cannot fall out of the function with None.
    raise netguard.BlockedTarget(f"Redirect handling fell through for {url}")


async def fetch_url(
    client: httpx.AsyncClient,
    url: str,
    semaphore: asyncio.Semaphore,
    broadcast: Broadcaster | None = None,
    cache: dict[str, dict[str, Any]] | None = None,
    cache_out: dict[str, dict[str, Any]] | None = None,
    allow_cache_skip: bool = True,
) -> tuple[str, str | None]:
    """
    Fetch a URL with retry + exponential backoff.

    Resilience for authorized testing (v2.4.0): on a WAF/CDN challenge
    (401/403/406/429/503) we retry with a different browser fingerprint before
    giving up, and emit a diagnostic that names the likely cause instead of a
    bare "failed". Respects 429 Retry-After.

    Returns ``(final_url, body)`` or ``(final_url, None)``. The first element is
    the URL that **answered**, which after a redirect is not the URL requested.
    Returning the requested URL, as this did before, mis-stated provenance in
    two ways that both reach the client's report: a finding served from the
    redirect's destination was attributed to the original host, and relative
    asset URLs in a redirected page were resolved against the pre-redirect base,
    producing 404s and a quietly under-covered scan.

    `allow_cache_skip=False` still sends the conditional GET and still records
    the validators, but never returns CACHED_CLEAN — the caller gets a real
    body. Crawled HTML pages must use it: a page is a link graph, not just
    something to grep. Skipping an unchanged page's body means never parsing
    its <script> tags, so every JS bundle it references drops out of the scan.
    That turns a re-scan of an unchanged site into a false all-clear, which is
    a far worse failure than re-downloading a few kilobytes of HTML.
    """
    host = urlparse(url).netloc
    async with semaphore:
        waf_block_status: int | None = None
        revalidate = True
        for attempt in range(1, RETRY_ATTEMPTS + 1):
            try:
                # Pace ourselves if this host has recently rate-limited us.
                await _throttle_wait(host)
                if broadcast:
                    await broadcast({
                        "type": "log",
                        "level": "INFO",
                        # "Fetching [1/3]" was an attempt counter, but printed
                        # once per asset directly above "3 file(s) to scan" it
                        # read as "file 1 of 3" — three identical [1/3] lines
                        # look like a counter that is stuck. Say what it is.
                        "message": (
                            f"Fetching: {url}" if attempt == 1
                            else f"Retry {attempt}/{RETRY_ATTEMPTS}: {url}"
                        ),
                    })
                # Rotate the browser fingerprint on retries after a WAF block —
                # some edges let a different UA through.
                extra_headers = None
                if attempt > 1 and waf_block_status and not _UA_OVERRIDE:
                    extra_headers = _browser_headers(_USER_AGENTS[(attempt - 1) % len(_USER_AGENTS)])

                # Conditional GET: only on the first attempt, and only while the
                # cache is still trusted. `revalidate` flips off once we have
                # decided we must see the body regardless.
                _cin = cache if cache is not None else _asset_cache_in
                _cout = cache_out if cache_out is not None else _asset_cache_out
                entry = _cin.get(url) if (_cin and ASSET_CACHE_ENABLED) else None
                if entry and revalidate:
                    cond = dict(extra_headers or {})
                    if entry.get("etag"):
                        cond["If-None-Match"] = entry["etag"]
                    if entry.get("last_modified"):
                        cond["If-Modified-Since"] = entry["last_modified"]
                    if len(cond) > len(extra_headers or {}):
                        extra_headers = cond

                response, final_url = await _get_following_redirects(
                    client, url, extra_headers, broadcast
                )
                if final_url != url:
                    # Keep the cache keyed on the requested URL (the stable key
                    # discovery will produce again next scan) while callers work
                    # with the URL that answered.
                    _asset_redirect_alias[final_url] = url

                if response.status_code == 304:
                    _throttle_reward(host)
                    if entry and entry.get("was_clean", True) and allow_cache_skip:
                        # Unchanged and previously clean -> nothing to re-scan.
                        _cout[url] = dict(entry)
                        _asset_cache_hits.add(url)
                        return final_url, CACHED_CLEAN
                    # Either the asset yielded a finding last time, or the server
                    # sent 304 unprompted. Both need the body: a finding that
                    # vanished from a report reads as "resolved", which would be
                    # a dangerous lie. Re-issue immediately WITHOUT the validators
                    # rather than looping — consuming a retry here means that with
                    # RETRY_ATTEMPTS=1 the refetch never happens and the asset is
                    # silently lost.
                    revalidate = False
                    response, final_url = await _get_following_redirects(
                        client, url,
                        extract_headers_without_validators(extra_headers),
                        broadcast,
                    )
                    if final_url != url:
                        _asset_redirect_alias[final_url] = url
                    if response.status_code == 304:
                        # Server insists nothing changed even unconditionally —
                        # treat as unreachable rather than spin.
                        return final_url, None

                if response.status_code == 429:
                    retry_after = _parse_retry_after(
                        response.headers.get("Retry-After"), 10.0 * attempt
                    )
                    paced = _throttle_penalise(host)
                    if broadcast:
                        await broadcast({
                            "type": "log",
                            "level": "WARN",
                            "message": (
                                f"429 rate-limited on {url} — backing off "
                                f"{retry_after:.0f}s; pacing {host} at {paced:.1f}s/request."
                            ),
                        })
                    await asyncio.sleep(min(retry_after, RETRY_MAX_BACKOFF))
                    continue

                if response.status_code in (404, 410):
                    return final_url, None

                if response.status_code in _WAF_BLOCK_CODES:
                    waf_block_status = response.status_code
                    if response.status_code == 503:
                        # Overloaded, not hostile — slow down rather than hammer.
                        _throttle_penalise(host)
                    server = response.headers.get("server", "")
                    hint = f" (server: {server})" if server else ""
                    if attempt < RETRY_ATTEMPTS:
                        if broadcast:
                            await broadcast({
                                "type": "log", "level": "WARN",
                                "message": (
                                    f"HTTP {response.status_code} on {url}{hint} — likely a "
                                    f"WAF/CDN challenge; retrying with a different browser fingerprint."
                                ),
                            })
                        await asyncio.sleep(_backoff_delay(attempt))
                        continue
                    if broadcast:
                        await broadcast({
                            "type": "log", "level": "ERROR",
                            "message": (
                                f"HTTP {response.status_code} for {url}{hint} — blocked by a "
                                f"WAF/CDN after {RETRY_ATTEMPTS} attempts. The resource exists but "
                                f"denies automated access. For a target you own, allowlist the "
                                f"scanner's source IP or set SECRETNODE_USER_AGENT to an approved value."
                            ),
                        })
                    return final_url, None

                response.raise_for_status()
                # Clean response — let this host's pacing relax back toward zero.
                _throttle_reward(host)

                # A malformed or duplicated Content-Length ("512, 512", as some
                # proxies emit) raised ValueError here, which the catch-all
                # handler below turned into a silent asset drop with no retry —
                # an unread asset is an unscanned asset, and the scan still
                # reported CLEAN. The body-size cap below already bounds what we
                # read, so an unparseable header is a reason to fall through to
                # it, not to abandon the asset.
                try:
                    cl = int(response.headers.get("content-length", 0) or 0)
                except (TypeError, ValueError):
                    cl = 0
                if cl > MAX_ASSET_BYTES:
                    if broadcast:
                        await broadcast({
                            "type": "log",
                            "level": "WARN",
                            "message": f"Skipping oversized asset ({cl/1024/1024:.1f} MB): {url}",
                        })
                    return final_url, None

                if not _looks_scannable(response.headers.get("content-type", "")):
                    return final_url, None

                # Guard against a chunked/undeclared body that exceeds the cap.
                text = response.text
                if len(text) > MAX_ASSET_BYTES:
                    text = text[:MAX_ASSET_BYTES]
                if ASSET_CACHE_ENABLED:
                    et = response.headers.get("etag")
                    lm = response.headers.get("last-modified")
                    if et or lm:
                        _cout[url] = {
                            "etag": et,
                            "last_modified": lm,
                            "content_hash": hashlib.sha256(
                                text.encode("utf-8", "replace")
                            ).hexdigest()[:32],
                            # Findings are unknown at fetch time; the scan loop
                            # corrects this once the asset has been scanned.
                            "was_clean": True,
                        }
                return final_url, text

            except httpx.TimeoutException:
                msg = f"Timeout (attempt {attempt}/{RETRY_ATTEMPTS}): {url}"
                logger.warning(msg)
                if broadcast:
                    await broadcast({"type": "log", "level": "WARN", "message": msg})

            except httpx.ConnectError as exc:
                msg = f"Connect error (attempt {attempt}/{RETRY_ATTEMPTS}): {url} — {exc}"
                logger.warning(msg)
                if broadcast:
                    await broadcast({"type": "log", "level": "WARN", "message": msg})

            except netguard.BlockedTarget as exc:
                # A refused hop is a skipped asset, never an aborted scan: one
                # bad redirect on one bundle must not cost the whole engagement.
                # It is logged at ERROR rather than swallowed, because this is
                # the branch where coverage is deliberately given up, and a
                # coverage loss nobody is told about is how a scan that read
                # almost nothing still reports CLEAN.
                msg = f"Refused to follow redirect from {url} — {exc}"
                logger.error(msg)
                if broadcast:
                    await broadcast({"type": "log", "level": "ERROR", "message": msg})
                return url, None

            except httpx.HTTPStatusError as exc:
                msg = f"HTTP {exc.response.status_code} for {url}"
                logger.warning(msg)
                if broadcast:
                    await broadcast({"type": "log", "level": "WARN", "message": msg})
                return url, None

            except Exception as exc:  # noqa: BLE001
                msg = f"Unexpected fetch error: {url} — {exc}"
                logger.error(msg)
                if broadcast:
                    await broadcast({"type": "log", "level": "ERROR", "message": msg})
                return url, None

            if attempt < RETRY_ATTEMPTS:
                await asyncio.sleep(_backoff_delay(attempt))

        return url, None


# ─────────────────────────────────────────────────────────────────────────────
# HTML Spidering & JS Discovery
# ─────────────────────────────────────────────────────────────────────────────

_SCRIPT_SRC_RE  = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
# <link href=…> that is script-ish: modulepreload / preload as=script, or a .js file.
_LINK_JS_RE = re.compile(
    r'<link\b[^>]*\bhref=["\']([^"\']+)["\'][^>]*>',
    re.IGNORECASE,
)
# A <link> is script-ish only if it actually points at a script:
#
#   rel=modulepreload            — by definition a JavaScript module
#   rel=preload ... as=script    — the `as` is what names the type
#   href=….js                    — an explicit script file
#
# `rel=preload` on its own is NOT enough, and treating it as enough was a real
# bug: `<link rel="preload" href="inter-var.woff2" as="font">` matched, so every
# preloaded font was fetched as a candidate JS asset. Font preloading is close
# to universal on modern sites, which made this a per-host tax of several
# hundred KB of binary downloads that can never contain a credential — and it
# inflated the reported "Discovered N JS asset(s)" with files that are not JS.
# Found by scanning cindrasec.com, which preloads three woff2 files.
_LINK_IS_SCRIPT_RE = re.compile(
    r'\brel=["\']?modulepreload\b|\bas=["\']?script\b|href=["\'][^"\']+\.js["\']',
    re.IGNORECASE,
)
# //# sourceMappingURL=app.js.map  (or the legacy //@ form, or a /*# … */ block)
_SOURCE_MAP_RE = re.compile(
    r'(?://[#@]|/\*[#@])\s*sourceMappingURL\s*=\s*([^\s"\'*]+)',
    re.IGNORECASE,
)

SCOPE_SAME_DOMAIN = os.environ.get("SCOPE_SAME_DOMAIN", "true").lower() == "true"
# Whether to follow declared source maps (.js.map) and scan their un-minified
# original source. Source maps routinely leak API keys, endpoints and comments
# that are stripped from the shipped bundle — a well-established ASM technique.
FOLLOW_SOURCE_MAPS = os.environ.get("FOLLOW_SOURCE_MAPS", "true").lower() == "true"
MAX_SOURCE_MAPS = _env_int("MAX_SOURCE_MAPS", 40)
# R5 surface expansion: a source map embeds the ORIGINAL, un-minified source in
# its `sourcesContent` array (JSON-escaped). The raw .map is scanned as text, but
# secrets in the original source are frequently escaped/split there and missed —
# so we also decode each embedded source and scan it as real code.
SCAN_SOURCEMAP_CONTENT = os.environ.get("SCAN_SOURCEMAP_CONTENT", "true").lower() == "true"
MAX_SOURCEMAP_SOURCES  = _env_int("MAX_SOURCEMAP_SOURCES", 200)
# R8: passive HTTP security-posture check (missing/weak security headers,
# version disclosure, insecure cookies) on the target root. Pure analysis of the
# response the target already serves — no exploitation, no third-party calls.
SCAN_HTTP_POSTURE = os.environ.get("SCAN_HTTP_POSTURE", "true").lower() == "true"
# R7: composite/proximity rules. A keyword-anchored detector (AWS Secret Access
# Key, Twilio Auth Token) needs the provider's name beside the value, and
# minification deletes it — so the shipped bundle keeps the credential and loses
# the word the regex anchors on. Composite rules use a nearby high-precision
# anchor (AKIA…, AC+32hex) to supply the identity instead. See composite.py.
SCAN_COMPOSITE = os.environ.get("SCAN_COMPOSITE", "true").lower() == "true"


def _same_scope(base_host: str, candidate_host: str) -> bool:
    """True if candidate_host is the same registrable domain as base_host
    (exact match or a subdomain of it). Keeps scans inside the authorized
    target instead of silently fetching third-party CDNs/analytics domains.

    Single source of truth is surface.same_scope — this gate decides whether a
    request goes out, so the domain report and the fetch decision must never be
    able to disagree about what "in scope" means.
    """
    return surface.same_scope(base_host, candidate_host)


def _accept_asset(raw: str, base_url: str, base_host: str, seen: set[str],
                  rejected: list[str] | None = None) -> str | None:
    """Absolutise + scope-check a discovered asset URL. Returns the absolute URL
    to keep, or None to skip (already seen, out of scope, or non-http).

    `rejected` collects URLs turned away specifically by the *scope* check —
    not the already-seen or non-HTTP skips, which are uninteresting. The caller
    uses it to notice the one failure mode that is otherwise silent: a page full
    of scripts, none of them kept, and a clean result that means nothing.
    """
    raw = raw.strip()
    if not raw or raw.startswith(("data:", "blob:")):
        return None
    absolute = urljoin(base_url, raw)
    p = urlparse(absolute)
    if p.scheme not in ("http", "https") or absolute in seen:
        return None
    if SCOPE_SAME_DOMAIN and not _same_scope(base_host, p.hostname or ""):
        if rejected is not None:
            rejected.append(absolute)
        return None
    seen.add(absolute)
    return absolute


def extract_js_urls(html: str, base_url: str,
                    rejected: list[str] | None = None) -> list[str]:
    """Absolutise all JS asset URLs discovered in the HTML: <script src>,
    <script type=module src>, and script-ish <link> tags (modulepreload,
    preload as=script, or an explicit .js href). By default only keeps assets
    on the same domain as base_url (SCOPE_SAME_DOMAIN=true) so the scanner
    doesn't fan out to unrelated third-party hosts.

    Pass `rejected` to also collect what the scope check turned away."""
    seen: set[str] = set()
    result: list[str] = []
    base_host = urlparse(base_url).hostname or ""
    for m in _SCRIPT_SRC_RE.finditer(html):
        absolute = _accept_asset(m.group(1), base_url, base_host, seen, rejected)
        if absolute:
            result.append(absolute)
    for m in _LINK_JS_RE.finditer(html):
        if not _LINK_IS_SCRIPT_RE.search(m.group(0)):
            continue
        absolute = _accept_asset(m.group(1), base_url, base_host, seen, rejected)
        if absolute:
            result.append(absolute)
    return result


def extract_source_map_urls(js_body: str, js_url: str) -> list[str]:
    """Find declared source-map URLs (//# sourceMappingURL=…) in a JS asset and
    absolutise them, keeping only same-scope, non-inline maps. Source maps
    routinely contain the un-minified original source — comments, endpoints and
    hard-coded secrets stripped from the shipped bundle."""
    if not FOLLOW_SOURCE_MAPS:
        return []
    seen: set[str] = set()
    result: list[str] = []
    base_host = urlparse(js_url).hostname or ""
    for m in _SOURCE_MAP_RE.finditer(js_body):
        raw = m.group(1).strip()
        if raw.startswith("data:"):   # inline base64 map — already inside js_body
            continue
        absolute = _accept_asset(raw, js_url, base_host, seen)
        if absolute:
            result.append(absolute)
    return result


def looks_like_sourcemap(url: str, body: str) -> bool:
    """Heuristic: is this asset a JS source map? By extension, or by the tell-tale
    `sourcesContent` / (`version` + `mappings`) keys near the top of the body."""
    if url.split("?", 1)[0].split("#", 1)[0].endswith(".map"):
        return True
    head = body[:4000]
    return '"sourcesContent"' in head or ('"mappings"' in head and '"version"' in head)


# ── Inline SSR state blobs (v2.7.6) ──────────────────────────────────────────
#
# Server-rendered apps embed their bootstrap state in the HTML: Next.js writes
# <script id="__NEXT_DATA__" type="application/json">, Nuxt writes
# window.__NUXT__, Redux-style apps write window.__INITIAL_STATE__. That blob is
# built server-side and regularly carries config a developer never meant to ship.
#
# The raw HTML is already scanned as text, so a plainly-embedded secret is caught
# today. What is missed is a value whose JSON *escaping* breaks the secret's
# shape — a \uXXXX-escaped character mid-token, or the < /   escaping
# that XSS-safe serializers (Next.js's htmlEscapeJsonString) apply. The regex
# sees "sk-ant-A1b2-C3d4" and no longer recognises the credential.
#
# The fix is the same one already used for source maps: decode the JSON and scan
# the *decoded* string values as real text. Purely local — no new requests, so
# the scan stays passive.

SCAN_INLINE_JSON = os.environ.get("SCAN_INLINE_JSON", "true").lower() == "true"
MAX_INLINE_JSON_BYTES = _env_int("MAX_INLINE_JSON_BYTES", 2_000_000)

# Inline <script> bodies. Bounded and non-greedy: no nested quantifier, so a
# hostile page cannot drive catastrophic backtracking.
# Lazy match to the literal </script> terminator. A [^<] class would truncate at
# the first raw "<", which JSON blobs contain constantly (prose like "a < b",
# embedded HTML fragments) — that silently lost the rest of the blob. Lazy
# matching to a fixed terminator is linear-time, so this stays ReDoS-free.
_INLINE_SCRIPT_RE = re.compile(
    r"<script\b[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL
)
# A JSON object assigned to a known SSR state global, e.g. window.__NUXT__={…}
_STATE_ASSIGN_RE = re.compile(
    r"(?:window\.)?(?:__NEXT_DATA__|__NUXT__|__INITIAL_STATE__|__APOLLO_STATE__"
    r"|__PRELOADED_STATE__|__remixContext)\s*=\s*(\{[^\0]{0,2000000})",
)


def _json_string_values(node: Any, out: list[str], budget: list[int]) -> None:
    """Walk a decoded JSON document, collecting string values (and keys, which
    sometimes hold the credential). Bounded by a shared byte budget."""
    if budget[0] <= 0:
        return
    if isinstance(node, str):
        budget[0] -= len(node)
        out.append(node)
    elif isinstance(node, dict):
        for k, v in node.items():
            if budget[0] <= 0:
                return
            if isinstance(k, str):
                out.append(k)
            _json_string_values(v, out, budget)
    elif isinstance(node, list):
        for v in node:
            if budget[0] <= 0:
                return
            _json_string_values(v, out, budget)


def extract_inline_json_strings(html: str) -> str:
    """Decode inline SSR/JSON script blobs and return their string values as
    scannable text, one per line.

    Returns "" when nothing parses. Fully defensive: any malformed blob is
    skipped rather than failing the scan.
    """
    if not SCAN_INLINE_JSON or not html:
        return ""
    candidates: list[str] = []
    for m in _INLINE_SCRIPT_RE.finditer(html):
        body = m.group(1).strip()
        if not body:
            continue
        if body.startswith(("{", "[")):
            candidates.append(body)
            continue
        assign = _STATE_ASSIGN_RE.search(body)
        if assign:
            candidates.append(assign.group(1))

    values: list[str] = []
    budget = [MAX_INLINE_JSON_BYTES]
    for blob in candidates:
        if budget[0] <= 0:
            break
        # A state assignment often ends in ";" or trailing JS — walk back to the
        # last closing brace so json.loads gets a complete document.
        text = blob
        if not text.endswith(("}", "]")):
            cut = max(text.rfind("}"), text.rfind("]"))
            if cut == -1:
                continue
            text = text[: cut + 1]
        try:
            doc = json.loads(text)
        except Exception:  # noqa: BLE001 — a non-JSON blob is simply not our business
            continue
        _json_string_values(doc, values, budget)

    return "\n".join(values)


def extract_sourcemap_sources(map_body: str, map_url: str) -> list[tuple[str, str]]:
    """R5 surface expansion: decode a source map's `sourcesContent` (the original,
    un-minified source, JSON-escaped inside the .map) into scannable code, paired
    with its `sources` name. Secrets stripped from the shipped bundle — or escaped
    within the raw .map JSON so the regex pass misses them — surface here.
    Bounded (MAX_SOURCEMAP_SOURCES) and fully defensive: any parse error → []."""
    try:
        doc = json.loads(map_body)
    except Exception:
        return []
    if not isinstance(doc, dict):
        return []
    contents = doc.get("sourcesContent")
    if not isinstance(contents, list):
        return []
    names = doc.get("sources") if isinstance(doc.get("sources"), list) else []
    out: list[tuple[str, str]] = []
    for i, content in enumerate(contents):
        if len(out) >= MAX_SOURCEMAP_SOURCES:
            break
        if not isinstance(content, str) or not content:
            continue
        name = names[i] if i < len(names) and isinstance(names[i], str) else f"source[{i}]"
        out.append((f"{map_url} → {name}", content))
    return out


_ANCHOR_HREF_RE = re.compile(r'<a[^>]+href=["\']([^"\']+)["\']', re.IGNORECASE)
_NON_PAGE_EXT = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".css",
    ".pdf", ".zip", ".tar", ".gz", ".mp4", ".mp3", ".woff", ".woff2",
    ".ttf", ".eot", ".xml", ".json", ".rss",
)


def extract_page_links(html: str, base_url: str) -> list[str]:
    """Same-domain, same-scope HTML page links for shallow crawling.
    Skips assets, mailto/tel/javascript links, and fragments-only hrefs."""
    seen: set[str] = set()
    result: list[str] = []
    base_host = urlparse(base_url).hostname or ""
    for m in _ANCHOR_HREF_RE.finditer(html):
        raw = m.group(1).strip()
        if not raw or raw.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
            continue
        absolute = urljoin(base_url, raw).split("#")[0]
        p = urlparse(absolute)
        if p.scheme not in ("http", "https") or absolute in seen:
            continue
        if absolute.lower().endswith(_NON_PAGE_EXT):
            continue
        if SCOPE_SAME_DOMAIN and not _same_scope(base_host, p.hostname or ""):
            continue
        seen.add(absolute)
        result.append(absolute)
    return result


RobotsGroup = tuple[list[str], list[tuple[str, str]], float | None]


def parse_robots_groups(body: str) -> list[RobotsGroup]:
    """Parse robots.txt into RFC 9309 groups: ([agents], [(field, path)], delay).

    Consecutive User-agent lines share one group; a User-agent line that follows
    a rule opens a new group. Comments and unparseable lines are discarded.
    """
    groups: list[RobotsGroup] = []
    agents: list[str] = []
    rules: list[tuple[str, str]] = []
    delay: float | None = None

    def flush() -> None:
        nonlocal agents, rules, delay
        if agents:
            groups.append((agents, rules, delay))
        agents, rules, delay = [], [], None

    for raw in body.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        field_name, _, value = line.partition(":")
        field_name = field_name.strip().lower()
        value = value.strip()
        if field_name == "user-agent":
            if rules or delay is not None:      # rules ended the previous group
                flush()
            if value:
                agents.append(value.lower())
        elif field_name in ("allow", "disallow"):
            if agents:
                rules.append((field_name, value))
        elif field_name == "crawl-delay" and agents:
            try:
                delay = float(value)
            except ValueError:
                pass
    flush()
    return groups


def _group_blocks_root(rules: list[tuple[str, str]]) -> bool:
    """Does this group disallow the root path '/'?

    Only a rule whose path is exactly "/" can match the root — "/src/" cannot,
    which is the whole point of parsing rather than grepping. Google resolves
    conflicts by longest match with ties going to Allow, so a group carrying
    both "Disallow: /" and "Allow: /" (equal length) permits the root.
    """
    paths = {(f, v.strip()) for f, v in rules}
    if ("allow", "/") in paths:
        return False
    return ("disallow", "/") in paths


async def check_robots_txt(
    client: httpx.AsyncClient,
    target_url: str,
    broadcast: Broadcaster | None = None,
) -> bool:
    """
    Informational robots.txt check (does NOT block the scan — this is an
    authorized security assessment tool, not a generic web crawler, and
    robots.txt has no legal bearing on authorized pentesting). Its purpose
    here is purely professional courtesy/visibility: log if the target
    publishes a crawl-delay or disallows the root path, so the operator
    is aware and can throttle manually if the client's ops team would
    care about being polite to their own robots.txt during a live audit.

    The check is group-aware because the previous regex (`^disallow:\\s*/\\s*$`
    anywhere in the file) was not. Any single blocked user-agent — one
    Cloudflare-managed "User-agent: GPTBot / Disallow: /" block is enough —
    made the scanner announce that the target "disallows all crawling" while
    every general-purpose crawler was in fact free to fetch the whole site.
    A courtesy notice that states something false is worse than no notice.

    SecretNode publishes no robots product token (it rotates browser
    fingerprints), so the wildcard group is the one that governs it.
    """
    parsed = urlparse(target_url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    try:
        resp = await client.get(robots_url, timeout=10.0)
        if resp.status_code != 200:
            return True
        body = resp.text[:20000]
        groups = parse_robots_groups(body)

        wildcard = next(((r, d) for a, r, d in groups if "*" in a), None)
        wildcard_blocked = bool(wildcard and _group_blocks_root(wildcard[0]))
        named_blocked = sorted({
            agent
            for agents, rules, _delay in groups
            for agent in agents
            if agent != "*" and _group_blocks_root(rules)
        })

        if not broadcast:
            return True

        if wildcard_blocked:
            await broadcast({
                "type": "log", "level": "WARN",
                "message": (
                    "Target's robots.txt disallows all crawling (User-agent: * / "
                    "Disallow: /). Proceeding — this is an authorized security "
                    "scan, not a generic crawler — but flagging for awareness."
                ),
            })
        elif named_blocked:
            shown = ", ".join(named_blocked[:6])
            more = f" and {len(named_blocked) - 6} more" if len(named_blocked) > 6 else ""
            await broadcast({
                "type": "log", "level": "INFO",
                "message": (
                    f"Target's robots.txt blocks {len(named_blocked)} named "
                    f"user-agent(s) ({shown}{more}) but leaves the wildcard group "
                    f"free to crawl — general crawling is permitted."
                ),
            })

        delay = wildcard[1] if wildcard else None
        if delay:
            await broadcast({
                "type": "log", "level": "INFO",
                "message": (
                    f"Target's robots.txt requests a {delay:g}s crawl-delay. Not "
                    f"enforced automatically — throttle manually if the client's "
                    f"ops team expects it."
                ),
            })
        return True
    except Exception:
        return True  # robots.txt missing/unreachable is not an error condition


class RootUnreachable(RuntimeError):
    """The target's root document could not be fetched, so there was nothing to
    scan.

    A distinct type because the caller must be able to tell this apart from a
    genuine crash: it is an expected outcome (a WAF block, an out-of-scope
    redirect, a dead host) that has to reach the report as a *failure* rather
    than as an empty-but-successful scan. Silence here is what let a deep scan
    call a host `scanned` when its root was never read.
    """


class _AssetBudget:
    """Tracks the bytes a scan is holding and says when to stop collecting.

    Deliberately advisory rather than a hard failure: a scan that stops reading
    new assets still reports everything it read, whereas one killed by the OOM
    killer reports nothing at all. The cap engaging is broadcast at WARN and
    recorded on the result, because silently reading less than the operator
    asked for is the failure mode this scanner treats as unacceptable — a
    clean verdict over assets nobody fetched means nothing.
    """

    __slots__ = ("used", "limit", "skipped")

    def __init__(self, limit: int = 0) -> None:
        self.limit = limit or MAX_TOTAL_ASSET_BYTES
        self.used = 0
        self.skipped = 0

    def exhausted(self) -> bool:
        return self.used >= self.limit

    def take(self, body: str | None) -> bool:
        """Charge `body` against the budget. False means do not keep it."""
        if not _usable_body(body):
            return False
        if self.exhausted():
            self.skipped += 1
            return False
        self.used += len(body)
        return True


async def spider_target(
    client: httpx.AsyncClient,
    target_url: str,
    semaphore: asyncio.Semaphore,
    broadcast: Broadcaster | None = None,
    max_pages: int = 1,
    budget: "_AssetBudget | None" = None,
) -> list[tuple[str, str]]:
    """
    Fetch the root HTML (and, if max_pages > 1, shallow-crawl same-domain
    pages linked from it), discover all JS bundles across every fetched
    page, fetch them concurrently. Returns list of (source_url, body_text).
    """
    if broadcast:
        await broadcast({
            "type": "log",
            "level": "INFO",
            "message": f"Starting spider for {target_url} (max_pages={max_pages})",
        })
        await broadcast({"type": "status", "stage": "spidering", "target": target_url})

    await check_robots_txt(client, target_url, broadcast)

    # allow_cache_skip=False: we need the root's body to discover assets, even
    # when the server says it has not changed.
    root_url, html_body = await fetch_url(client, target_url, semaphore, broadcast,
                                          allow_cache_skip=False)
    if html_body is None:
        if broadcast:
            await broadcast({
                "type": "log",
                "level": "ERROR",
                "message": (
                    f"Could not fetch the target root ({target_url}). See the reason above — "
                    f"commonly a WAF/CDN block (HTTP 403/503), an unresolved host, or a timeout. "
                    f"The scan cannot proceed without the root document."
                ),
            })
        # Raise rather than return []. Returning an empty asset list made an
        # unreachable target indistinguishable from a reachable one that simply
        # had nothing in it: the scan completed, reported 0 assets and 0
        # findings, and every deliverable then said "clean". A deep scan of
        # nmap.org showed the cost — issues.nmap.org redirected out of scope,
        # its root was never fetched, and the per-host table still read
        # `scanned` with no note while the domain verdict said CLEAN across
        # 5 of 5 hosts. The coverage verdict cannot hedge to PARTIAL either,
        # because that counts hosts carrying an error and this one carried none.
        raise RootUnreachable(
            f"could not fetch the target root ({target_url}) — commonly a WAF/CDN "
            f"block (HTTP 403/503), an out-of-scope redirect, an unresolved host, "
            f"or a timeout"
        )

    budget = budget or _AssetBudget()
    assets: list[tuple[str, str]] = (
        [(root_url, html_body)] if budget.take(html_body) else []
    )
    html_pages: list[tuple[str, str]] = [(root_url, html_body)]
    visited_pages: set[str] = {root_url}
    scope_rejected: list[str] = []
    # Relative URLs in the root document resolve against the URL that ANSWERED,
    # not the one that was asked for. `https://example.com` answering as
    # `https://example.com/en/` means `src="app.js"` is `/en/app.js`; resolving
    # it against the pre-redirect base produced `/app.js`, a 404, and a bundle
    # that silently never entered the scan. Every redirecting target — an apex
    # sending traffic to `www`, a locale prefix, a trailing-slash normalisation —
    # was losing coverage this way, and nothing in the output said so.
    all_js_urls: set[str] = set(extract_js_urls(html_body, root_url, scope_rejected))

    # ── Shallow same-domain crawl for additional HTML pages ─────────────────
    if max_pages > 1:
        # Same reason as the asset base above: link hrefs resolve against the
        # URL that answered.
        queue = [u for u in extract_page_links(html_body, root_url) if u not in visited_pages]
        while queue and len(visited_pages) < max_pages:
            batch = queue[: max_pages - len(visited_pages)]
            queue = queue[len(batch):]
            fetch_tasks = [fetch_url(client, u, semaphore, broadcast,
                                     allow_cache_skip=False) for u in batch]
            fetched_pages = await asyncio.gather(*fetch_tasks, return_exceptions=False)
            for page_url, page_body in fetched_pages:
                visited_pages.add(page_url)
                if not _usable_body(page_body):
                    continue
                # A page is a link graph as well as something to grep, so it is
                # still parsed for assets even when the budget is spent — only
                # its body is dropped from the scan set.
                html_pages.append((page_url, page_body))
                if budget.take(page_body):
                    assets.append((page_url, page_body))
                for js in extract_js_urls(page_body, page_url, scope_rejected):
                    all_js_urls.add(js)
        if broadcast and len(visited_pages) > 1:
            await broadcast({
                "type": "log", "level": "INFO",
                "message": f"Crawled {len(visited_pages)} same-domain page(s): {', '.join(sorted(visited_pages))[:300]}",
            })

    js_urls = sorted(all_js_urls)
    if len(js_urls) > MAX_JS_ASSETS:
        # Fail loud: a truncated asset list is a truncated scan, and a clean
        # verdict over assets nobody fetched is the failure this tool exists to
        # avoid reporting.
        if broadcast:
            await broadcast({
                "type": "log", "level": "WARN",
                "message": (
                    f"{len(js_urls)} JS assets discovered — scanning the first "
                    f"{MAX_JS_ASSETS} (MAX_JS_ASSETS). Coverage is partial; raise "
                    f"the cap to scan the rest."
                ),
            })
        js_urls = js_urls[:MAX_JS_ASSETS]

    # Fail loud, never silent. The scope check rejecting a script served by the
    # target's OWN host cannot be correct under any scope policy — it means the
    # rule is broken, and the consequence is the worst outcome this tool has:
    # nothing to read, therefore nothing found, therefore a CLEAN verdict that
    # means nothing. The v2.12.4 `lstrip("www.")` bug did exactly this to every
    # target starting with "w" and went unnoticed because no surface said so.
    #
    # Deliberately narrower than "all scripts were rejected": a page that loads
    # only third-party analytics is ordinary and must not raise an alarm. Only
    # self-rejection is unambiguous.
    if broadcast and scope_rejected:
        own = urlparse(target_url).hostname or ""
        self_rejected = [u for u in scope_rejected
                         if (urlparse(u).hostname or "").lower() == own.lower()]
        if self_rejected:
            await broadcast({
                "type": "log", "level": "ERROR",
                "message": (
                    f"Scope check rejected {len(self_rejected)} script(s) served by "
                    f"the target's own host ({own}). That cannot be right: the scope "
                    f"rule is broken, this scan is not reading the target's "
                    f"JavaScript, and a clean result from it proves nothing. "
                    f"Example: {self_rejected[0]}"
                ),
            })

    if broadcast:
        await broadcast({
            "type": "log",
            "level": "INFO",
            "message": f"Discovered {len(js_urls)} JS asset(s) across {len(html_pages)} page(s)",
        })

    js_bodies: list[tuple[str, str]] = []
    if js_urls:
        tasks = [fetch_url(client, u, semaphore, broadcast) for u in js_urls]
        fetched = await asyncio.gather(*tasks, return_exceptions=False)
        for js_url, js_body in fetched:
            if budget.take(js_body):
                assets.append((js_url, js_body))
                js_bodies.append((js_url, js_body))

    # ── Follow declared source maps (.js.map) for un-minified original source ──
    map_urls: list[str] = []
    if FOLLOW_SOURCE_MAPS and js_bodies:
        seen_maps: set[str] = set()
        for js_url, js_body in js_bodies:
            for mu in extract_source_map_urls(js_body, js_url):
                if mu not in seen_maps:
                    seen_maps.add(mu)
                    map_urls.append(mu)
        map_urls = map_urls[:MAX_SOURCE_MAPS]
        if map_urls:
            if broadcast:
                await broadcast({
                    "type": "log", "level": "INFO",
                    "message": f"Following {len(map_urls)} source map(s) for original source",
                })
            map_tasks = [fetch_url(client, u, semaphore, broadcast) for u in map_urls]
            fetched_maps = await asyncio.gather(*map_tasks, return_exceptions=False)
            for map_url, map_body in fetched_maps:
                if budget.take(map_body):
                    assets.append((map_url, map_body))

    # Broadcast every non-HTML asset we actually collected (JS + source maps),
    # so the dashboard's "Discovered Assets" panel reflects real coverage even
    # when a target ships a single bundle.
    if broadcast:
        collected = [u for (u, _b) in assets if u not in visited_pages]
        await broadcast({
            "type": "assets_found",
            "count": len(collected),
            "urls": collected[:50],  # cap for WS payload size
        })
        await broadcast({
            "type": "log",
            "level": "INFO",
            "message": f"Spidering complete — {len(assets)} assets collected",
        })

    return assets


# ─────────────────────────────────────────────────────────────────────────────
# Regex Secret Extraction
# ─────────────────────────────────────────────────────────────────────────────

# ── Accuracy filters (v2.3.0): example/placeholder allowlist + base64 decoding ──
_KNOWN_EXAMPLE_SECRETS = frozenset({
    "AKIAIOSFODNN7EXAMPLE",   # AWS's official documentation example key
    # Firebase's own Android SDK documentation keys. They are `AIza`-shaped and
    # therefore matched, and they appear in copied sample code across the web.
    # gitleaks carries the same sixteen values in a hard-coded allowlist on its
    # `gcp-api-key` rule; three were transcribed in v2.14.5, and measuring this
    # scanner against that list showed the remaining thirteen were still being
    # reported. They accounted for 13 of the 14 alarms the whole external corpus
    # produced, which is worth stating plainly rather than as a precision number:
    # the corpus over-weights one vendor's documentation. The narrow, real gain
    # is bundles that paste Firebase's Android sample config verbatim, which is
    # common enough to be worth the eight lines.
    "AIzaSyabcdefghijklmnopqrstuvwxyz1234567",
    "AIzaSyAnLA7NfeLquW1tJFpx_eQCxoX-oo6YyIs",
    "AIzaSyCkEhVjf3pduRDt6d1yKOMitrUEke8agEM",
    "AIzaSyDMAScliyLx7F0NPDEJi1QmyCgHIAODrlU",
    "AIzaSyD3asb-2pEZVqMkmL6M9N6nHZRR_znhrh0",
    "AIzayDNSXIbFmlXbIE6mCzDLQAqITYefhixbX4A",
    "AIzaSyAdOS2zB6NCsk1pCdZ4-P6GBdi_UUPwX7c",
    "AIzaSyASWm6HmTMdYWpgMnjRBjxcQ9CKctWmLd4",
    "AIzaSyANUvH9H9BsUccjsu2pCmEkOPjjaXeDQgY",
    "AIzaSyA5_iVawFQ8ABuTZNUdcwERLJv_a_p4wtM",
    "AIzaSyA4UrcGxgwQFTfaI3no3t7Lt1sjmdnP5sQ",
    "AIzaSyDSb51JiIcB6OJpwwMicseKRhhrOq1cS7g",
    "AIzaSyBF2RrAIm4a0mO64EShQfqfd2AFnzAvvuU",
    "AIzaSyBcE-OOIbhjyR83gm4r2MFCu4MJmprNXsw",
    "AIzaSyB8qGxt4ec15vitgn44duC5ucxaOi4FmqE",
    "AIzaSyA8vmApnrHNFE0bApF4hoZ11srVL_n0nvY",
})
_PLACEHOLDER_RE = re.compile(
    r"(?i)(your[_-]?(?:api|key|token|secret|id)|placeholder|changeme|"
    r"redacted|x{8,}|0{8,}|<[^>]{2,}>|"
    # Un-interpolated template syntax. `<…>` was already here; the interpolation
    # forms were not, and they ship for real — a broken build, a server-rendered
    # template that never ran, a Docker entrypoint that failed to substitute.
    # Found by scanning this project's own diff with this scanner, which
    # reported the literal `{_STRIPE_LIVE}` out of a test fixture as a
    # credential. Placed here rather than in one detector because the failure
    # belongs to every detector that reads a quoted value.
    r"\$\{[^}]{1,80}\}|"          # ${VAR} — shell, JS template literal
    r"\{\{[^}]{1,80}\}\}|"        # {{VAR}} — Handlebars, Jinja, Vue, Go
    r"^\{[A-Za-z_][A-Za-z0-9_]{0,60}\}$|"   # {VAR} alone — str.format, f-string
    r"%\([A-Za-z_][A-Za-z0-9_]*\)s|"        # %(name)s — Python printf mapping
    # The EXAMPLE marker, case-sensitive. AWS documents its sample credentials by
    # ending them in literal `EXAMPLE`, and other vendors copied the convention
    # (`ABSKQmVkcm9ja0FQSUtleS1EXAMPLE`). Case-sensitivity is deliberate: a
    # case-insensitive form would swallow `example.com` and every `exampleKey`
    # identifier, trading a real detection for a cosmetic one.
    r"(?-i:EXAMPLE))"
)
_B64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_MAX_B64_BLOBS = 200


def is_benign_placeholder(value: str) -> bool:
    """True if a matched value is a known documentation example or an obvious
    placeholder. Filtering these out is a standard false-positive-reduction step."""
    return value in _KNOWN_EXAMPLE_SECRETS or bool(_PLACEHOLDER_RE.search(value))


# Share of the value one character may occupy before it reads as filler. A
# genuinely random 16-character decimal id crosses 0.6 about once in 25,000
# draws; `AKIAAAAAAAAAAAAAAAAA` is at 0.8 and `Q`*58 at 1.0.
_DEGENERATE_DOMINANCE = _env_float("DEGENERATE_DOMINANCE", 0.6)


def looks_degenerate(value: str) -> bool:
    """True when a value is filler rather than a credential.

    This replaces an absolute Shannon floor for structural detectors, and the
    reason is a measured false negative rather than a preference.

    MIN_STRUCTURAL_ENTROPY exists to reject `AKIAAAAAAAAAAAAAAAAA` and `Q`*58 —
    its comment says so. At 2.5 bits it does. But Shannon entropy is measured in
    absolute bits and a decimal digit carries at most log2(10) = 3.32 of them, so
    an ordinary random numeric id sits far closer to that floor than an
    alphanumeric key of the same length ever does. Measured over 20,000 draws
    each: 5.4% of genuine 16-digit ids and 2.4% of 18-digit ids fall below 2.5
    bits and were silently dropped. Hex and alphanumeric values are unaffected
    (0.0%), which is why this went unnoticed — it is invisible unless a detector
    matches a numeric value, and the Discord and Asana client IDs are the first
    that do.

    Degeneracy does not depend on how large the alphabet is. A value is filler
    when it is built from almost no distinct characters, or when one character
    dominates it — both true of the junk the floor was written to reject, and
    neither true of a random id in any base.
    """
    core = value.strip()
    if len(core) < 8:
        # Too short for any of these tests to mean anything; the pattern's own
        # shape is doing the work at this length.
        return False
    distinct = set(core)
    if len(distinct) <= 2:
        return True
    if max(core.count(c) for c in distinct) / len(core) >= _DEGENERATE_DOMINANCE:
        return True
    # Periodic filler. `GR1348941` + `123123123…` is dominated by no single
    # character and holds nine distinct ones, so neither test above sees it —
    # but it repeats a three-character cycle and is plainly not a credential.
    # gitleaks lists exactly that string as a declared non-secret, and the
    # absolute entropy floor this function replaced happened to catch it at 2.45
    # bits; keeping that catch is what makes the replacement a pure improvement
    # rather than a trade.
    #
    # Distinct trigrams against half the length, applied only from 16 characters
    # up. Measured over 20,000 draws per shape at 12/16/18/24/32/40 characters
    # in base 10, 16 and 62: 0.000% of random values are dropped at every length
    # of 16 or more, and 0.005% at 12 — which is why the floor is 16 and not 8.
    if len(core) >= 16:
        trigrams = {core[i:i + 3] for i in range(len(core) - 2)}
        if len(trigrams) <= len(core) / 2:
            return True
    return False


def _decode_base64_blobs(text: str) -> list[str]:
    """Decode base64-looking blobs so the regex pass can also inspect secrets
    hidden inside encoded strings (a technique used by modern scanners)."""
    import base64
    out: list[str] = []
    for m in _B64_BLOB_RE.finditer(text):
        if len(out) >= _MAX_B64_BLOBS:
            break
        blob = m.group(0)
        if len(blob) % 4:
            continue
        try:
            decoded = base64.b64decode(blob, validate=True)
            s = decoded.decode("utf-8")
        except Exception:
            continue
        if len(s) >= 8 and s.isprintable():
            out.append(s)
    return out


def _scan_text(
    scan_id: str, target_url: str, source_url: str, text: str, decoded: bool = False,
) -> list[RawFinding]:
    findings: list[RawFinding] = []
    # One lowercase copy, then a substring test per pattern, instead of 108 full
    # regex passes over the asset. Measured at ~11 ms per pattern per megabyte,
    # and on a real bundle nearly every provider name is absent — so most of
    # those passes were reading a megabyte to find nothing.
    #
    # The test is a NECESSARY condition only: it decides whether to run the
    # regex, never whether a match counts. Patterns that could not be reduced to
    # a safe literal carry an empty prefilter and are scanned exactly as before.
    haystack = text.lower()
    for pattern in SECRET_PATTERNS:
        if pattern.prefilter and not any(k in haystack for k in pattern.prefilter):
            continue
        examined = 0
        for match in pattern.regex.finditer(text):
            examined += 1
            if examined > MAX_MATCHES_PER_PATTERN:
                # Defence-in-depth: a pathological blob shall not spawn unbounded
                # matches for one detector. Bound the work and move on.
                logger.debug(
                    "Match cap (%d) reached for %s; truncating further matches.",
                    MAX_MATCHES_PER_PATTERN, pattern.name,
                )
                break
            raw_value = (
                match.group(1)
                if match.lastindex and match.lastindex >= 1
                else match.group(0)
            )
            if is_benign_placeholder(raw_value):
                continue
            entropy = shannon_entropy(raw_value)
            # Generic keyword=value catch-all must clear the full randomness bar.
            # Its values are alphanumeric, where an absolute bit floor behaves.
            #
            # Structural detectors are asked a different question — "is this
            # filler?" — and asked it directly, because an absolute floor answers
            # it wrongly on a small alphabet. See looks_degenerate().
            if pattern.entropy_gated:
                if entropy < MIN_ENTROPY_THRESHOLD:
                    continue
            elif looks_degenerate(raw_value):
                continue
            start = max(0, match.start() - CONTEXT_WINDOW_CHARS)
            end   = min(len(text), match.end() + CONTEXT_WINDOW_CHARS)
            snippet = text[start:end].replace("\n", " ").strip()
            if decoded:
                snippet = "[base64-decoded] " + snippet
            findings.append(RawFinding(
                scan_id=scan_id,
                target_url=target_url,
                source_url=source_url,
                secret_type=pattern.name,
                raw_match=raw_value,
                context_snippet=snippet,
                entropy=entropy,
            ))
    return findings


# Secret types that reached a finding through a composite rule rather than
# through their own detector. Used by `_collapse_duplicates` to rank a composite
# claim below a real detector's claim on the same value.
COMPOSITE_TYPES: frozenset[str] = frozenset(r.name for r in composite.COMPOSITE_RULES)


def _scan_composites(
    scan_id: str, target_url: str, source_url: str, text: str,
) -> list[RawFinding]:
    """Findings a single regex cannot reach — see composite.py.

    Every existing gate still applies. The composite rule supplies an *identity*
    for a value whose own shape carries none; it is not a licence to skip the
    placeholder allowlist or the entropy floor, and skipping them is how a
    proximity rule turns into a false-positive engine.

    The entropy floor used is the structural one, not the generic one: a value
    that an AKIA vouches for is anchored by shape in the same sense a provider
    prefix is, so holding it to the loose-match bar would drop genuinely
    modest-entropy live keys for no gain.
    """
    if not SCAN_COMPOSITE:
        return []
    out: list[RawFinding] = []
    for cm in composite.find_composites(text):
        if is_benign_placeholder(cm.value):
            continue
        entropy = shannon_entropy(cm.value)
        if looks_degenerate(cm.value):
            continue
        start = max(0, cm.start - CONTEXT_WINDOW_CHARS)
        end = min(len(text), cm.end + CONTEXT_WINDOW_CHARS)
        snippet = text[start:end].replace("\n", " ").strip()
        out.append(RawFinding(
            scan_id=scan_id,
            target_url=target_url,
            source_url=source_url,
            secret_type=cm.secret_type,
            raw_match=cm.value,
            # The rationale travels with the finding because a report otherwise
            # has no way to explain why a shapeless 40-character string was
            # called an AWS secret key. "Proximity to an AKIA ID" is the whole
            # justification, and a finding that cannot show its reasoning is one
            # an analyst is right to distrust.
            context_snippet=f"[composite: {cm.rationale}] {snippet}",
            entropy=entropy,
        ))
    return out


def extract_secrets(
    scan_id: str,
    target_url: str,
    source_url: str,
    text: str,
) -> list[RawFinding]:
    findings = _scan_text(scan_id, target_url, source_url, text)
    # R7: values that only become identifiable because of what sits next to them.
    findings.extend(_scan_composites(scan_id, target_url, source_url, text))
    # Also inspect base64-decoded blobs for secrets hidden inside encoded strings.
    for decoded in _decode_base64_blobs(text):
        findings.extend(_scan_text(scan_id, target_url, source_url, decoded, decoded=True))
    # Inline SSR state (__NEXT_DATA__, __NUXT__, __INITIAL_STATE__ …): decode the
    # JSON and scan its string values, so a credential mangled by JSON escaping
    # is still recognised. Only worth doing on markup.
    if SCAN_INLINE_JSON and "<script" in text[:MAX_INLINE_JSON_BYTES].lower():
        decoded_json = extract_inline_json_strings(text)
        if decoded_json:
            findings.extend(
                _scan_text(scan_id, target_url, source_url, decoded_json, decoded=True)
            )
    # De-duplicate by fingerprint (same secret found raw and base64-encoded = one finding).
    seen: set[str] = set()
    unique: list[RawFinding] = []
    for f in findings:
        fp = f.fingerprint
        if fp in seen:
            continue
        seen.add(fp)
        unique.append(f)
    return _collapse_duplicates(unique)


def scan_asset(
    scan_id: str, target_url: str, source_url: str, body: str,
) -> list[tuple[str, list[RawFinding]]]:
    """Per-asset dispatch: a source map is scanned as its DECODED original
    sources, anything else as itself. Returns (attributed_url, findings) groups
    so the caller can report per-original-file provenance.

    Extracted so the benchmark harness measures the path production actually
    takes. Reimplementing this dispatch in the harness produced a "miss" for
    every quote-delimited detector — `datadog: { apiKey: "…" }` inside a map's
    JSON-escaped `sourcesContent` reads as `\\"…\\"`, and the closing quote the
    pattern needs is a backslash. That was the measuring instrument being wrong
    about the tool, which is the one thing a benchmark must never be.
    """
    if SCAN_SOURCEMAP_CONTENT and looks_like_sourcemap(source_url, body):
        srcs = extract_sourcemap_sources(body, source_url)
        if srcs:
            return [(vsrc_url, extract_secrets(scan_id, target_url, vsrc_url, content))
                    for vsrc_url, content in srcs]
    return [(source_url, extract_secrets(scan_id, target_url, source_url, body))]


def _claim_rank(secret_type: str) -> int:
    """How authoritative a detector's claim on a value is. Higher wins.

    2 — a provider detector matched the value by its own shape. Most specific:
        it knows the provider, so it carries the right severity and the right
        remediation text.
    1 — a composite rule inferred the value's identity from a neighbouring
        anchor. Correct often enough to be worth having, but it is a fallback
        for what the registry missed, never a second opinion on what it caught.
    0 — the generic keyword=value catch-all. Matched loosely; knows nothing
        about the provider.
    """
    if secret_type == GENERIC_SECRET_TYPE:
        return 0
    return 1 if secret_type in COMPOSITE_TYPES else 2


def _collapse_duplicates(findings: list[RawFinding]) -> list[RawFinding]:
    """Collapse one credential matched by several detectors into a single finding.

    The generic keyword=value catch-all matches loosely and therefore also fires on
    secrets a provider-specific detector already typed precisely. Reporting both is
    wrong three ways: it double-counts the exposure in client reports, spends a
    second AI-validation call on the same string, and leaves two conflicting
    severities for one credential. R7's composite rules create the same collision
    from the other direction — an AWS secret key that the keyword-anchored detector
    *did* manage to see would also be claimed by the AKIA-proximity rule.

    Identity here is (source_url, raw_match) — the same value at the same location.
    The most authoritative claim on that value wins; order is otherwise preserved.
    """
    best: dict[tuple[str, str], int] = {}
    for f in findings:
        key = (f.source_url, f.raw_match)
        rank = _claim_rank(f.secret_type)
        if rank > best.get(key, -1):
            best[key] = rank

    kept: list[RawFinding] = []
    seen: set[tuple[str, str]] = set()
    for f in findings:
        key = (f.source_url, f.raw_match)
        if _claim_rank(f.secret_type) < best[key] or key in seen:
            continue
        seen.add(key)
        kept.append(f)
    return kept


# Retained under its original name: the v2.x tests and the benchmark harness
# import it directly, and renaming a function is not a behaviour change worth
# breaking a caller over.
_collapse_generic_duplicates = _collapse_duplicates


# ─────────────────────────────────────────────────────────────────────────────
# Gemini Contextual Validation
# ─────────────────────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = (
    "You are a senior application-security analyst triaging a string extracted from a "
    "website's client-side code. Decide whether it is a GENUINELY SENSITIVE, EXPLOITABLE "
    "secret — not merely something shaped like a key. Clients pay for impact, not for "
    "known-public information, so be rigorous about what actually creates risk.\n\n"
    "PUBLIC-BY-DESIGN identifiers are NOT secrets. Many credential-shaped strings are "
    "meant to ship in client code and are safe on their own — mark these is_valid=false "
    "and public_by_design=true:\n"
    "  • Firebase Web config apiKey (an AIza… value next to authDomain / projectId / appId / "
    "storageBucket) — a project identifier, not a secret; real risk comes only from insecure "
    "Firebase Security Rules or an unrestricted API key, which cannot be judged from the key alone.\n"
    "  • Google Maps / other browser API keys, reCAPTCHA site keys.\n"
    "  • PUBLISHABLE payment keys (Stripe/PayPal pk_live / pk_test), Sentry DSNs, PostHog / "
    "Segment write keys, Algolia search-only keys, Mapbox pk. tokens.\n\n"
    "GENUINELY SENSITIVE (is_valid=true) — private keys, service-account JSON, provider SECRET "
    "keys (sk_live, AWS secret access key, GitHub/GitLab/Slack tokens), database connection URIs "
    "with embedded credentials, session/refresh tokens. Also reject obvious mocks, placeholders, "
    "example keys and minified-code artefacts (is_valid=false).\n\n"
    "Return: is_valid, confidence (0-100), public_by_design, impact (ONE concrete sentence on what "
    "an attacker could actually do with this if exploitable — the blast radius; empty string if "
    "benign/public), and a brief reason."
)


class GeminiVerdict(BaseModel):
    """Strict structured-output contract for a single validation verdict.

    Bound directly to the SDK's ``response_schema`` so the model is constrained to
    emit exactly these fields with these types — replacing the old regex-scrape +
    ``json.loads`` path and its data-type ambiguity. Field names/types mirror the
    ``ValidatedFinding`` columns so values flow into SQLite without coercion."""

    is_valid: bool = Field(
        description="True only if this is a genuine, sensitive, exploitable secret — "
                    "NOT a public-by-design client identifier, mock, or placeholder.")
    confidence: int = Field(ge=0, le=100, description="Confidence in is_valid, 0-100.")
    public_by_design: bool = Field(
        default=False,
        description="True if this value is intended to be public in client code (Firebase web "
                    "apiKey, browser/Maps key, Stripe pk_ publishable key, Sentry DSN, etc.). "
                    "These are identifiers, not secrets, and must not be reported as exposures.")
    impact: str = Field(
        default="",
        description="One concrete sentence: what an attacker could actually do with this if "
                    "exploitable (blast radius). Empty string when benign or public-by-design.")
    reason: str = Field(description="Brief (one sentence) justification.")


def _severity_for(secret_type: str) -> str:
    meta = PATTERN_BY_NAME.get(secret_type)
    return meta.severity if meta is not None else "MEDIUM"


def _tier_config(thinking_level: str) -> types.GenerateContentConfig:
    """Build the GenerateContentConfig for one validation tier.

    The system instruction is a stable, identical prefix on every call, which lets
    Gemini's *implicit* context caching (automatic, free, no minimum-token floor)
    discount the shared tokens on repeat calls — the honest, workload-appropriate
    form of the "cache to cut input tokens" optimisation (explicit caches.create
    needs a large shared prefix this per-finding workload does not have).
    ``response_schema`` pins the output to GeminiVerdict; ``thinking_level`` is the
    Gemini-3.x reasoning control (minimal→high) that replaces the retired numeric
    thinking_budget."""
    return types.GenerateContentConfig(
        system_instruction=_SYSTEM_PROMPT,
        temperature=0.1,
        response_mime_type="application/json",
        response_schema=GeminiVerdict,
        thinking_config=types.ThinkingConfig(thinking_level=thinking_level),
    )


# API status codes that indicate a permanent configuration problem — an invalid /
# blocked key or a model the key can't call — rather than a transient hiccup.
# Retrying them is futile, so we fail fast and disable AI for the rest of the scan
# instead of hammering the API (and flooding needs-review) once per finding.
_NON_RETRYABLE_AI_CODES = frozenset({400, 401, 403, 404})
_ai_disabled_reason: "str | None" = None


def _describe_ai_config_error(code: object, exc: Exception) -> str:
    s = str(exc).lower()
    if code == 404 or "not found" in s or "does not exist" in s:
        return ("Gemini model not available to this key (404) — set GEMINI_TIER1_MODEL / "
                "GEMINI_TIER2_MODEL to models your API key can call.")
    if code == 403:
        return ("Gemini API access denied (403) — the key lacks permission or the Generative "
                "Language API is not enabled for its project.")
    if code in (400, 401) or "api key not valid" in s or "invalid" in s:
        return ("GEMINI_API_KEY was rejected by Google (invalid key) — set a valid key from "
                "https://aistudio.google.com/apikey in your .env.")
    return f"Gemini API error {code} — AI validation disabled for this scan."


def _ai_skipped(finding: RawFinding, reason: str) -> ValidatedFinding:
    """AI unavailable for a configuration reason (no key / rejected key / missing
    model). The root cause is surfaced once, not once per finding.

    `ai_judged=False` is what makes "unvalidated" mean it: without it,
    classify_validated read confidence 50 as an ordinary weak verdict, sent
    structural findings to review and *dropped* every entropy-gated one. Running
    with no Gemini key is the documented offline mode, so the default
    configuration was silently discarding every `apiKey = "…"` finding.

    What it returned instead — is_valid=True, confidence=50, no impact, no
    public-by-design call — kept every finding, but it is not a verdict. It is
    the absence of one, identical for an AWS secret key and for a Stripe
    publishable key, and the operator got both in the same undifferentiated
    queue with nothing said about either. `triage` renders a real deterministic
    verdict here instead: known-public values are dismissed with the same
    confidence the AI tier would use, generic noise from test scaffolding is
    dismissed, and everything retained carries a blast-radius sentence.

    `ai_judged` stays False regardless, because it is a statement of fact about
    which tier judged this, and the report says "triaged offline" rather than
    implying a model looked at it. What changed is that the offline tier now has
    something to say.
    """
    meta = PATTERN_BY_NAME.get(finding.secret_type)
    verdict = triage.triage(
        secret_type=finding.secret_type,
        raw_match=finding.raw_match,
        context_snippet=finding.context_snippet,
        entropy=finding.entropy,
        severity=meta.severity if meta else "MEDIUM",
        structural=(meta is not None and not meta.entropy_gated),
        source_url=finding.source_url,
    )
    return ValidatedFinding(
        raw=finding,
        is_valid=verdict.is_valid,
        confidence=verdict.confidence,
        reason=f"{reason} Offline triage: {verdict.reason}",
        impact=verdict.impact,
        public_by_design=verdict.public_by_design,
        ai_judged=False,
        offline_triaged=True,
    )


async def _call_tier(
    finding: RawFinding,
    model: str,
    thinking_level: str,
    tier_label: str,
    broadcast: Broadcaster | None,
) -> tuple[GeminiVerdict | None, str]:
    """Run one validation tier with retry/backoff.

    Returns ``(verdict, "")`` on success, or ``(None, last_error)`` if every attempt
    failed — rate limit (429), token exhaustion, transport error, or unparseable
    output. The caller decides how a None degrades; a finding is never dropped."""
    user_prompt = (
        f"Secret type: {finding.secret_type}\n"
        f"Severity: {_severity_for(finding.secret_type)}\n"
        f"Extracted value: {finding.raw_match}\n"
        f"Surrounding code:\n```\n{finding.context_snippet}\n```"
    )
    cfg = _tier_config(thinking_level)
    last_error = "unknown error"

    for attempt in range(1, RETRY_ATTEMPTS + 1):
        try:
            response = await asyncio.to_thread(
                functools.partial(
                    _get_client().models.generate_content,
                    model=model,
                    contents=user_prompt,
                    config=cfg,
                )
            )
            verdict = response.parsed
            if not isinstance(verdict, GeminiVerdict):
                # Structured parse unavailable — validate the raw JSON text against
                # the same schema instead of ad-hoc dict cleanups.
                text = (getattr(response, "text", "") or "").strip()
                if not text:
                    raise ValueError("empty model response")
                # Validate against the same strict schema (0-100, correct types) —
                # an out-of-range / malformed verdict raises here and degrades to
                # needs-review rather than being silently coerced.
                verdict = GeminiVerdict.model_validate_json(text)
            return verdict, ""

        except genai_errors.APIError as exc:
            code = getattr(exc, "code", "?")
            last_error = f"API error {code}: {exc}"
            logger.warning("Gemini %s API error (attempt %d): %s", tier_label, attempt, exc)
            if code in _NON_RETRYABLE_AI_CODES:
                # Permanent config error — do not retry, and latch AI off for this scan
                # so the remaining findings don't repeat the same futile call.
                global _ai_disabled_reason
                if _ai_disabled_reason is None:
                    _ai_disabled_reason = _describe_ai_config_error(code, exc)
                    logger.error("AI validation disabled for this scan: %s", _ai_disabled_reason)
                    if broadcast:
                        await broadcast({
                            "type": "log", "level": "ERROR",
                            "message": f"[AI] Validation disabled for this scan — {_ai_disabled_reason}",
                        })
                return None, last_error
            if broadcast:
                await broadcast({
                    "type": "log", "level": "WARN",
                    "message": f"[AI:{tier_label}] API error attempt {attempt} (code {code})",
                })
        except (ValidationError, ValueError, json.JSONDecodeError) as exc:
            last_error = f"parse error: {exc}"
            logger.warning("Gemini %s parse error (attempt %d): %s", tier_label, attempt, exc)
        except Exception as exc:  # noqa: BLE001 — a validation call must never crash a scan
            last_error = str(exc)
            logger.warning("Gemini %s error (attempt %d): %s", tier_label, attempt, exc)

        if attempt < RETRY_ATTEMPTS:
            await asyncio.sleep(RETRY_BACKOFF_BASE ** attempt)

    return None, last_error


async def _emit_verdict(
    finding: RawFinding,
    verdict: GeminiVerdict,
    tier_label: str,
    broadcast: Broadcaster | None,
) -> ValidatedFinding:
    result = ValidatedFinding(
        raw=finding,
        is_valid=verdict.is_valid,
        confidence=verdict.confidence,
        reason=verdict.reason,
        impact=getattr(verdict, "impact", "") or "",
        public_by_design=bool(getattr(verdict, "public_by_design", False)),
    )
    if broadcast:
        level = "ERROR" if result.is_valid and result.confidence >= GEMINI_CONFIDENCE_MIN else "INFO"
        await broadcast({
            "type": "log", "level": level,
            "message": (
                f"[AI:{tier_label}] {finding.secret_type} — "
                f"valid={result.is_valid} confidence={result.confidence}% — {result.reason}"
            ),
        })
    return result


async def _emit_needs_review(
    finding: RawFinding,
    last_error: str,
    broadcast: Broadcaster | None,
) -> ValidatedFinding:
    # All tiers exhausted — do NOT drop the finding. Surface it for a human.
    logger.error(
        "AI validation permanently failed for %s in %s after %d attempts: %s — "
        "flagging as NEEDS REVIEW instead of dropping.",
        finding.secret_type, finding.source_url, RETRY_ATTEMPTS, last_error,
    )
    if broadcast:
        await broadcast({
            "type": "log", "level": "ERROR",
            "message": (
                f"[AI] Validation FAILED for {finding.secret_type} "
                f"({last_error}) — flagged for manual review."
            ),
        })
    return ValidatedFinding(
        raw=finding,
        is_valid=False,
        confidence=NEEDS_REVIEW_SENTINEL,
        reason=f"AI validation unavailable after {RETRY_ATTEMPTS} attempts ({last_error}). Manual review required.",
    )


async def validate_with_gemini(
    finding: RawFinding,
    broadcast: Broadcaster | None = None,
) -> ValidatedFinding:
    """Two-tier contextual validation. Always returns a ValidatedFinding — never
    None.

    Tier 1 (fast, minimal reasoning) pre-filters obvious noise. Tier 2 (stronger,
    high reasoning) deep-validates anything the pre-filter flags as real, or that
    carries an escalate-severity (e.g. cloud keys, DB URIs, private keys) — we never
    let the cheap model be the last word on a critical secret. If the API is
    unreachable / rate-limited / exhausted after retries, the finding is surfaced as
    needs-review (confidence = NEEDS_REVIEW_SENTINEL) rather than silently dropped —
    a scanner must never lose a finding quietly."""
    if not GEMINI_API_KEY:
        # NEEDS_REVIEW_SENTINEL, not a fabricated confidence. `confidence=50,
        # is_valid=True` looked harmless — too low to confirm, so everything
        # lands in review — but classify_validated only sends a finding to
        # review on that path when it is *structural*. The generic
        # keyword=value catch-all is entropy-gated, so it fell through to
        # "drop": with no key configured, every `apiKey = "…"` /
        # `password: "…"` / `token = "…"` finding was discarded in silence, and
        # that is the most common shape a hardcoded credential takes in real
        # client code. Running without a Gemini key is the documented offline
        # mode on the Pi, so this was the default configuration losing findings.
        #
        # The sentinel says what is actually true — the AI did not judge this —
        # and routes it to a human, which is the rule the rest of the file
        # already follows: a scanner must never lose a finding quietly.
        return _ai_skipped(finding, "AI validation skipped — GEMINI_API_KEY not configured.")

    # A prior finding already hit a permanent config error this scan — skip the API
    # entirely (don't repeat the futile call) and return the finding unvalidated.
    if _ai_disabled_reason:
        return _ai_skipped(finding, f"AI validation unavailable — {_ai_disabled_reason}")

    if broadcast:
        await broadcast({
            "type": "log", "level": "WARN",
            "message": f"[AI] Validating {finding.secret_type} from {finding.source_url} …",
        })

    severity = _severity_for(finding.secret_type)

    # ── Tier 1: cheap pre-filter ────────────────────────────────────────────────
    v1, err1 = await _call_tier(
        finding, GEMINI_TIER1_MODEL, GEMINI_TIER1_THINKING, "pre-filter", broadcast,
    )

    # Escalate to the deep tier when the finding is an escalate-severity, or the
    # pre-filter believes it is a real secret and we want a rigorous confirmation.
    escalate = severity in GEMINI_ESCALATE_SEVERITIES or (v1 is not None and v1.is_valid)

    if escalate:
        v2, err2 = await _call_tier(
            finding, GEMINI_TIER2_MODEL, GEMINI_TIER2_THINKING, "deep", broadcast,
        )
        if v2 is not None:
            return await _emit_verdict(finding, v2, "deep", broadcast)
        # Deep tier failed — fall back to the pre-filter verdict if we have one.
        if v1 is not None:
            return await _emit_verdict(finding, v1, "pre-filter (deep tier unavailable)", broadcast)
        # A config error (invalid key / missing model) degrades to skipped, not the
        # needs-review flood; a transient failure still surfaces for manual review.
        if _ai_disabled_reason:
            return _ai_skipped(finding, f"AI validation unavailable — {_ai_disabled_reason}")
        return await _emit_needs_review(finding, err2 or err1, broadcast)

    if v1 is not None:
        return await _emit_verdict(finding, v1, "pre-filter", broadcast)

    if _ai_disabled_reason:
        return _ai_skipped(finding, f"AI validation unavailable — {_ai_disabled_reason}")
    return await _emit_needs_review(finding, err1, broadcast)


# ─────────────────────────────────────────────────────────────────────────────
# Discord Webhook Dispatcher
# ─────────────────────────────────────────────────────────────────────────────

# Embed accent colour, keyed on the finding's *effective* severity rather than
# on its type name. The previous per-type table listed 16 of the registry's 60+
# detectors, so every newer pattern (the whole AI/ML provider family included)
# silently fell through to the CRITICAL red — an ElevenLabs key and an AWS root
# key arrived in Discord looking identical. Severity already comes from the
# pattern registry and accounts for the public-by-design downgrade, so use it.
_SEVERITY_COLORS: dict[str, int] = {
    "CRITICAL": 0xE53E3E,
    "HIGH":     0xDD6B20,
    "MEDIUM":   0xD69E2E,
    "LOW":      0x3182CE,
    "INFO":     0x63B3ED,
}

# secret_type name -> severity, sourced directly from the pattern registry
# (single source of truth — no more guessing severity from a Discord color).
SECRET_TYPE_SEVERITY: dict[str, str] = {p.name: p.severity for p in SECRET_PATTERNS}


async def dispatch_discord(
    client: httpx.AsyncClient,
    finding: ValidatedFinding,
    semaphore: asyncio.Semaphore,
    broadcast: Broadcaster | None = None,
) -> bool:
    if not DISCORD_WEBHOOK_URL:
        return False

    raw = finding.raw
    color = _SEVERITY_COLORS.get(finding.effective_severity(), 0xD69E2E)
    safe_snippet_full = redact_snippet(raw.context_snippet, raw.raw_match)
    snippet = (
        safe_snippet_full[:900] + "…"
        if len(safe_snippet_full) > 900
        else safe_snippet_full
    )
    redacted = redact_secret(raw.raw_match)

    payload = {
        "username": f"SecretNode v{version.TOOL_VERSION}",
        "avatar_url": "https://cdn-icons-png.flaticon.com/512/2092/2092757.png",
        "embeds": [{
            "title": f"🚨 Secret Exposed: {raw.secret_type}",
            "color": color,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "footer": {"text": f"SecretNode v{version.TOOL_VERSION} — ASM Scanner"},
            "fields": [
                {"name": "🎯 Target",        "value": f"`{raw.target_url}`",      "inline": False},
                {"name": "📄 Source Asset",  "value": f"`{raw.source_url}`",      "inline": False},
                {"name": "🔑 Secret Type",   "value": raw.secret_type,            "inline": True},
                {"name": "⚠️ Severity",      "value": finding.effective_severity(), "inline": True},
                {"name": "📊 Entropy",       "value": f"`{raw.entropy:.2f} bits`","inline": True},
                {"name": "🤖 AI Confidence", "value": f"`{finding.confidence}%`", "inline": True},
                {"name": "💬 AI Reasoning",  "value": finding.reason[:1000],      "inline": False},
                {"name": "🔍 Code Snippet",  "value": f"```\n{snippet}\n```",     "inline": False},
                {"name": "🗝️ Matched (redacted)", "value": f"`{redacted}`",       "inline": False},
            ],
        }],
    }

    async with semaphore:
        for attempt in range(1, RETRY_ATTEMPTS + 1):
            try:
                resp = await client.post(
                    DISCORD_WEBHOOK_URL, json=payload, timeout=15.0
                )
                if resp.status_code in (200, 204):
                    if broadcast:
                        await broadcast({
                            "type": "log",
                            "level": "INFO",
                            "message": f"[Discord] Alert dispatched for {raw.secret_type}",
                        })
                    return True
                if resp.status_code == 429:
                    ra = float(resp.headers.get("Retry-After", 5 * attempt))
                    await asyncio.sleep(ra)
                    continue
                logger.error("Discord HTTP %d: %s", resp.status_code, resp.text[:200])
                return False
            except Exception as exc:  # noqa: BLE001
                logger.warning("Discord dispatch error (attempt %d): %s", attempt, exc)
                if attempt < RETRY_ATTEMPTS:
                    await asyncio.sleep(RETRY_BACKOFF_BASE ** attempt)

    return False


# ─────────────────────────────────────────────────────────────────────────────
# Scan State (for stop/cancel support)
# ─────────────────────────────────────────────────────────────────────────────

class ScanState:
    """Holds mutable scan-level state; allows cooperative cancellation."""

    def __init__(self) -> None:
        self.cancelled = False
        self.started_at: float = time.monotonic()

    def cancel(self) -> None:
        self.cancelled = True

    def check(self) -> None:
        """Raise asyncio.CancelledError if the scan has been stopped."""
        if self.cancelled:
            raise asyncio.CancelledError("Scan cancelled by user")


# ─────────────────────────────────────────────────────────────────────────────
# Master Scan Orchestrator
# ─────────────────────────────────────────────────────────────────────────────

def classify_validated(v: "ValidatedFinding") -> str:
    """Route a validated finding to exactly one of: 'confirmed', 'review',
    'informational', 'drop'.

    The critical rule is the structural one: a *structural/provider* match
    (high-precision by shape — AKIA…, ghp_…, sk_live_…, PEM) that was **not
    confidently dismissed** is sent to manual review, never silently dropped.
    Without this, a real live key a tier merely under-called on (e.g. because a
    page gave it no surrounding context) would vanish with no trace — a false
    negative, the worst failure mode for a scanner. The generic keyword=value
    catch-all keeps the aggressive behaviour (a confident 'no' there is trusted
    and dropped), preserving the 'no false positives in Confirmed' promise.

    'informational' is public-by-design: a Stripe pk_, a Sentry DSN, a Firebase
    web apiKey. These used to route to 'drop', because a public-by-design verdict
    is a confident dismissal and confident dismissals were deleted. Two things
    said that was wrong. `effective_severity()` exists for the sole purpose of
    downgrading such a finding to INFO, and nothing reaching it could survive
    routing — so the method was unreachable. And the ground-truth corpus declares
    a `public` class whose contract is "must be detected AND classified
    public-by-design", which deletion does not satisfy; the HTTP benchmark scored
    exactly those three specimens as false negatives.

    Reporting them is also the better client outcome. Silently deleting a Stripe
    publishable key leaves the reader unable to tell whether the scanner examined
    it and cleared it or never saw it at all. An INFO line saying "found, public
    by design, no action needed" is evidence of thoroughness. It is emphatically
    NOT the same as reporting it as an exposure: informational findings raise no
    alert, are never live-verified, and carry INFO severity.
    """
    if v.confidence == NEEDS_REVIEW_SENTINEL:
        return "review"                                    # no verdict — human decides
    if v.public_by_design:
        return "informational"
    if not v.ai_judged:
        # No model judged this. Either the deterministic tier did, or nothing did.
        if not v.offline_triaged:
            return "review"
        if v.is_valid:
            # Triage retains but never confirms: a rules engine that has not seen
            # the credential work has no business putting a finding under a
            # heading that reads "confirmed". Live verification is what promotes
            # one, on the provider's own evidence rather than on an opinion.
            return "review"
        if v.confidence >= GEMINI_CONFIDENCE_MIN:
            return "drop"      # confidently not an exposure (public by design, test scaffolding)
        # A hedged offline dismissal is not grounds to discard anything. The
        # asymmetry is the whole point: a wrong confirmation wastes an
        # afternoon, a wrong dismissal is the failure this tool exists to
        # prevent. Anything short of certain goes to a human.
        return "review"
    if v.is_valid and v.confidence >= GEMINI_CONFIDENCE_MIN:
        return "confirmed"
    meta = PATTERN_BY_NAME.get(v.raw.secret_type)
    structural = meta is not None and not meta.entropy_gated
    ai_confidently_dismissed = (not v.is_valid) and v.confidence >= GEMINI_CONFIDENCE_MIN
    if structural and not ai_confidently_dismissed:
        return "review"        # shape-anchored + AI not sure it's fake → human confirms
    return "drop"


async def verify_confirmed_findings(
    confirmed: list["ValidatedFinding"],
    client: Any,
    state: "ScanState",
    semaphore: asyncio.Semaphore,
) -> None:
    """Live-verify every confirmed finding, concurrently and bounded by `semaphore`
    (the same one already used for fetches and Gemini validation). Mutates
    `vf.verified` / `vf.verified_detail` on each finding in place.

    A deep scan can confirm dozens of findings across many hosts, and each verify
    call is its own network round-trip to a provider API — running them one at a
    time, as the original implementation did, was pure added wall-clock with no
    correctness benefit. Mirrors `_validate_one`/`validation_tasks` in `run_scan`:
    `state.check()` inside the task (so a stopped scan still cancels promptly) and
    `gather(return_exceptions=True)` with an explicit fallback so an unexpected
    failure leaves a finding as "unsupported" rather than ambiguous —
    `verify_finding_detailed` itself already fails closed to "unverified"/
    "unsupported" for ordinary provider errors, so anything landing here is a bug,
    not routine API flakiness.

    One divergence from that mirrored pattern, deliberately: `return_exceptions=True`
    does not propagate a `CancelledError` raised inside a gathered task — it is
    captured as a per-task result instead, same as any other exception. Left alone,
    a stopped scan would silently keep "verifying" (mutating findings from
    already-in-flight tasks) and return normally with no sign the scan had been
    cancelled — the STOP button doing nothing during this stage. So cancellation is
    detected and re-raised explicitly before the ordinary exception handling below
    ever sees it.
    """
    async def _verify_one(vf: "ValidatedFinding") -> None:
        state.check()
        async with semaphore:
            vres = await verifier.verify_finding_detailed(
                vf.raw.secret_type, vf.raw.raw_match, client
            )
        vf.verified = vres.status
        vf.verified_detail = vres.detail

    results = await asyncio.gather(
        *(_verify_one(vf) for vf in confirmed), return_exceptions=True
    )
    for res in results:
        if isinstance(res, asyncio.CancelledError):
            raise res
    for vf, res in zip(confirmed, results):
        if isinstance(res, Exception):
            logger.error(
                "Unexpected verification failure for %s: %s", vf.raw.secret_type, res
            )
            vf.verified = "unsupported"
            vf.verified_detail = ""


async def run_scan(
    target_url: str,
    scan_id: str | None = None,
    broadcast: Broadcaster | None = None,
    state: ScanState | None = None,
    known_fingerprints: frozenset[str] = frozenset(),
    suppressed_fingerprints: frozenset[str] = frozenset(),
    max_crawl_pages: int = 1,
    verify: bool | None = None,
    only_verified: bool = False,
    seed_urls: list[str] | None = None,
) -> dict[str, Any]:
    """
    Full pipeline:
      spider → extract → entropy-filter → gemini-validate → discord-alert
    Streams live events via broadcast(). Respects cooperative cancellation via state.

    known_fingerprints:      fingerprints seen in a *previous* scan of this same
                              target — used to mark each confirmed finding as
                              new (first time seen) vs recurring (still present).
    suppressed_fingerprints: fingerprints an operator has marked as a false
                              positive — these are filtered out entirely and
                              never re-alerted.
    max_crawl_pages:         number of same-domain HTML pages to crawl beyond
                              the initial target_url (1 = target page only).
    """
    scan_id = scan_id or str(uuid.uuid4())
    state   = state or ScanState()
    t0      = time.monotonic()

    # Reset the per-scan AI-disable latch (set if this scan hits a permanent AI
    # config error such as an invalid key or an unavailable model).
    global _ai_disabled_reason
    _ai_disabled_reason = None

    # Pacing learned from a previous target must not penalise this one.
    reset_throttle()

    # Likewise the cache-hit tally. It is module state (see _asset_cache_in), so
    # without this a scan that never primes the cache — every deep-scan host
    # takes that path — inherits the previous scan's count and reports assets it
    # never looked at. Only the tally is cleared: `load_asset_cache()` runs
    # before this and its priming must survive.
    _asset_cache_hits.clear()

    async def emit(event: dict[str, Any]) -> None:
        if broadcast:
            await broadcast(event)

    await emit({"type": "scan_start", "scan_id": scan_id, "target_url": target_url})
    await emit({"type": "log", "level": "INFO",
                "message": f"=== Scan {scan_id} started for {target_url} ==="})

    result: dict[str, Any] = {
        "scan_id":             scan_id,
        "target_url":         target_url,
        "status":             "running",
        "assets_fetched":     0,   # bodies downloaded this run
        "assets_cached":      0,   # skipped: unchanged since last scan and clean then
        "assets_scanned":     0,   # total coverage = fetched + cached
        "raw_findings":       0,
        "validated_findings": 0,
        "confirmed_findings": [],
        "needs_review_findings": [],
        # Public-by-design values (Stripe pk_, Sentry DSN, Firebase web apiKey).
        # Reported at INFO so the client can see the scanner examined them and
        # cleared them, rather than being unable to tell whether it looked.
        "informational_findings": [],
        "suppressed_count":   0,
        "new_findings_count": 0,
        "recurring_findings_count": 0,
        "verified_count": 0,
        "unverified_count": 0,
        "filtered_unverified_count": 0,
        "posture_findings":   [],
        "discovered_endpoints": [],   # slice 5: same-site URLs/paths referenced in JS/HTML
        "associated_hosts":   [],     # slice 4: external hosts the assets talk to
        "errors":             [],
        "duration_seconds":   0.0,
    }

    semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)

    async with build_client() as client:
        # ── 1. Spider ──────────────────────────────────────────────────────
        state.check()
        try:
            budget = _AssetBudget()
            assets = await spider_target(client, target_url, semaphore, broadcast,
                                         max_pages=max_crawl_pages, budget=budget)
        except asyncio.CancelledError:
            result["status"] = "cancelled"
            await emit({"type": "scan_cancelled", "scan_id": scan_id})
            return result
        except RootUnreachable as exc:
            # Expected and reportable, not a crash — no stack trace. What matters
            # is that `status` and `errors` say so, because that is what a deep
            # scan reads to decide whether this host counts as covered.
            result["status"] = "failed"
            result["errors"].append(str(exc))
            await emit({"type": "scan_error", "error": str(exc)})
            return result
        except Exception as exc:
            logger.exception("Fatal spider error")
            result["status"] = "failed"
            result["errors"].append(str(exc))
            await emit({"type": "scan_error", "error": str(exc)})
            return result

        # ── 1a. Inject seed assets (deep-ASM slice 3.5) ────────────────────
        # Externally-supplied URLs — e.g. historical JS bundles recovered from
        # public archives (Wayback/CommonCrawl) — that the live crawl would never
        # link to. Fetch any not already collected and add them to the scan set.
        if seed_urls:
            state.check()
            have = {u for u, _ in assets}
            to_fetch = [u for u in dict.fromkeys(seed_urls) if u not in have][:MAX_SEED_URLS]
            if to_fetch:
                await emit({
                    "type": "log", "level": "INFO",
                    "message": f"Fetching {len(to_fetch)} seed asset(s) from archives",
                })
                fetched = await asyncio.gather(
                    *(fetch_url(client, u, semaphore, broadcast) for u in to_fetch)
                )
                added = 0
                for u, body in fetched:
                    if _usable_body(body):
                        if budget.take(body):
                            assets.append((u, body))
                        added += 1
                await emit({
                    "type": "log", "level": "INFO",
                    "message": f"Added {added} seed asset(s) from archives ({len(to_fetch) - added} unreachable)",
                })

        # ── 1b. Surface intel + one-level deeper crawl (slices 5 & 4) ──────
        # Mine every fetched asset for referenced endpoints (JS-called URLs a live
        # crawl never links to) and external hosts (the associated-asset graph).
        # Then fetch same-site .js endpoints we don't already have, so code-
        # referenced bundles get secret-scanned too.
        if EXTRACT_SURFACE:
            state.check()
            base_host = urlparse(target_url).hostname or ""
            all_eps: set[str] = set()
            ext_hosts: set[str] = set()
            for src_url, body in list(assets):
                all_eps.update(surface.extract_endpoints(body, src_url))
                ext_hosts.update(surface.extract_referenced_hosts(body, src_url))
            same_eps, _assoc = surface.classify_endpoints(sorted(all_eps), base_host)

            have = {u.split("?", 1)[0] for u, _ in assets}
            js_eps = [
                e for e in same_eps
                if e.split("?", 1)[0].lower().endswith(".js") and e.split("?", 1)[0] not in have
            ][:MAX_ENDPOINT_SEEDS]
            if js_eps:
                await emit({
                    "type": "log", "level": "INFO",
                    "message": f"Deeper crawl: fetching {len(js_eps)} JS endpoint(s) referenced in code",
                })
                fetched = await asyncio.gather(
                    *(fetch_url(client, u, semaphore, broadcast) for u in js_eps)
                )
                for u, body in fetched:
                    if _usable_body(body):
                        if budget.take(body):
                            assets.append((u, body))

            result["discovered_endpoints"] = same_eps[:MAX_DISCOVERED_ENDPOINTS]
            # Scope-aware, not exact-string: `h != base_host` filed the target's
            # own apex under "third-party / connected infrastructure" in the
            # client report whenever the scan ran against www.
            result["associated_hosts"] = sorted(
                h for h in ext_hosts if h and not surface.same_scope(base_host, h)
            )
            if result["discovered_endpoints"] or result["associated_hosts"]:
                await emit({
                    "type": "log", "level": "INFO",
                    "message": (f"Surface intel: {len(result['discovered_endpoints'])} endpoint(s), "
                                f"{len(result['associated_hosts'])} associated host(s)"),
                })

        # The budget engaging means this scan deliberately read less than the
        # target offered. That is a coverage statement, and a coverage statement
        # belongs on the result rather than only in a log line nobody keeps.
        if budget.skipped:
            result["assets_skipped_over_budget"] = budget.skipped
            await emit({
                "type": "log", "level": "WARN",
                "message": (
                    f"Asset budget reached ({budget.limit // (1024 * 1024)} MB) — "
                    f"{budget.skipped} asset(s) fetched but not retained. Coverage "
                    f"is partial; raise MAX_TOTAL_ASSET_BYTES to scan them."
                ),
            })

        # Three distinct numbers, because conflating them misreports coverage:
        #   assets_fetched — bodies actually downloaded this run
        #   assets_cached  — unchanged since last scan and clean then, so skipped
        #   assets_scanned — total coverage, and the number a report should lead
        #                    with. A fully-cached re-scan downloads nothing; saying
        #                    "0 assets" would describe that as having scanned
        #                    nothing, when in fact every asset was accounted for.
        cached = cached_clean_count()
        result["assets_fetched"] = len(assets)
        result["assets_cached"] = cached
        result["assets_scanned"] = len(assets) + cached
        await emit({
            "type": "log", "level": "INFO",
            "message": (f"Asset collection complete — {len(assets)} file(s) to scan"
                        + (f", {cached} unchanged since last scan (cached)" if cached else "")),
        })

        # ── 1b. Passive security-posture check (R8) ─────────────────────────
        # Analyse the target root's own response headers for missing/weak
        # security controls. Best-effort: never blocks or fails the scan.
        if SCAN_HTTP_POSTURE:
            state.check()
            # Inject the validated hop-walk so posture measures the page a
            # visitor lands on, not a 301 pointing at it. The same walk the
            # fetch path uses, so a redirect into internal space is refused here
            # too rather than being read for headers.
            pfindings = await posture.fetch_posture(
                client, target_url, get_final=_get_following_redirects,
            )
            result["posture_findings"] = [p.to_dict() for p in pfindings]
            if pfindings:
                await emit({
                    "type": "log", "level": "INFO",
                    "message": f"Security posture: {len(pfindings)} header/misconfiguration issue(s) found",
                })

        # ── 2. Regex Extraction ────────────────────────────────────────────
        state.check()
        all_raw: list[RawFinding] = []
        for source_url, body in assets:
            state.check()

            # ── R5: for a source map, scan its DECODED original source instead of
            # the raw .map JSON. Better per-file attribution, catches secrets that
            # are escaped/structured in the raw JSON, and avoids the map's own
            # high-entropy "mappings" VLQ blob (a false-positive source). Falls
            # back to scanning the raw body if there's no usable sourcesContent.
            if SCAN_SOURCEMAP_CONTENT and looks_like_sourcemap(source_url, body):
                groups = scan_asset(scan_id, target_url, source_url, body)
                if not (len(groups) == 1 and groups[0][0] == source_url):
                    for vsrc_url, sfound in groups:
                        state.check()
                        if sfound:
                            await emit({
                                "type": "log", "level": "WARN",
                                "message": f"Found {len(sfound)} match(es) in source-map original {vsrc_url}",
                            })
                        all_raw.extend(sfound)
                    continue

            found = extract_secrets(scan_id, target_url, source_url, body)
            if found:
                # This asset yielded something: a future 304 must refetch it
                # rather than skip, so the finding cannot silently disappear.
                mark_asset_dirty(source_url)
                await emit({
                    "type": "log", "level": "WARN",
                    "message": f"Found {len(found)} potential match(es) in {source_url}",
                })
            all_raw.extend(found)

        result["raw_findings"] = len(all_raw)
        if len(all_raw) > MAX_RAW_FINDINGS_PER_SCAN:
            await emit({
                "type": "log", "level": "WARN",
                "message": (
                    f"Raw candidate count ({len(all_raw)}) exceeds safety cap "
                    f"({MAX_RAW_FINDINGS_PER_SCAN}) — validating the first "
                    f"{MAX_RAW_FINDINGS_PER_SCAN} only. This usually means a target "
                    f"asset has abnormal high-entropy noise (obfuscated/minified bundle); "
                    f"consider raising MIN_ENTROPY_THRESHOLD or excluding that asset."
                ),
            })
            result["errors"].append(
                f"Truncated raw findings to {MAX_RAW_FINDINGS_PER_SCAN} of {len(all_raw)}"
            )
            all_raw = all_raw[:MAX_RAW_FINDINGS_PER_SCAN]

        await emit({
            "type": "log", "level": "INFO",
            "message": f"Regex scan complete — {len(all_raw)} raw candidates (entropy-filtered)",
        })
        await emit({"type": "raw_count", "count": len(all_raw)})

        if not all_raw:
            result["status"] = "clean"
            result["duration_seconds"] = round(time.monotonic() - t0, 2)
            await emit({
                "type": "scan_complete",
                "scan_id": scan_id,
                "result": result,
            })
            return result

        # ── 3. Gemini Validation ───────────────────────────────────────────
        state.check()
        await emit({"type": "status", "stage": "validating",
                    "total": len(all_raw)})

        async def _validate_one(f: RawFinding) -> ValidatedFinding:
            state.check()
            async with semaphore:
                return await validate_with_gemini(f, broadcast)

        validation_tasks = [_validate_one(f) for f in all_raw]
        validated_raw = await asyncio.gather(*validation_tasks, return_exceptions=True)

        # gather(return_exceptions=True) does not propagate a CancelledError raised
        # inside a task — it lands in validated_raw as an ordinary result, same as
        # any other exception. Left unhandled, the loop below would treat a
        # user-requested STOP mid-validation as "an unexpected validation error"
        # for every remaining item and keep going, so the STOP button would do
        # nothing during this stage. Detect and re-raise it before that loop runs.
        for v in validated_raw:
            if isinstance(v, asyncio.CancelledError):
                raise v

        validated: list[ValidatedFinding] = []
        for f, v in zip(all_raw, validated_raw):
            if isinstance(v, ValidatedFinding):
                validated.append(v)
            else:
                # asyncio.gather caught an exception our own retry loop didn't —
                # e.g. a cancellation or an unexpected bug. Still don't drop it.
                logger.error("Unexpected validation failure for %s: %s", f.secret_type, v)
                validated.append(ValidatedFinding(
                    raw=f,
                    is_valid=False,
                    confidence=NEEDS_REVIEW_SENTINEL,
                    reason=f"Unexpected validation error: {v}. Manual review required.",
                ))

        _routed = [(classify_validated(v), v) for v in validated]
        confirmed: list[ValidatedFinding] = [v for b, v in _routed if b == "confirmed"]
        needs_review: list[ValidatedFinding] = [v for b, v in _routed if b == "review"]
        informational: list[ValidatedFinding] = [v for b, v in _routed if b == "informational"]

        # ── Suppress known false positives ──────────────────────────────
        if suppressed_fingerprints:
            pre_suppress = len(confirmed)
            confirmed = [v for v in confirmed if v.raw.fingerprint not in suppressed_fingerprints]
            needs_review = [v for v in needs_review if v.raw.fingerprint not in suppressed_fingerprints]
            informational = [
                v for v in informational if v.raw.fingerprint not in suppressed_fingerprints
            ]
            result["suppressed_count"] = pre_suppress - len(confirmed)
            if result["suppressed_count"]:
                await emit({
                    "type": "log", "level": "INFO",
                    "message": f"Suppressed {result['suppressed_count']} finding(s) previously marked as false positive.",
                })

        # ── 3b. Optional live verification (off by default) ─────────────────
        # Read-only "is this credential still active?" checks against each
        # secret's own provider (never the target). Eliminates dead-key noise.
        #
        # This runs BEFORE the scan-to-scan diff, because it can change which
        # bucket a finding is in and the diff has to describe the final answer.
        do_verify = VERIFY_SECRETS if verify is None else verify

        # Review findings with a verifier are checked too, not just confirmed
        # ones. A provider answering "yes, this key works" is the strongest
        # evidence this tool can obtain — stronger than any model's opinion,
        # because it is an observation rather than a judgement. Leaving that
        # evidence ungathered for exactly the findings nobody could judge was
        # backwards, and it made the offline mode structurally incapable of
        # confirming anything: with no Gemini key every finding lands in review,
        # review was never verified, so the Confirmed table was always empty no
        # matter how many live credentials the scan had actually found.
        verifiable_review = [
            v for v in needs_review if verifier.is_supported(v.raw.secret_type)
        ] if do_verify else []

        to_verify = confirmed + verifiable_review
        if do_verify and to_verify:
            await emit({"type": "status", "stage": "verifying", "total": len(to_verify)})
            await emit({
                "type": "log", "level": "WARN",
                "message": (
                    f"[VERIFY] Live-verifying {len(confirmed)} confirmed"
                    + (f" and {len(verifiable_review)} needs-review" if verifiable_review else "")
                    + " finding(s) against provider APIs (read-only). Authorized use only."
                ),
            })
            await verify_confirmed_findings(to_verify, client, state, semaphore)

            # Promote on evidence. A verified-active credential is confirmed by
            # the provider itself; it does not also need a model to agree.
            promoted = [v for v in verifiable_review if v.verified == "verified"]
            if promoted:
                confirmed = confirmed + promoted
                promoted_fps = {v.raw.fingerprint for v in promoted}
                needs_review = [v for v in needs_review if v.raw.fingerprint not in promoted_fps]
                result["promoted_by_verification_count"] = len(promoted)
                await emit({
                    "type": "log", "level": "ERROR",
                    "message": (
                        f"[VERIFY] {len(promoted)} needs-review finding(s) confirmed ACTIVE by "
                        f"the provider — promoted to confirmed on evidence."
                    ),
                })

            result["verified_count"]   = sum(1 for v in confirmed if v.verified == "verified")
            result["unverified_count"] = sum(1 for v in confirmed if v.verified == "unverified")
            await emit({
                "type": "log",
                "level": "ERROR" if result["verified_count"] else "INFO",
                "message": (
                    f"[VERIFY] {result['verified_count']} ACTIVE, "
                    f"{result['unverified_count']} inactive/unconfirmed, "
                    f"{sum(1 for v in confirmed if v.verified == 'unsupported')} unsupported"
                ),
            })
            if only_verified:
                # Keep verified + unsupported (can't auto-check); drop confirmed-inactive.
                before = len(confirmed)
                confirmed = [v for v in confirmed if v.verified != "unverified"]
                result["filtered_unverified_count"] = before - len(confirmed)

        # ── Diff against the previous scan of this same target ─────────────
        # After verification, so a finding promoted on live evidence is diffed
        # like any other confirmed finding rather than missing from the counts.
        for v in confirmed:
            v.is_new = v.raw.fingerprint not in known_fingerprints
        result["new_findings_count"] = sum(1 for v in confirmed if v.is_new)
        result["recurring_findings_count"] = len(confirmed) - result["new_findings_count"]
        if known_fingerprints:
            await emit({
                "type": "log", "level": "INFO",
                "message": (
                    f"Diff vs previous scan: {result['new_findings_count']} new, "
                    f"{result['recurring_findings_count']} recurring"
                ),
            })

        result["validated_findings"] = len(validated)
        await emit({
            "type": "log", "level": "INFO",
            "message": (
                f"Validation done — {len(confirmed)}/{len(all_raw)} confirmed "
                f"(confidence ≥ {GEMINI_CONFIDENCE_MIN}%)"
                + (f", {len(needs_review)} flagged for manual review" if needs_review else "")
                + (f", {len(informational)} public-by-design (INFO)" if informational else "")
            ),
        })

        # ── 4. Broadcast Confirmed + Needs-Review + Informational ─────────
        for vf in confirmed:
            await emit({
                "type": "finding",
                "data": vf.to_dict(),
            })
        for vf in needs_review:
            await emit({
                "type": "finding_needs_review",
                "data": vf.to_dict(),
            })
        # Emitted at INFO, and deliberately without a toast: a public-by-design
        # value needs no attention, and an alert that needs no action is how an
        # operator learns to dismiss alerts. It belongs in the log so the run is
        # legible after the fact, and in the report so the client can see it was
        # examined.
        for vf in informational:
            await emit({
                "type": "finding_informational",
                "data": vf.to_dict(),
            })

        # ── 5. Discord Alerts ─────────────────────────────────────────────
        # Confirmed findings always alert. Needs-review findings only alert
        # when the underlying regex pattern is CRITICAL severity — those are
        # the ones most likely to be a real, live credential, so a human
        # should not have to notice them buried in the dashboard. Recurring
        # findings (already alerted on a prior scan) are skipped to avoid
        # spamming Discord on every re-scan of a long-lived target.
        critical_unreviewed = [
            v for v in needs_review
            if SECRET_TYPE_SEVERITY.get(v.raw.secret_type) == "CRITICAL"
        ]
        to_alert = [v for v in confirmed if v.is_new] + critical_unreviewed
        if to_alert:
            await emit({
                "type": "log", "level": "INFO",
                "message": f"Dispatching {len(to_alert)} Discord alert(s)…",
            })
            discord_tasks = [
                dispatch_discord(client, vf, semaphore, broadcast)
                for vf in to_alert
            ]
            await asyncio.gather(*discord_tasks, return_exceptions=True)

        # ── 6. Finalise ────────────────────────────────────────────────────
        result["confirmed_findings"]    = [vf.to_dict() for vf in confirmed]
        result["needs_review_findings"] = [vf.to_dict() for vf in needs_review]
        result["informational_findings"] = [vf.to_dict() for vf in informational]
        result["status"]             = "complete"
        result["duration_seconds"]   = round(time.monotonic() - t0, 2)

        await emit({
            "type": "log", "level": "INFO",
            "message": (
                f"=== Scan complete — {len(confirmed)} confirmed findings "
                f"in {result['duration_seconds']:.2f}s ==="
            ),
        })
        await emit({"type": "scan_complete", "scan_id": scan_id, "result": result})

    return result
