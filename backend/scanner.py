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
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine
from urllib.parse import urljoin, urlparse

import httpx
from google import genai
from google.genai import errors as genai_errors, types
from pydantic import BaseModel, Field, ValidationError

import posture
import surface
import verifier

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
_LEGACY_MODEL              = os.environ.get("GEMINI_MODEL", "").strip()
GEMINI_TIER1_MODEL: str    = os.environ.get("GEMINI_TIER1_MODEL", _LEGACY_MODEL or "gemini-3.1-flash-lite")
GEMINI_TIER2_MODEL: str    = os.environ.get("GEMINI_TIER2_MODEL", "gemini-3.5-flash")
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
    #     fixed-format hex/UUID tokens) are high-precision by shape. They get
    #     only a LOW anti-degenerate floor (MIN_STRUCTURAL_ENTROPY) that rejects
    #     obvious junk like "AKIAAAAAAAAAAAAAAAAA" while still catching genuinely
    #     modest-entropy live keys — because gating these on the full generic bar
    #     silently drops real credentials (a false negative, the worst failure).
    #   • The generic keyword=value catch-all matches loosely and needs the full
    #     MIN_ENTROPY_THRESHOLD randomness signal to stay quiet; it opts in below.
    entropy_gated: bool = False


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
        return {
            "fingerprint":    self.raw.fingerprint,
            "scan_id":        self.raw.scan_id,
            "target_url":     self.raw.target_url,
            "source_url":     self.raw.source_url,
            "secret_type":    self.raw.secret_type,
            "raw_match":      self.raw.raw_match[:80] + "…" if len(self.raw.raw_match) > 80 else self.raw.raw_match,
            "context_snippet": self.raw.context_snippet[:400],
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
        }

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

SECRET_PATTERNS: list[SecretPattern] = [
    SecretPattern(
        name="AWS Access Key",
        regex=re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        description="AWS IAM Access Key ID",
        severity="CRITICAL",
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
        regex=re.compile(r"\b(sk_live_[0-9a-zA-Z]{24,})\b"),
        description="Stripe Live Secret Key",
        severity="CRITICAL",
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
        name="Generic High-Entropy Secret",
        regex=re.compile(
            r"(?i)(?:api[_-]?key|secret|token|password|passwd|auth)\s*[=:]\s*['\"]([A-Za-z0-9\-_.~+/]{20,80})['\"]"
        ),
        description="Generic credential assignment",
        severity="MEDIUM",
        entropy_gated=True,   # loose keyword=value match — entropy keeps it quiet
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
        name="GitLab Personal Access Token",
        regex=re.compile(r"\b(glpat-[0-9A-Za-z_\-]{20})\b"),
        description="GitLab personal access token",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="OpenAI API Key",
        regex=re.compile(r"\b(sk-(?:proj-)?[A-Za-z0-9_\-]{20}T3BlbkFJ[A-Za-z0-9_\-]{20})\b"),
        description="OpenAI API key (project or user)",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="Anthropic API Key",
        regex=re.compile(r"\b(sk-ant-[A-Za-z0-9_\-]{20,})\b"),
        description="Anthropic (Claude) API key",
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
        regex=re.compile(r"\b(https?://[^:@/\s]+:[^@/\s]{3,}@[^\s'\"<>]+)"),
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
        regex=re.compile(r"(-----BEGIN PGP PRIVATE KEY BLOCK-----)"),
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
        follow_redirects=True,
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


async def fetch_url(
    client: httpx.AsyncClient,
    url: str,
    semaphore: asyncio.Semaphore,
    broadcast: Broadcaster | None = None,
) -> tuple[str, str | None]:
    """
    Fetch a URL with retry + exponential backoff.

    Resilience for authorized testing (v2.4.0): on a WAF/CDN challenge
    (401/403/406/429/503) we retry with a different browser fingerprint before
    giving up, and emit a diagnostic that names the likely cause instead of a
    bare "failed". Respects 429 Retry-After. Returns (url, body) or (url, None).
    """
    async with semaphore:
        waf_block_status: int | None = None
        for attempt in range(1, RETRY_ATTEMPTS + 1):
            try:
                if broadcast:
                    await broadcast({
                        "type": "log",
                        "level": "INFO",
                        "message": f"Fetching [{attempt}/{RETRY_ATTEMPTS}]: {url}",
                    })
                # Rotate the browser fingerprint on retries after a WAF block —
                # some edges let a different UA through.
                extra_headers = None
                if attempt > 1 and waf_block_status and not _UA_OVERRIDE:
                    extra_headers = _browser_headers(_USER_AGENTS[(attempt - 1) % len(_USER_AGENTS)])
                response = await client.get(url, headers=extra_headers)

                if response.status_code == 429:
                    retry_after = float(
                        response.headers.get("Retry-After", 10 * attempt)
                    )
                    if broadcast:
                        await broadcast({
                            "type": "log",
                            "level": "WARN",
                            "message": f"429 rate-limited on {url} — backing off {retry_after:.0f}s",
                        })
                    await asyncio.sleep(min(retry_after, 30.0))
                    continue

                if response.status_code in (404, 410):
                    return url, None

                if response.status_code in _WAF_BLOCK_CODES:
                    waf_block_status = response.status_code
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
                        await asyncio.sleep(RETRY_BACKOFF_BASE ** attempt)
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
                    return url, None

                response.raise_for_status()

                cl = int(response.headers.get("content-length", 0))
                if cl > MAX_ASSET_BYTES:
                    if broadcast:
                        await broadcast({
                            "type": "log",
                            "level": "WARN",
                            "message": f"Skipping oversized asset ({cl/1024/1024:.1f} MB): {url}",
                        })
                    return url, None

                if not _looks_scannable(response.headers.get("content-type", "")):
                    return url, None

                # Guard against a chunked/undeclared body that exceeds the cap.
                text = response.text
                if len(text) > MAX_ASSET_BYTES:
                    return url, text[:MAX_ASSET_BYTES]
                return url, text

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
                backoff = RETRY_BACKOFF_BASE ** attempt
                await asyncio.sleep(backoff)

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
_LINK_IS_SCRIPT_RE = re.compile(
    r'\brel=["\']?(?:modulepreload|preload)\b|\bas=["\']?script\b|href=["\'][^"\']+\.js["\']',
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


def _same_scope(base_host: str, candidate_host: str) -> bool:
    """True if candidate_host is the same registrable domain as base_host
    (exact match or a subdomain of it). Keeps scans inside the authorized
    target instead of silently fetching third-party CDNs/analytics domains."""
    base_host = base_host.lower().lstrip("www.")
    candidate_host = candidate_host.lower()
    return candidate_host == base_host or candidate_host.endswith("." + base_host)


def _accept_asset(raw: str, base_url: str, base_host: str, seen: set[str]) -> str | None:
    """Absolutise + scope-check a discovered asset URL. Returns the absolute URL
    to keep, or None to skip (already seen, out of scope, or non-http)."""
    raw = raw.strip()
    if not raw or raw.startswith(("data:", "blob:")):
        return None
    absolute = urljoin(base_url, raw)
    p = urlparse(absolute)
    if p.scheme not in ("http", "https") or absolute in seen:
        return None
    if SCOPE_SAME_DOMAIN and not _same_scope(base_host, p.hostname or ""):
        return None
    seen.add(absolute)
    return absolute


def extract_js_urls(html: str, base_url: str) -> list[str]:
    """Absolutise all JS asset URLs discovered in the HTML: <script src>,
    <script type=module src>, and script-ish <link> tags (modulepreload,
    preload as=script, or an explicit .js href). By default only keeps assets
    on the same domain as base_url (SCOPE_SAME_DOMAIN=true) so the scanner
    doesn't fan out to unrelated third-party hosts."""
    seen: set[str] = set()
    result: list[str] = []
    base_host = urlparse(base_url).hostname or ""
    for m in _SCRIPT_SRC_RE.finditer(html):
        absolute = _accept_asset(m.group(1), base_url, base_host, seen)
        if absolute:
            result.append(absolute)
    for m in _LINK_JS_RE.finditer(html):
        if not _LINK_IS_SCRIPT_RE.search(m.group(0)):
            continue
        absolute = _accept_asset(m.group(1), base_url, base_host, seen)
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
    """
    parsed = urlparse(target_url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    try:
        resp = await client.get(robots_url, timeout=10.0)
        if resp.status_code != 200:
            return True
        body = resp.text[:5000]
        disallow_root = bool(re.search(r"(?im)^disallow:\s*/\s*$", body))
        if disallow_root and broadcast:
            await broadcast({
                "type": "log", "level": "WARN",
                "message": (
                    "Target's robots.txt disallows all crawling (Disallow: /). "
                    "Proceeding — this is an authorized security scan, not a "
                    "generic crawler — but flagging for awareness."
                ),
            })
        return True
    except Exception:
        return True  # robots.txt missing/unreachable is not an error condition


async def spider_target(
    client: httpx.AsyncClient,
    target_url: str,
    semaphore: asyncio.Semaphore,
    broadcast: Broadcaster | None = None,
    max_pages: int = 1,
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

    root_url, html_body = await fetch_url(client, target_url, semaphore, broadcast)
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
        return []

    assets: list[tuple[str, str]] = [(root_url, html_body)]
    html_pages: list[tuple[str, str]] = [(root_url, html_body)]
    visited_pages: set[str] = {root_url}
    all_js_urls: set[str] = set(extract_js_urls(html_body, target_url))

    # ── Shallow same-domain crawl for additional HTML pages ─────────────────
    if max_pages > 1:
        queue = [u for u in extract_page_links(html_body, target_url) if u not in visited_pages]
        while queue and len(visited_pages) < max_pages:
            batch = queue[: max_pages - len(visited_pages)]
            queue = queue[len(batch):]
            fetch_tasks = [fetch_url(client, u, semaphore, broadcast) for u in batch]
            fetched_pages = await asyncio.gather(*fetch_tasks, return_exceptions=False)
            for page_url, page_body in fetched_pages:
                visited_pages.add(page_url)
                if not page_body:
                    continue
                html_pages.append((page_url, page_body))
                assets.append((page_url, page_body))
                for js in extract_js_urls(page_body, page_url):
                    all_js_urls.add(js)
        if broadcast and len(visited_pages) > 1:
            await broadcast({
                "type": "log", "level": "INFO",
                "message": f"Crawled {len(visited_pages)} same-domain page(s): {', '.join(sorted(visited_pages))[:300]}",
            })

    js_urls = sorted(all_js_urls)
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
            if js_body:
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
                if map_body:
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
})
_PLACEHOLDER_RE = re.compile(
    r"(?i)(your[_-]?(?:api|key|token|secret|id)|placeholder|changeme|"
    r"redacted|x{8,}|0{8,}|<[^>]{2,}>)"
)
_B64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_MAX_B64_BLOBS = 200


def is_benign_placeholder(value: str) -> bool:
    """True if a matched value is a known documentation example or an obvious
    placeholder. Filtering these out is a standard false-positive-reduction step."""
    return value in _KNOWN_EXAMPLE_SECRETS or bool(_PLACEHOLDER_RE.search(value))


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
    for pattern in SECRET_PATTERNS:
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
            # Generic keyword=value catch-all must clear the full randomness bar;
            # structural detectors only need to clear a low anti-degenerate floor
            # so genuinely modest-entropy live keys are not silently dropped.
            floor = MIN_ENTROPY_THRESHOLD if pattern.entropy_gated else MIN_STRUCTURAL_ENTROPY
            if entropy < floor:
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


def extract_secrets(
    scan_id: str,
    target_url: str,
    source_url: str,
    text: str,
) -> list[RawFinding]:
    findings = _scan_text(scan_id, target_url, source_url, text)
    # Also inspect base64-decoded blobs for secrets hidden inside encoded strings.
    for decoded in _decode_base64_blobs(text):
        findings.extend(_scan_text(scan_id, target_url, source_url, decoded, decoded=True))
    # De-duplicate by fingerprint (same secret found raw and base64-encoded = one finding).
    seen: set[str] = set()
    unique: list[RawFinding] = []
    for f in findings:
        fp = f.fingerprint
        if fp in seen:
            continue
        seen.add(fp)
        unique.append(f)
    return unique


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
    model). The finding is returned unvalidated (confidence 50) rather than flooding
    needs-review with one scary item per finding — the root cause is surfaced once."""
    return ValidatedFinding(raw=finding, is_valid=True, confidence=50, reason=reason)


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
        return ValidatedFinding(
            raw=finding,
            is_valid=True,
            confidence=50,
            reason="AI validation skipped — GEMINI_API_KEY not configured.",
        )

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

_SEVERITY_COLORS: dict[str, int] = {
    "AWS Access Key":              0xE53E3E,
    "AWS Secret Access Key":       0xE53E3E,
    "GitHub Personal Access Token":0xE53E3E,
    "Stripe Secret Key":           0xE53E3E,
    "Private Key Block":           0xE53E3E,
    "Google Cloud API Key":        0xDD6B20,
    "GitHub OAuth Token":          0xDD6B20,
    "Slack Webhook":               0xD69E2E,
    "SendGrid API Key":            0xDD6B20,
    "Twilio Auth Token":           0xDD6B20,
    "Heroku API Key":              0xDD6B20,
    "Shopify Access Token":        0xDD6B20,
    "Mailgun API Key":             0xDD6B20,
    "JWT Token":                   0xD69E2E,
    "Stripe Publishable Key":      0x3182CE,
    "Generic High-Entropy Secret": 0xD69E2E,
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
    color = _SEVERITY_COLORS.get(raw.secret_type, 0xE53E3E)
    safe_snippet_full = redact_snippet(raw.context_snippet, raw.raw_match)
    snippet = (
        safe_snippet_full[:900] + "…"
        if len(safe_snippet_full) > 900
        else safe_snippet_full
    )
    redacted = redact_secret(raw.raw_match)

    payload = {
        "username": "SecretNode v2.4.0",
        "avatar_url": "https://cdn-icons-png.flaticon.com/512/2092/2092757.png",
        "embeds": [{
            "title": f"🚨 Secret Exposed: {raw.secret_type}",
            "color": color,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "footer": {"text": "SecretNode v2.4.0 — ASM Scanner"},
            "fields": [
                {"name": "🎯 Target",        "value": f"`{raw.target_url}`",      "inline": False},
                {"name": "📄 Source Asset",  "value": f"`{raw.source_url}`",      "inline": False},
                {"name": "🔑 Secret Type",   "value": raw.secret_type,            "inline": True},
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
    """Route a validated finding to exactly one of: 'confirmed', 'review', 'drop'.

    The critical rule is the last one: a *structural/provider* match (high-precision
    by shape — AKIA…, ghp_…, sk_live_…, PEM) that the AI did **not confidently
    dismiss** is sent to manual review, never silently dropped. Without this, a real
    live key the AI merely under-called on (e.g. because a page gave it no
    surrounding context) would vanish with no trace — a false negative, the worst
    failure mode for a scanner. The generic keyword=value catch-all keeps the old
    aggressive behaviour (an AI 'no' there is trusted and dropped), preserving the
    'no false positives in Confirmed' promise."""
    if v.confidence == NEEDS_REVIEW_SENTINEL:
        return "review"                                    # AI unavailable — human decides
    if v.is_valid and v.confidence >= GEMINI_CONFIDENCE_MIN:
        return "confirmed"
    meta = PATTERN_BY_NAME.get(v.raw.secret_type)
    structural = meta is not None and not meta.entropy_gated
    ai_confidently_dismissed = (not v.is_valid) and v.confidence >= GEMINI_CONFIDENCE_MIN
    if structural and not ai_confidently_dismissed:
        return "review"        # shape-anchored + AI not sure it's fake → human confirms
    return "drop"


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
        "assets_fetched":     0,
        "raw_findings":       0,
        "validated_findings": 0,
        "confirmed_findings": [],
        "needs_review_findings": [],
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
            assets = await spider_target(client, target_url, semaphore, broadcast, max_pages=max_crawl_pages)
        except asyncio.CancelledError:
            result["status"] = "cancelled"
            await emit({"type": "scan_cancelled", "scan_id": scan_id})
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
                    if body:
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
                    if body:
                        assets.append((u, body))

            result["discovered_endpoints"] = same_eps[:MAX_DISCOVERED_ENDPOINTS]
            result["associated_hosts"] = sorted(h for h in ext_hosts if h and h != base_host)
            if result["discovered_endpoints"] or result["associated_hosts"]:
                await emit({
                    "type": "log", "level": "INFO",
                    "message": (f"Surface intel: {len(result['discovered_endpoints'])} endpoint(s), "
                                f"{len(result['associated_hosts'])} associated host(s)"),
                })

        result["assets_fetched"] = len(assets)
        await emit({
            "type": "log", "level": "INFO",
            "message": f"Asset collection complete — {len(assets)} files to scan",
        })

        # ── 1b. Passive security-posture check (R8) ─────────────────────────
        # Analyse the target root's own response headers for missing/weak
        # security controls. Best-effort: never blocks or fails the scan.
        if SCAN_HTTP_POSTURE:
            state.check()
            pfindings = await posture.fetch_posture(client, target_url)
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
                srcs = extract_sourcemap_sources(body, source_url)
                if srcs:
                    for vsrc_url, content in srcs:
                        state.check()
                        sfound = extract_secrets(scan_id, target_url, vsrc_url, content)
                        if sfound:
                            await emit({
                                "type": "log", "level": "WARN",
                                "message": f"Found {len(sfound)} match(es) in source-map original {vsrc_url}",
                            })
                        all_raw.extend(sfound)
                    continue

            found = extract_secrets(scan_id, target_url, source_url, body)
            if found:
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

        # ── Suppress known false positives ──────────────────────────────
        if suppressed_fingerprints:
            pre_suppress = len(confirmed)
            confirmed = [v for v in confirmed if v.raw.fingerprint not in suppressed_fingerprints]
            needs_review = [v for v in needs_review if v.raw.fingerprint not in suppressed_fingerprints]
            result["suppressed_count"] = pre_suppress - len(confirmed)
            if result["suppressed_count"]:
                await emit({
                    "type": "log", "level": "INFO",
                    "message": f"Suppressed {result['suppressed_count']} finding(s) previously marked as false positive.",
                })

        # ── Diff against the previous scan of this same target ─────────────
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
                f"AI validation done — {len(confirmed)}/{len(all_raw)} confirmed "
                f"(confidence ≥ {GEMINI_CONFIDENCE_MIN}%)"
                + (f", {len(needs_review)} flagged for manual review" if needs_review else "")
            ),
        })

        # ── 3b. Optional live verification (off by default) ─────────────────
        # Read-only "is this credential still active?" checks against each
        # secret's own provider (never the target). Eliminates dead-key noise.
        do_verify = VERIFY_SECRETS if verify is None else verify
        if do_verify and confirmed:
            await emit({"type": "status", "stage": "verifying", "total": len(confirmed)})
            await emit({
                "type": "log", "level": "WARN",
                "message": (
                    f"[VERIFY] Live-verifying {len(confirmed)} confirmed finding(s) against "
                    f"provider APIs (read-only). Authorized use only."
                ),
            })
            for vf in confirmed:
                state.check()
                _vres = await verifier.verify_finding_detailed(
                    vf.raw.secret_type, vf.raw.raw_match, client
                )
                vf.verified = _vres.status
                vf.verified_detail = _vres.detail
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
                # keep new/recurring counts consistent with the filtered set
                result["new_findings_count"] = sum(1 for v in confirmed if v.is_new)
                result["recurring_findings_count"] = len(confirmed) - result["new_findings_count"]

        # ── 4. Broadcast Confirmed + Needs-Review Findings ────────────────
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
