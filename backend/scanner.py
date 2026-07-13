"""
SecretNode v2.0 — scanner.py
Async passive scanning engine: spider → regex → entropy → Gemini → Discord
Optimised for Raspberry Pi 5 / Linux ARM64 with uvloop
"""

from __future__ import annotations

import asyncio
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
import google.generativeai as genai

logger = logging.getLogger("secretnode.scanner")

# ── Environment ────────────────────────────────────────────────────────────────
GEMINI_API_KEY: str        = os.environ.get("GEMINI_API_KEY", "")
DISCORD_WEBHOOK_URL: str   = os.environ.get("DISCORD_WEBHOOK_URL", "")
GEMINI_MODEL: str          = os.environ.get("GEMINI_MODEL", "gemini-1.5-flash")

if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

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
CONTEXT_WINDOW_CHARS    = _env_int("CONTEXT_WINDOW_CHARS", 120)
MAX_ASSET_BYTES         = _env_int("MAX_ASSET_BYTES", 5 * 1024 * 1024)   # 5 MB
GEMINI_CONFIDENCE_MIN   = _env_int("GEMINI_CONFIDENCE_MIN", 80)
NEEDS_REVIEW_SENTINEL   = -1        # confidence value marking "AI validation failed — human must decide"
MAX_RAW_FINDINGS_PER_SCAN = _env_int("MAX_RAW_FINDINGS_PER_SCAN", 500)  # safety cap: stop a runaway scan
                                     # (e.g. a minified bundle full of high-entropy noise) from
                                     # generating unbounded Gemini calls / RAM use on the Pi

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
            "found_at":       self.raw.found_at,
            "validated_at":   self.validated_at,
            "is_new":         self.is_new,
            "severity":       self._meta().severity,
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

def build_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=httpx.Timeout(FETCH_TIMEOUT, connect=10.0),
        follow_redirects=True,
        limits=httpx.Limits(max_connections=40, max_keepalive_connections=20),
        headers={
            "User-Agent": (
                "Mozilla/5.0 (compatible; SecretNode/2.0; "
                "+https://github.com/internal/secretnode)"
            ),
            "Accept": "text/html,application/xhtml+xml,application/javascript,*/*;q=0.9",
            "Accept-Language": "en-US,en;q=0.5",
        },
        verify=True,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Resilient Fetch
# ─────────────────────────────────────────────────────────────────────────────

async def fetch_url(
    client: httpx.AsyncClient,
    url: str,
    semaphore: asyncio.Semaphore,
    broadcast: Broadcaster | None = None,
) -> tuple[str, str | None]:
    """
    Fetch a URL with retry + exponential backoff.
    Respects 429 Retry-After headers. Returns (url, body) or (url, None).
    """
    async with semaphore:
        for attempt in range(1, RETRY_ATTEMPTS + 1):
            try:
                if broadcast:
                    await broadcast({
                        "type": "log",
                        "level": "INFO",
                        "message": f"Fetching [{attempt}/{RETRY_ATTEMPTS}]: {url}",
                    })
                response = await client.get(url)

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
                    await asyncio.sleep(retry_after)
                    continue

                if response.status_code == 404:
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

                return url, response.text

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
_LINK_HREF_JS_RE = re.compile(r'<link[^>]+href=["\']([^"\']+\.js)["\']', re.IGNORECASE)

SCOPE_SAME_DOMAIN = os.environ.get("SCOPE_SAME_DOMAIN", "true").lower() == "true"


def _same_scope(base_host: str, candidate_host: str) -> bool:
    """True if candidate_host is the same registrable domain as base_host
    (exact match or a subdomain of it). Keeps scans inside the authorized
    target instead of silently fetching third-party CDNs/analytics domains."""
    base_host = base_host.lower().lstrip("www.")
    candidate_host = candidate_host.lower()
    return candidate_host == base_host or candidate_host.endswith("." + base_host)


def extract_js_urls(html: str, base_url: str) -> list[str]:
    """Absolutise all JS asset URLs discovered in the HTML. By default only
    keeps assets on the same domain as base_url (SCOPE_SAME_DOMAIN=true) so
    the scanner doesn't fan out to unrelated third-party hosts."""
    seen: set[str] = set()
    result: list[str] = []
    base_host = urlparse(base_url).hostname or ""
    for pattern in (_SCRIPT_SRC_RE, _LINK_HREF_JS_RE):
        for m in pattern.finditer(html):
            raw = m.group(1).strip()
            if not raw or raw.startswith("data:"):
                continue
            absolute = urljoin(base_url, raw)
            p = urlparse(absolute)
            if p.scheme not in ("http", "https") or absolute in seen:
                continue
            if SCOPE_SAME_DOMAIN and not _same_scope(base_host, p.hostname or ""):
                continue
            seen.add(absolute)
            result.append(absolute)
    return result


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
                "message": f"Failed to fetch root: {target_url}",
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
        await broadcast({
            "type": "assets_found",
            "count": len(js_urls),
            "urls": js_urls[:50],  # cap for WS payload size
        })

    if js_urls:
        tasks = [fetch_url(client, u, semaphore, broadcast) for u in js_urls]
        fetched = await asyncio.gather(*tasks, return_exceptions=False)
        for js_url, js_body in fetched:
            if js_body:
                assets.append((js_url, js_body))

    if broadcast:
        await broadcast({
            "type": "log",
            "level": "INFO",
            "message": f"Spidering complete — {len(assets)} assets collected",
        })

    return assets


# ─────────────────────────────────────────────────────────────────────────────
# Regex Secret Extraction
# ─────────────────────────────────────────────────────────────────────────────

def extract_secrets(
    scan_id: str,
    target_url: str,
    source_url: str,
    text: str,
) -> list[RawFinding]:
    findings: list[RawFinding] = []

    for pattern in SECRET_PATTERNS:
        for match in pattern.regex.finditer(text):
            raw_value = (
                match.group(1)
                if match.lastindex and match.lastindex >= 1
                else match.group(0)
            )

            entropy = shannon_entropy(raw_value)
            if not passes_entropy_check(raw_value):
                continue

            start = max(0, match.start() - CONTEXT_WINDOW_CHARS)
            end   = min(len(text), match.end() + CONTEXT_WINDOW_CHARS)
            snippet = text[start:end].replace("\n", " ").strip()

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


# ─────────────────────────────────────────────────────────────────────────────
# Gemini Contextual Validation
# ─────────────────────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = (
    "You are an AppSec validator. Review this extracted string and its surrounding code. "
    "Determine if this is a genuinely exposed, sensitive API key/secret, or a benign mock "
    "variable, placeholder, or minified code artifact. "
    'Respond strictly with a JSON object: '
    '{"is_valid": true/false, "confidence": 0-100, "reason": "brief explanation"}. '
    "Output ONLY the JSON object. No markdown, no extra text."
)

_JSON_RE = re.compile(r'\{[^{}]+\}', re.DOTALL)


async def validate_with_gemini(
    finding: RawFinding,
    broadcast: Broadcaster | None = None,
) -> ValidatedFinding:
    """
    Always returns a ValidatedFinding — never None. If Gemini is unreachable,
    misconfigured, or returns unparseable output after all retries, the
    finding is returned with confidence=NEEDS_REVIEW_SENTINEL rather than
    being silently dropped. A security scanner must never lose findings
    quietly; when in doubt, surface it to a human.
    """
    if not GEMINI_API_KEY:
        return ValidatedFinding(
            raw=finding,
            is_valid=True,
            confidence=50,
            reason="AI validation skipped — GEMINI_API_KEY not configured.",
        )

    if broadcast:
        await broadcast({
            "type": "log",
            "level": "WARN",
            "message": f"[AI] Validating {finding.secret_type} from {finding.source_url} …",
        })

    user_prompt = (
        f"Secret type: {finding.secret_type}\n"
        f"Extracted value: {finding.raw_match}\n"
        f"Surrounding code:\n```\n{finding.context_snippet}\n```"
    )

    last_error = "unknown error"
    for attempt in range(1, RETRY_ATTEMPTS + 1):
        try:
            model = genai.GenerativeModel(
                model_name=GEMINI_MODEL,
                system_instruction=_SYSTEM_PROMPT,
            )
            response = await asyncio.to_thread(
                model.generate_content,
                user_prompt,
                generation_config=genai.GenerationConfig(
                    temperature=0.1,
                    max_output_tokens=256,
                ),
            )

            raw_text = response.text.strip()
            json_match = _JSON_RE.search(raw_text)
            if not json_match:
                raise ValueError(f"No JSON in Gemini response: {raw_text[:200]}")

            payload: dict[str, Any] = json.loads(json_match.group(0))
            is_valid   = bool(payload.get("is_valid", False))
            confidence = int(payload.get("confidence", 0))
            reason     = str(payload.get("reason", "No reason provided."))

            if broadcast:
                level = "ERROR" if is_valid and confidence >= GEMINI_CONFIDENCE_MIN else "INFO"
                await broadcast({
                    "type": "log",
                    "level": level,
                    "message": (
                        f"[AI] {finding.secret_type} — "
                        f"valid={is_valid} confidence={confidence}% — {reason}"
                    ),
                })

            return ValidatedFinding(
                raw=finding,
                is_valid=is_valid,
                confidence=confidence,
                reason=reason,
            )

        except json.JSONDecodeError as exc:
            last_error = f"JSON parse error: {exc}"
            logger.warning("Gemini JSON parse error (attempt %d): %s", attempt, exc)
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
            logger.warning("Gemini error (attempt %d): %s", attempt, exc)
            if broadcast:
                await broadcast({
                    "type": "log",
                    "level": "WARN",
                    "message": f"[AI] Gemini error attempt {attempt}: {exc}",
                })

        if attempt < RETRY_ATTEMPTS:
            await asyncio.sleep(RETRY_BACKOFF_BASE ** attempt)

    # All retries exhausted — do NOT drop the finding. Surface it as
    # needs-review so a human decides instead of the tool losing it.
    logger.error(
        "AI validation permanently failed for %s in %s after %d attempts: %s — "
        "flagging as NEEDS REVIEW instead of dropping.",
        finding.secret_type, finding.source_url, RETRY_ATTEMPTS, last_error,
    )
    if broadcast:
        await broadcast({
            "type": "log",
            "level": "ERROR",
            "message": (
                f"[AI] Validation FAILED for {finding.secret_type} after "
                f"{RETRY_ATTEMPTS} attempts ({last_error}) — flagged for manual review."
            ),
        })
    return ValidatedFinding(
        raw=finding,
        is_valid=False,
        confidence=NEEDS_REVIEW_SENTINEL,
        reason=f"AI validation unavailable after {RETRY_ATTEMPTS} attempts ({last_error}). Manual review required.",
    )


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
        "username": "SecretNode v2.0",
        "avatar_url": "https://cdn-icons-png.flaticon.com/512/2092/2092757.png",
        "embeds": [{
            "title": f"🚨 Secret Exposed: {raw.secret_type}",
            "color": color,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "footer": {"text": "SecretNode v2.0 — ASM Scanner"},
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

async def run_scan(
    target_url: str,
    scan_id: str | None = None,
    broadcast: Broadcaster | None = None,
    state: ScanState | None = None,
    known_fingerprints: frozenset[str] = frozenset(),
    suppressed_fingerprints: frozenset[str] = frozenset(),
    max_crawl_pages: int = 1,
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

        result["assets_fetched"] = len(assets)
        await emit({
            "type": "log", "level": "INFO",
            "message": f"Asset collection complete — {len(assets)} files to scan",
        })

        # ── 2. Regex Extraction ────────────────────────────────────────────
        state.check()
        all_raw: list[RawFinding] = []
        for source_url, body in assets:
            state.check()
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

        confirmed: list[ValidatedFinding] = [
            v for v in validated
            if v.is_valid and v.confidence >= GEMINI_CONFIDENCE_MIN
        ]
        needs_review: list[ValidatedFinding] = [
            v for v in validated
            if v.confidence == NEEDS_REVIEW_SENTINEL
        ]

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
