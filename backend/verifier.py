"""
SecretNode — verifier.py  (v2.6.0)

Optional, OFF-BY-DEFAULT live credential verification — the "is this secret
actually active?" step that modern scanners (e.g. TruffleHog's --only-verified)
use to eliminate false-positive fatigue. Instead of only asking "does this look
like a secret?", we can ask "does this secret still work?" — and, when it does,
"WHO does it belong to and what can it reach?"

v2.6.0 (R1 — verification enrichment): a successful check now also captures a
short, non-sensitive **identity/scope** detail (which account, which scopes,
which workspace) so a client report states the concrete blast radius of a live
key — e.g. "GitHub account @acme-bot · scopes: repo, read:org" — instead of a
bare "verified". This is the impact signal Cindrasec reports are built to sell.

Each verifier makes exactly ONE read-only identity/"whoami" call to the
credential's own provider (never to the scan target) and reports whether the
credential is currently active. Verifiers:
  • are strictly read-only (no writes, no destructive calls),
  • never reveal or transmit the secret anywhere except to its own issuer,
  • never store or return the secret itself — only a derived identity label,
  • fail closed (any error / timeout → "unverified", never a crash).

This capability is disabled unless the operator sets VERIFY_SECRETS=true (or
passes verify=true on a scan). Using a discovered credential — even for a
read-only check — is only appropriate on assets you own or are explicitly
authorized to test. See SECURITY.md.

Status values returned:
  • "verified"    — the credential responded as active/valid
  • "unverified"  — a verifier ran but the credential did not validate (likely dead/rotated)
  • "unsupported" — no safe automatic verifier exists for this secret type (verify manually)
  • "disabled"    — verification was not requested for this scan
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

logger = logging.getLogger("secretnode.verifier")

VERIFY_TIMEOUT = 10.0

# A "client" here is any object exposing async .get()/.post() like httpx.AsyncClient,
# which lets these functions be unit-tested with a lightweight mock.
# A verifier returns (active, detail): whether the credential is live, and a short
# non-sensitive identity/scope label ("" when nothing safe could be extracted).
Verifier = Callable[[str, Any], Awaitable["tuple[bool, str]"]]


@dataclass
class VerifyResult:
    """Result of a live verification attempt.

    status  — one of verified / unverified / unsupported
    detail  — short, non-sensitive identity/scope label for a VERIFIED credential
              (empty otherwise); never contains the secret value itself.
    """
    status: str
    detail: str = ""


# ── helpers ──────────────────────────────────────────────────────────────────

def _safe_json(r: Any) -> dict:
    try:
        data = r.json()
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _safe_headers(r: Any) -> dict:
    try:
        h = getattr(r, "headers", {}) or {}
        # httpx.Headers is mapping-like; dict() normalises for .get()
        return {str(k).lower(): v for k, v in dict(h).items()}
    except Exception:
        return {}


def _detail(*parts: str) -> str:
    """Join non-empty identity fragments into one short label."""
    return " · ".join(p for p in parts if p)


# ── verifiers (one read-only call each) ──────────────────────────────────────

async def _github(token: str, client: Any) -> tuple[bool, str]:
    r = await client.get(
        "https://api.github.com/user",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
        timeout=VERIFY_TIMEOUT,
    )
    if r.status_code != 200:
        return False, ""
    login = _safe_json(r).get("login", "")
    scopes = _safe_headers(r).get("x-oauth-scopes", "")
    return True, _detail(f"GitHub @{login}" if login else "",
                         f"scopes: {scopes}" if scopes else "")


async def _gitlab(token: str, client: Any) -> tuple[bool, str]:
    r = await client.get(
        "https://gitlab.com/api/v4/user",
        headers={"PRIVATE-TOKEN": token},
        timeout=VERIFY_TIMEOUT,
    )
    if r.status_code != 200:
        return False, ""
    j = _safe_json(r)
    user = j.get("username", "")
    return True, _detail(f"GitLab @{user}" if user else "",
                         "admin" if j.get("is_admin") else "")


async def _stripe(token: str, client: Any) -> tuple[bool, str]:
    r = await client.get("https://api.stripe.com/v1/account", auth=(token, ""), timeout=VERIFY_TIMEOUT)
    if r.status_code != 200:
        return False, ""
    j = _safe_json(r)
    acct = j.get("id", "")
    mode = "LIVE mode" if token.startswith("sk_live") else ""
    return True, _detail(f"Stripe {acct}" if acct else "", mode,
                         "charges enabled" if j.get("charges_enabled") else "")


async def _sendgrid(token: str, client: Any) -> tuple[bool, str]:
    r = await client.get(
        "https://api.sendgrid.com/v3/scopes",
        headers={"Authorization": f"Bearer {token}"},
        timeout=VERIFY_TIMEOUT,
    )
    if r.status_code != 200:
        return False, ""
    scopes = _safe_json(r).get("scopes", [])
    can_send = "mail.send" in scopes if isinstance(scopes, list) else False
    return True, _detail("can send mail" if can_send else "",
                         f"{len(scopes)} scopes" if isinstance(scopes, list) and scopes else "")


async def _openai(token: str, client: Any) -> tuple[bool, str]:
    r = await client.get(
        "https://api.openai.com/v1/models",
        headers={"Authorization": f"Bearer {token}"},
        timeout=VERIFY_TIMEOUT,
    )
    if r.status_code != 200:
        return False, ""
    org = _safe_headers(r).get("openai-organization", "")
    return True, _detail(f"org: {org}" if org and org != "user" else "")


async def _slack(token: str, client: Any) -> tuple[bool, str]:
    r = await client.post(
        "https://slack.com/api/auth.test",
        headers={"Authorization": f"Bearer {token}"},
        timeout=VERIFY_TIMEOUT,
    )
    if r.status_code != 200:
        return False, ""
    j = _safe_json(r)
    if not j.get("ok"):
        return False, ""
    team, user = j.get("team", ""), j.get("user", "")
    return True, _detail(f"Slack {team}" if team else "",
                         f"as {user}" if user else "")


async def _npm(token: str, client: Any) -> tuple[bool, str]:
    r = await client.get(
        "https://registry.npmjs.org/-/whoami",
        headers={"Authorization": f"Bearer {token}"},
        timeout=VERIFY_TIMEOUT,
    )
    if r.status_code != 200:
        return False, ""
    user = _safe_json(r).get("username", "")
    return True, _detail(f"npm @{user}" if user else "")


async def _mailgun(token: str, client: Any) -> tuple[bool, str]:
    r = await client.get(
        "https://api.mailgun.net/v3/domains", auth=("api", token), timeout=VERIFY_TIMEOUT
    )
    if r.status_code != 200:
        return False, ""
    n = _safe_json(r).get("total_count")
    return True, _detail(f"{n} domain(s)" if isinstance(n, int) else "")


async def _telegram(token: str, client: Any) -> tuple[bool, str]:
    r = await client.get(f"https://api.telegram.org/bot{token}/getMe", timeout=VERIFY_TIMEOUT)
    if r.status_code != 200:
        return False, ""
    j = _safe_json(r)
    if not j.get("ok"):
        return False, ""
    bot = (j.get("result") or {}).get("username", "") if isinstance(j.get("result"), dict) else ""
    return True, _detail(f"Telegram bot @{bot}" if bot else "")


# secret_type (from scanner.SECRET_PATTERNS) -> verifier
VERIFIERS: dict[str, Verifier] = {
    "GitHub Personal Access Token": _github,
    "GitHub Fine-Grained PAT": _github,
    "GitHub OAuth Token": _github,
    "GitHub Server/Refresh Token": _github,
    "GitLab Personal Access Token": _gitlab,
    "Stripe Secret Key": _stripe,
    "SendGrid API Key": _sendgrid,
    "OpenAI API Key": _openai,
    "OpenAI Service Account Key": _openai,
    "Slack Token": _slack,
    "Slack App-Level Token": _slack,
    "npm Access Token": _npm,
    "Mailgun API Key": _mailgun,
    "Telegram Bot Token": _telegram,
}


def is_supported(secret_type: str) -> bool:
    return secret_type in VERIFIERS


async def verify_finding_detailed(secret_type: str, raw_value: str, client: Any) -> VerifyResult:
    """Verify a credential and, if active, capture a short identity/scope label.
    Returns a VerifyResult. Never raises (fails closed to 'unverified')."""
    fn = VERIFIERS.get(secret_type)
    if fn is None:
        return VerifyResult("unsupported", "")
    try:
        active, detail = await fn(raw_value, client)
        return VerifyResult("verified", detail) if active else VerifyResult("unverified", "")
    except Exception as exc:  # noqa: BLE001 — fail closed, never crash a scan
        logger.warning("Verification error for %s: %s", secret_type, exc)
        return VerifyResult("unverified", "")


async def verify_finding(secret_type: str, raw_value: str, client: Any) -> str:
    """Backward-compatible status-only API. Return one of:
    'verified', 'unverified', 'unsupported'. Never raises."""
    return (await verify_finding_detailed(secret_type, raw_value, client)).status
