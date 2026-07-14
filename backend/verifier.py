"""
SecretNode — verifier.py  (v2.3.0)

Optional, OFF-BY-DEFAULT live credential verification — the "is this secret
actually active?" step that modern scanners (e.g. TruffleHog's --only-verified)
use to eliminate false-positive fatigue. Instead of only asking "does this look
like a secret?", we can ask "does this secret still work?"

Each verifier makes exactly ONE read-only identity/"whoami" call to the
credential's own provider (never to the scan target) and reports whether the
credential is currently active. Verifiers:
  • are strictly read-only (no writes, no destructive calls),
  • never reveal or transmit the secret anywhere except to its own issuer,
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
from typing import Any, Awaitable, Callable

logger = logging.getLogger("secretnode.verifier")

VERIFY_TIMEOUT = 10.0

# A "client" here is any object exposing async .get()/.post() like httpx.AsyncClient,
# which lets these functions be unit-tested with a lightweight mock.
Verifier = Callable[[str, Any], Awaitable[bool]]


async def _github(token: str, client: Any) -> bool:
    r = await client.get(
        "https://api.github.com/user",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
        timeout=VERIFY_TIMEOUT,
    )
    return r.status_code == 200


async def _gitlab(token: str, client: Any) -> bool:
    r = await client.get(
        "https://gitlab.com/api/v4/user",
        headers={"PRIVATE-TOKEN": token},
        timeout=VERIFY_TIMEOUT,
    )
    return r.status_code == 200


async def _stripe(token: str, client: Any) -> bool:
    r = await client.get("https://api.stripe.com/v1/account", auth=(token, ""), timeout=VERIFY_TIMEOUT)
    return r.status_code == 200


async def _sendgrid(token: str, client: Any) -> bool:
    r = await client.get(
        "https://api.sendgrid.com/v3/scopes",
        headers={"Authorization": f"Bearer {token}"},
        timeout=VERIFY_TIMEOUT,
    )
    return r.status_code == 200


async def _openai(token: str, client: Any) -> bool:
    r = await client.get(
        "https://api.openai.com/v1/models",
        headers={"Authorization": f"Bearer {token}"},
        timeout=VERIFY_TIMEOUT,
    )
    return r.status_code == 200


async def _slack(token: str, client: Any) -> bool:
    r = await client.post(
        "https://slack.com/api/auth.test",
        headers={"Authorization": f"Bearer {token}"},
        timeout=VERIFY_TIMEOUT,
    )
    if r.status_code != 200:
        return False
    try:
        return bool(r.json().get("ok"))
    except Exception:
        return False


async def _npm(token: str, client: Any) -> bool:
    r = await client.get(
        "https://registry.npmjs.org/-/whoami",
        headers={"Authorization": f"Bearer {token}"},
        timeout=VERIFY_TIMEOUT,
    )
    return r.status_code == 200


async def _mailgun(token: str, client: Any) -> bool:
    r = await client.get(
        "https://api.mailgun.net/v3/domains", auth=("api", token), timeout=VERIFY_TIMEOUT
    )
    return r.status_code == 200


async def _telegram(token: str, client: Any) -> bool:
    r = await client.get(f"https://api.telegram.org/bot{token}/getMe", timeout=VERIFY_TIMEOUT)
    if r.status_code != 200:
        return False
    try:
        return bool(r.json().get("ok"))
    except Exception:
        return False


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


async def verify_finding(secret_type: str, raw_value: str, client: Any) -> str:
    """Return one of: 'verified', 'unverified', 'unsupported'. Never raises."""
    fn = VERIFIERS.get(secret_type)
    if fn is None:
        return "unsupported"
    try:
        active = await fn(raw_value, client)
        return "verified" if active else "unverified"
    except Exception as exc:  # noqa: BLE001 — fail closed, never crash a scan
        logger.warning("Verification error for %s: %s", secret_type, exc)
        return "unverified"
