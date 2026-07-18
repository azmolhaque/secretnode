"""
SecretNode — posture.py  (R8: passive attack-surface breadth)

A first step from "secret scanner" toward the fuller attack-surface scanner the
brand promises: analyse the target's own HTTP response for missing/weak security
headers and simple misconfigurations. This is **pure passive analysis of a
response the target already serves** — no exploitation, no third-party calls, no
writes. Each issue is a `PostureFinding` with severity / CWE / remediation, so it
flows into the same reports as credential findings but stays in its own category
(it never enters the secret-validation or live-verification pipeline).

Follow-ups (deferred, higher-risk / external network): CT-log subdomain
discovery (crt.sh), DNS resolution + dangling-CNAME takeover checks.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("secretnode.posture")


@dataclass
class PostureFinding:
    name: str
    severity: str            # CRITICAL / HIGH / MEDIUM / LOW / INFO
    cwe: str
    evidence: str            # what was observed on the response
    remediation: str
    category: str = "Security Posture"
    found_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "severity": self.severity, "cwe": self.cwe,
            "evidence": self.evidence, "remediation": self.remediation,
            "category": self.category, "found_at": self.found_at,
        }


def analyze_security_headers(headers: dict[str, Any] | None, final_url: str) -> list[PostureFinding]:
    """Inspect response headers for missing/weak security controls. Pure and
    deterministic — unit-tested without any network."""
    h = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    is_https = final_url.lower().startswith("https://")
    out: list[PostureFinding] = []

    def add(name: str, sev: str, cwe: str, evidence: str, remediation: str) -> None:
        out.append(PostureFinding(name, sev, cwe, evidence, remediation))

    if is_https and "strict-transport-security" not in h:
        add("Missing HSTS", "MEDIUM", "CWE-319",
            "No Strict-Transport-Security header on an HTTPS response.",
            "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.")

    csp = h.get("content-security-policy", "")
    if not csp:
        add("Missing Content-Security-Policy", "MEDIUM", "CWE-693",
            "No Content-Security-Policy header — weaker XSS / data-injection defence.",
            "Define a restrictive Content-Security-Policy.")

    xcto = h.get("x-content-type-options", "")
    if xcto.lower() != "nosniff":
        add("Missing X-Content-Type-Options: nosniff", "LOW", "CWE-693",
            f"X-Content-Type-Options is '{xcto or 'absent'}'.",
            "Set 'X-Content-Type-Options: nosniff'.")

    if not h.get("x-frame-options", "") and "frame-ancestors" not in csp.lower():
        add("No clickjacking protection", "MEDIUM", "CWE-1021",
            "Neither X-Frame-Options nor a CSP 'frame-ancestors' directive is present.",
            "Set 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive.")

    if "referrer-policy" not in h:
        add("Missing Referrer-Policy", "LOW", "CWE-200",
            "No Referrer-Policy header — the referrer URL may leak to third parties.",
            "Set e.g. 'Referrer-Policy: strict-origin-when-cross-origin'.")

    if "permissions-policy" not in h:
        add("Missing Permissions-Policy", "LOW", "CWE-693",
            "No Permissions-Policy header — powerful browser features are not restricted.",
            "Set a Permissions-Policy that disables features the site does not use.")

    for hdr in ("server", "x-powered-by", "x-aspnet-version"):
        val = h.get(hdr, "")
        if val and any(c.isdigit() for c in val):
            add(f"Version disclosure via {hdr}", "LOW", "CWE-200",
                f"{hdr}: {val}",
                f"Remove or obscure the '{hdr}' header so it does not reveal software versions.")

    cookie = h.get("set-cookie", "")
    if cookie:
        low = cookie.lower()
        if is_https and "secure" not in low:
            add("Cookie without Secure flag", "MEDIUM", "CWE-614",
                "A Set-Cookie on an HTTPS response lacks the 'Secure' attribute.",
                "Add 'Secure' to cookies so they are never sent over plain HTTP.")
        if "httponly" not in low:
            add("Cookie without HttpOnly flag", "LOW", "CWE-1004",
                "A Set-Cookie lacks the 'HttpOnly' attribute.",
                "Add 'HttpOnly' to cookies that JavaScript does not need to read.")

    return out


async def fetch_posture(client: Any, target_url: str) -> list[PostureFinding]:
    """One passive GET to the target root; analyse its response headers. Fully
    defensive — any error yields no findings rather than failing the scan."""
    try:
        r = await client.get(target_url)
        headers = dict(getattr(r, "headers", {}) or {})
        final_url = str(getattr(r, "url", "") or target_url)
        return analyze_security_headers(headers, final_url)
    except Exception as exc:  # noqa: BLE001 — best-effort, never break a scan
        logger.warning("posture check failed for %s: %s", target_url, exc)
        return []
