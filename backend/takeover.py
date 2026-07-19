#!/usr/bin/env python3
"""
SecretNode subdomain-takeover detection — deep-dive slice D1.

A subdomain whose DNS still points (via CNAME) at a de-provisioned third-party
service — an unclaimed S3 bucket, a deleted GitHub Pages site, a removed Heroku
app — can be *claimed by an attacker*, who then serves arbitrary content from a
hostname your users trust. That is one of the highest-impact issues an external
assessment can surface, and it is findable passively: resolve the host and read
the service's own "this isn't claimed" response.

Detection is deliberately high-precision (low false positive): a host is only
flagged when the response body matches a service's *specific* unclaimed-resource
signature (e.g. GitHub's "There isn't a GitHub Pages site here."). A CNAME to the
service, when resolvable, is recorded as corroborating evidence.

Passive and authorized-scope only: this inspects hosts within the target domain
that the deep scan already covers — no exploitation, no claiming of resources.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from dataclasses import dataclass

import httpx

logger = logging.getLogger("secretnode.takeover")


@dataclass(frozen=True)
class TakeoverFingerprint:
    service: str
    cname_markers: tuple[str, ...]   # substrings expected in the CNAME chain
    body_markers: tuple[str, ...]    # specific unclaimed-resource response signatures
    severity: str = "HIGH"


# Curated from the community "can-i-take-over-xyz" catalogue — only entries with a
# SPECIFIC body signature (generic "404 Not Found" pages are excluded to keep the
# false-positive rate at zero, per Cindrasec's brand promise).
FINGERPRINTS: tuple[TakeoverFingerprint, ...] = (
    TakeoverFingerprint("GitHub Pages", ("github.io",),
                        ("There isn't a GitHub Pages site here.",), "HIGH"),
    TakeoverFingerprint("AWS S3", ("amazonaws.com", "s3"),
                        ("NoSuchBucket", "The specified bucket does not exist"), "CRITICAL"),
    TakeoverFingerprint("Heroku", ("herokudns.com", "herokuapp.com", "herokussl.com"),
                        ("No such app", "herokucdn.com/error-pages/no-such-app.html"), "HIGH"),
    TakeoverFingerprint("Netlify", ("netlify.app", "netlify.com"),
                        ("Not Found - Request ID",), "HIGH"),
    TakeoverFingerprint("Shopify", ("myshopify.com",),
                        ("Sorry, this shop is currently unavailable",), "HIGH"),
    TakeoverFingerprint("Fastly", ("fastly.net",),
                        ("Fastly error: unknown domain",), "HIGH"),
    TakeoverFingerprint("Zendesk", ("zendesk.com",),
                        ("Help Center Closed",), "HIGH"),
    TakeoverFingerprint("Surge.sh", ("surge.sh",),
                        ("project not found",), "HIGH"),
    TakeoverFingerprint("Bitbucket", ("bitbucket.io",),
                        ("Repository not found",), "HIGH"),
    TakeoverFingerprint("Ghost", ("ghost.io",),
                        ("The thing you were looking for is no longer here",), "HIGH"),
    TakeoverFingerprint("Pantheon", ("pantheonsite.io",),
                        ("The gods are wise, but do not know of the site which you seek.",), "HIGH"),
    TakeoverFingerprint("Tumblr", ("domains.tumblr.com",),
                        ("Whatever you were looking for doesn't currently exist at this address.",), "HIGH"),
    TakeoverFingerprint("Wordpress", ("wordpress.com",),
                        ("Do you want to register",), "MEDIUM"),
    TakeoverFingerprint("Readme.io", ("readme.io",),
                        ("Project doesnt exist... yet!",), "HIGH"),
    TakeoverFingerprint("Cargo", ("cargocollective.com",),
                        ("If you're moving your domain away from Cargo",), "HIGH"),
    TakeoverFingerprint("Webflow", ("proxy-ssl.webflow.com", "proxy.webflow.com"),
                        ("The page you are looking for doesn't exist or has been moved.",), "MEDIUM"),
)


@dataclass
class TakeoverFinding:
    host: str
    service: str
    severity: str
    evidence: str
    cname: str = ""
    remediation: str = ("Remove the dangling DNS record, or re-claim the resource at the "
                        "provider before an attacker does. A subdomain pointing at an "
                        "unclaimed service can be taken over and used to serve content from "
                        "your domain (phishing, cookie theft, brand abuse).")
    cwe: str = "CWE-350"    # Reliance on reverse DNS resolution / untrusted third-party
    secret_type: str = "Subdomain Takeover"

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "service": self.service,
            "severity": self.severity,
            "evidence": self.evidence,
            "cname": self.cname,
            "remediation": self.remediation,
            "cwe": self.cwe,
            "secret_type": self.secret_type,
        }


def resolve_cnames(host: str) -> list[str]:
    """Best-effort CNAME/alias chain for a host (stdlib only). Returns [] on any
    resolution error — CNAME data is corroborating evidence, never required."""
    try:
        _name, aliases, _ips = socket.gethostbyname_ex(host)
        return [a.lower() for a in aliases]
    except (socket.gaierror, OSError):
        return []


def check_takeover(host: str, cnames: list[str], body: str) -> TakeoverFinding | None:
    """Pure, deterministic takeover check. A host is flagged only when the body
    carries a service's specific unclaimed-resource signature. A matching CNAME
    (when available) is recorded as evidence and, when present, is required — so a
    body signature alone on a host clearly NOT delegated to that service does not
    over-trigger."""
    body = body or ""
    for fp in FINGERPRINTS:
        if not any(bm in body for bm in fp.body_markers):
            continue
        cname_hit = next((c for c in cnames if any(m in c for m in fp.cname_markers)), "")
        # If we resolved CNAMEs at all, require one to point at this service (guards
        # against a look-alike error string on an unrelated host). If we could not
        # resolve CNAMEs, trust the specific body signature on its own.
        if cnames and not cname_hit:
            continue
        marker = next(bm for bm in fp.body_markers if bm in body)
        return TakeoverFinding(
            host=host, service=fp.service, severity=fp.severity,
            evidence=f"Response matches {fp.service} unclaimed-resource signature: “{marker}”.",
            cname=cname_hit,
        )
    return None


async def detect_takeover(
    client: httpx.AsyncClient, host: str, *, timeout: float = 10.0,
) -> TakeoverFinding | None:
    """Resolve the host's CNAME chain and fetch it once, then run the pure check.
    Fails closed (returns None) on any network error."""
    cnames = await asyncio.to_thread(resolve_cnames, host)
    for scheme in ("https", "http"):
        try:
            resp = await client.get(f"{scheme}://{host}",
                                    timeout=httpx.Timeout(timeout, connect=10.0))
        except httpx.HTTPError:
            continue
        return check_takeover(host, cnames, resp.text)
    # Host unreachable over HTTP but may still be a takeover target with only a
    # CNAME signal — without a body signature we do not flag (precision first).
    return None


async def scan_hosts_for_takeover(
    client: httpx.AsyncClient, hosts: list[str], *, concurrency: int = 10,
) -> list[TakeoverFinding]:
    """Concurrently check many hosts; return the confirmed takeover findings."""
    sem = asyncio.Semaphore(max(1, concurrency))

    async def _one(h: str) -> TakeoverFinding | None:
        async with sem:
            try:
                return await detect_takeover(client, h)
            except Exception as exc:  # a single host must never sink the pass
                logger.debug("takeover check failed for %s: %s", h, exc)
                return None

    results = await asyncio.gather(*(_one(h) for h in hosts))
    return [r for r in results if r]
