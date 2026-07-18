#!/usr/bin/env python3
"""
SecretNode passive reconnaissance — attack-surface discovery.

The first discovery layer of the deep-ASM pipeline: given a domain, expand it
into its full known subdomain surface using **passive public data only**, so no
packet is ever sent to the target itself. This slice sources subdomains from
Certificate Transparency (crt.sh) — every publicly-trusted TLS certificate is
logged there, which makes CT the single richest passive source of a domain's
hostnames.

Design rules (mirror the scanner's posture):
  • Passive only — we query third-party CT logs, never the target. Nothing here
    resolves DNS, connects to, or probes the target host.
  • Fails closed — any network/parse error yields an empty result, never an
    exception that would abort a scan. Discovery is best-effort by nature.
  • Authorized use only — enumerating a domain's surface is reconnaissance; only
    run it against assets you own or are explicitly permitted to assess.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

logger = logging.getLogger("secretnode.recon")


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default


# crt.sh is the CT-log front-end; %25 is a URL-encoded '%' wildcard so the query
# "%.example.com" returns every logged hostname under the domain.
CRTSH_URL          = os.environ.get("CRTSH_URL", "https://crt.sh").rstrip("/")
SUBDOMAIN_TIMEOUT  = _env_int("SUBDOMAIN_ENUM_TIMEOUT", 30)
MAX_SUBDOMAINS     = _env_int("MAX_SUBDOMAINS", 500)   # safety cap on result size

# A small public-suffix table so we can find the *registrable* domain of a host
# without a heavyweight PSL dependency. Covers the common two-label suffixes,
# with Bangladesh (Cindrasec's home market) explicitly included. Anything not
# listed falls back to the last two labels, which is correct for gTLDs.
_TWO_LEVEL_SUFFIXES: frozenset[str] = frozenset({
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "com.bd", "net.bd", "org.bd", "edu.bd", "gov.bd", "ac.bd", "mil.bd",
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in",
    "com.br", "net.br", "org.br", "gov.br",
    "com.sg", "com.my", "com.pk", "com.np", "com.lk", "com.cn", "com.hk",
    "co.jp", "or.jp", "ne.jp", "co.kr", "co.za", "co.id", "co.th",
})


@dataclass
class SubdomainResult:
    """Outcome of a passive subdomain enumeration for one registrable domain."""
    domain: str
    subdomains: list[str] = field(default_factory=list)
    source: str = "crt.sh"
    error: str | None = None

    @property
    def count(self) -> int:
        return len(self.subdomains)

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "subdomains": self.subdomains,
            "count": self.count,
            "source": self.source,
            "error": self.error,
        }


def _host_of(target: str) -> str:
    """Extract the bare hostname from a URL, host[:port], or bare domain."""
    target = (target or "").strip()
    if not target:
        return ""
    if "://" in target:
        target = urlparse(target).hostname or ""
    else:
        # Strip a trailing path and any :port, but keep bracketed IPv6 intact.
        target = target.split("/", 1)[0]
        if target.count(":") == 1:          # host:port (not IPv6, which has many)
            target = target.split(":", 1)[0]
    return target.strip().strip(".").lower()


def is_ip_literal(target: str) -> bool:
    """True if the target's host is an IP address (subdomain enum does not apply)."""
    host = _host_of(target).strip("[]")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def extract_registrable_domain(target: str) -> str | None:
    """Reduce a URL / host / bare domain to its registrable domain
    (e.g. https://api.blog.example.co.uk/x -> example.co.uk). Returns None for IP
    literals and inputs with no usable hostname, since neither can be enumerated."""
    host = _host_of(target)
    if not host or is_ip_literal(target):
        return None
    labels = [x for x in host.split(".") if x]
    if len(labels) < 2:
        return None
    last_two = ".".join(labels[-2:])
    if last_two in _TWO_LEVEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def _clean_name(name: str, domain: str) -> str | None:
    """Normalise one CT 'name_value' entry into a single in-scope hostname, or
    None if it is not a usable subdomain of `domain`."""
    n = (name or "").strip().lower().rstrip(".")
    if n.startswith("*."):          # wildcard cert — the base host is what matters
        n = n[2:]
    if not n or "@" in n or " " in n:   # skip emails / malformed entries
        return None
    if n == domain or n.endswith("." + domain):
        return n
    return None


def parse_crtsh_json(payload: object, domain: str) -> list[str]:
    """Parse a crt.sh JSON response into a sorted, deduplicated list of in-scope
    hostnames. Pure function (no I/O) so it is cheap and deterministic to test.

    Accepts either an already-decoded list or a raw JSON string. crt.sh packs one
    or more newline-separated names into each record's `name_value`, plus a
    `common_name`; we harvest every name from both fields."""
    domain = (domain or "").strip().lower().rstrip(".")
    if isinstance(payload, (str, bytes)):
        try:
            payload = json.loads(payload)
        except (ValueError, TypeError):
            return []
    if not isinstance(payload, list):
        return []

    found: set[str] = set()
    for record in payload:
        if not isinstance(record, dict):
            continue
        raw_names = str(record.get("name_value", "")).split("\n")
        raw_names.append(str(record.get("common_name", "")))
        for raw in raw_names:
            host = _clean_name(raw, domain)
            if host:
                found.add(host)
    return sorted(found)


async def enumerate_subdomains_ct(
    client: httpx.AsyncClient,
    domain: str,
    *,
    limit: int = MAX_SUBDOMAINS,
) -> SubdomainResult:
    """Passively enumerate subdomains of `domain` via Certificate Transparency.

    Never contacts the target — only crt.sh. Fails closed: on any error the
    result carries an `error` string and an empty subdomain list so a caller can
    proceed (and report the gap) instead of aborting."""
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain:
        return SubdomainResult(domain=domain, error="empty domain")

    url = f"{CRTSH_URL}/?q=%25.{domain}&output=json"
    try:
        resp = await client.get(url, timeout=httpx.Timeout(SUBDOMAIN_TIMEOUT, connect=10.0))
        if resp.status_code != 200:
            return SubdomainResult(domain=domain, error=f"crt.sh HTTP {resp.status_code}")
        subs = parse_crtsh_json(resp.text, domain)
    except (httpx.HTTPError, httpx.InvalidURL) as exc:
        logger.debug("crt.sh enumeration failed for %s: %s", domain, exc)
        return SubdomainResult(domain=domain, error=f"crt.sh request failed: {exc}")

    if len(subs) > limit:
        logger.debug("crt.sh returned %d subdomains for %s; capping at %d",
                     len(subs), domain, limit)
        subs = subs[:limit]
    return SubdomainResult(domain=domain, subdomains=subs)
