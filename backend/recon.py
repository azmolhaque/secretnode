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

import asyncio
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
# Certspotter is a second, independent CT aggregator. Querying more than one
# passive source is how industrial enumerators (subfinder/amass) stay reliable
# when any single source is rate-limited or down — crt.sh in particular returns
# 502/timeout often enough that a lone source is not production-grade.
CERTSPOTTER_URL    = os.environ.get("CERTSPOTTER_URL", "https://api.certspotter.com").rstrip("/")
SUBDOMAIN_TIMEOUT  = _env_int("SUBDOMAIN_ENUM_TIMEOUT", 30)
MAX_SUBDOMAINS     = _env_int("MAX_SUBDOMAINS", 500)   # safety cap on result size
ENUM_RETRIES       = _env_int("SUBDOMAIN_ENUM_RETRIES", 2)  # retries on transient CT errors

# Transient HTTP statuses worth retrying — crt.sh/Certspotter throw these under
# load; a retry with backoff usually clears them.
_TRANSIENT_STATUS: frozenset[int] = frozenset({429, 500, 502, 503, 504})

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
    """Outcome of a passive subdomain enumeration for one registrable domain.

    `sources` lists the passive sources that actually returned data; `error` is
    set only when *every* source failed (so a caller can distinguish "the domain
    has no subdomains" from "enumeration could not run")."""
    domain: str
    subdomains: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def count(self) -> int:
        return len(self.subdomains)

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "subdomains": self.subdomains,
            "count": self.count,
            "sources": self.sources,
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


def parse_certspotter_json(payload: object, domain: str) -> list[str]:
    """Parse a Certspotter `/v1/issuances` response into sorted, in-scope
    hostnames. Each issuance carries a `dns_names` list. Pure function."""
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
        for raw in record.get("dns_names", []) or []:
            host = _clean_name(str(raw), domain)
            if host:
                found.add(host)
    return sorted(found)


async def _get_with_retries(
    client: httpx.AsyncClient, url: str, *, headers: dict | None = None,
) -> tuple[httpx.Response | None, str | None]:
    """GET with backoff retries on transient statuses/timeouts. Returns
    (response, None) on a final response, or (None, error) if every attempt
    failed to produce one. Always names the failure type so errors are never
    blank (the crt.sh timeout showed up as an empty string before)."""
    last_err = "no attempt made"
    for attempt in range(ENUM_RETRIES + 1):
        try:
            resp = await client.get(
                url, headers=headers or {},
                timeout=httpx.Timeout(SUBDOMAIN_TIMEOUT, connect=10.0),
            )
            if resp.status_code in _TRANSIENT_STATUS and attempt < ENUM_RETRIES:
                last_err = f"HTTP {resp.status_code}"
                await asyncio.sleep(2 ** attempt)
                continue
            return resp, None
        except (httpx.HTTPError, httpx.InvalidURL) as exc:
            last_err = f"{type(exc).__name__}: {exc}".rstrip(": ").strip()
            if attempt < ENUM_RETRIES:
                await asyncio.sleep(2 ** attempt)
                continue
    return None, last_err


async def _fetch_crtsh(client: httpx.AsyncClient, domain: str) -> tuple[set[str], str | None]:
    resp, err = await _get_with_retries(client, f"{CRTSH_URL}/?q=%25.{domain}&output=json")
    if resp is None:
        return set(), err
    if resp.status_code != 200:
        return set(), f"HTTP {resp.status_code}"
    return set(parse_crtsh_json(resp.text, domain)), None


async def _fetch_certspotter(client: httpx.AsyncClient, domain: str) -> tuple[set[str], str | None]:
    url = (f"{CERTSPOTTER_URL}/v1/issuances?domain={domain}"
           "&include_subdomains=true&expand=dns_names")
    resp, err = await _get_with_retries(client, url)
    if resp is None:
        return set(), err
    if resp.status_code != 200:
        return set(), f"HTTP {resp.status_code}"
    return set(parse_certspotter_json(resp.text, domain)), None


async def enumerate_subdomains(
    client: httpx.AsyncClient,
    domain: str,
    *,
    limit: int = MAX_SUBDOMAINS,
) -> SubdomainResult:
    """Passively enumerate subdomains of `domain` from multiple Certificate
    Transparency sources (crt.sh + Certspotter), merged and deduplicated.

    Never contacts the target. Fails closed: `error` is set only if *every*
    source failed; if any source returns data the result is usable and lists the
    sources that succeeded. Querying several sources is what keeps enumeration
    reliable when one is rate-limited or down."""
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain:
        return SubdomainResult(domain=domain, error="empty domain")

    all_hosts: set[str] = set()
    ok_sources: list[str] = []
    errors: list[str] = []
    for name, fetch in (("crt.sh", _fetch_crtsh), ("certspotter", _fetch_certspotter)):
        try:
            hosts, err = await fetch(client, domain)
        except Exception as exc:  # defensive: a source must never crash the run
            hosts, err = set(), f"{type(exc).__name__}: {exc}".rstrip(": ").strip()
        if hosts:
            all_hosts |= hosts
            ok_sources.append(name)
        if err:
            errors.append(f"{name}: {err}")

    subs = sorted(all_hosts)
    if len(subs) > limit:
        logger.debug("enumeration returned %d subdomains for %s; capping at %d",
                     len(subs), domain, limit)
        subs = subs[:limit]

    error = None if ok_sources else ("; ".join(errors) or "no sources returned data")
    return SubdomainResult(domain=domain, subdomains=subs, sources=ok_sources, error=error)


# Backward-compatible alias: the original single-source name now maps to the
# multi-source enumerator.
enumerate_subdomains_ct = enumerate_subdomains
