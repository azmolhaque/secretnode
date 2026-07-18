#!/usr/bin/env python3
"""
SecretNode multi-target orchestration — deep-ASM slice 2.

Closes the loop from discovery to findings: given a single domain, expand it to
its subdomain surface (passive CT enumeration), probe which of those hosts are
actually live, then run the existing passive secret+posture scan against each
one and aggregate the results into a single deliverable.

Everything here stays within SecretNode's passive/authorized posture:
  • Enumeration is passive (Certificate Transparency, never the target).
  • Liveness probing and scanning are the same passive fetches the single-target
    scanner already performs — no exploitation, no brute-force, read-only.
  • Authorized use only. Scanning a whole domain's host list at once magnifies
    the responsibility: run it only against assets you own or are explicitly
    permitted to assess (owned / signed RoE / in-scope program).

Collaborators (enumeration, client factory, per-host scan) are injected so the
orchestration is unit-testable without any network.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import socket
from dataclasses import dataclass, field
from typing import Awaitable, Callable

import httpx

import historical
import recon
import scanner

logger = logging.getLogger("secretnode.orchestrator")


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default


MAX_TARGETS       = _env_int("MAX_TARGETS", 25)          # cap hosts scanned per run
PROBE_CONCURRENCY = _env_int("PROBE_CONCURRENCY", 10)    # parallel liveness probes
PROBE_TIMEOUT     = _env_int("PROBE_TIMEOUT", 10)        # seconds per liveness probe

# Type aliases for the injected collaborators.
EnumerateFn = Callable[..., Awaitable["recon.SubdomainResult"]]
ScanFn      = Callable[..., Awaitable[dict]]
ClientFactory = Callable[[], httpx.AsyncClient]


@dataclass
class HostScan:
    """Per-host outcome inside a deep scan."""
    host: str
    url: str
    confirmed: int = 0
    needs_review: int = 0
    posture_issues: int = 0
    assets: int = 0
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "host": self.host, "url": self.url, "confirmed": self.confirmed,
            "needs_review": self.needs_review, "posture_issues": self.posture_issues,
            "assets": self.assets, "error": self.error,
        }


@dataclass
class DeepScanResult:
    """Aggregate of a domain-wide deep scan."""
    domain: str
    subdomains: list[str] = field(default_factory=list)
    enum_sources: list[str] = field(default_factory=list)
    live_hosts: list[str] = field(default_factory=list)
    hosts: list[HostScan] = field(default_factory=list)
    scans: list[dict] = field(default_factory=list)   # raw per-host scan dicts
    historical_urls: int = 0        # historical URLs discovered (0 if not requested)
    error: str | None = None

    @property
    def total_confirmed(self) -> int:
        return sum(h.confirmed for h in self.hosts)

    @property
    def total_needs_review(self) -> int:
        return sum(h.needs_review for h in self.hosts)

    @property
    def total_posture(self) -> int:
        return sum(h.posture_issues for h in self.hosts)

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "subdomains": self.subdomains,
            "enum_sources": self.enum_sources,
            "live_hosts": self.live_hosts,
            "hosts": [h.to_dict() for h in self.hosts],
            "historical_urls": self.historical_urls,
            "totals": {
                "subdomains": len(self.subdomains),
                "live_hosts": len(self.live_hosts),
                "hosts_scanned": len(self.hosts),
                "historical_urls": self.historical_urls,
                "confirmed": self.total_confirmed,
                "needs_review": self.total_needs_review,
                "posture_issues": self.total_posture,
            },
            "error": self.error,
        }


def _target_ip_class(host: str) -> str:
    """Classify a host by the address it resolves to: 'public', 'private'
    (loopback/private/link-local/reserved/multicast — an SSRF risk), or
    'unresolved'. Used to keep a discovered host list from ever pointing the
    scanner at internal infrastructure."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return "unresolved"
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast):
            return "private"
    return "public"


async def _probe_one(client: httpx.AsyncClient, host: str) -> str | None:
    """Return the reachable base URL for a host (preferring https), or None if it
    is unreachable. ANY HTTP response — including 401/403/5xx — means the host is
    live and worth scanning; only a transport error (DNS/connect/timeout) is dead."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            await client.get(url, timeout=httpx.Timeout(PROBE_TIMEOUT, connect=10.0))
            return url
        except httpx.HTTPError:
            continue
    return None


async def probe_live_hosts(
    client: httpx.AsyncClient, hosts: list[str], *, concurrency: int = PROBE_CONCURRENCY,
) -> list[str]:
    """Concurrently probe hosts; return the reachable base URLs, order preserved."""
    sem = asyncio.Semaphore(max(1, concurrency))

    async def _guarded(h: str) -> str | None:
        async with sem:
            return await _probe_one(client, h)

    results = await asyncio.gather(*(_guarded(h) for h in hosts))
    return [u for u in results if u]


def _summarise_scan(host: str, url: str, scan: dict) -> HostScan:
    return HostScan(
        host=host,
        url=url,
        confirmed=len(scan.get("confirmed_findings", [])),
        needs_review=len(scan.get("needs_review_findings", [])),
        posture_issues=len(scan.get("posture_findings", [])),
        assets=int(scan.get("assets_fetched", 0) or 0),
        error=scan.get("error"),
    )


async def run_deep_scan(
    target: str,
    *,
    max_crawl_pages: int = 1,
    verify: bool = False,
    only_verified: bool = False,
    max_targets: int = MAX_TARGETS,
    include_historical: bool = False,
    enumerate_fn: EnumerateFn = recon.enumerate_subdomains,
    scan_fn: ScanFn = scanner.run_scan,
    client_factory: ClientFactory = scanner.build_client,
    discover_historical_fn: Callable[..., Awaitable["historical.HistoricalResult"]]
        = historical.discover_historical_urls,
) -> DeepScanResult:
    """Domain → enumerate → probe → scan each live host → aggregate.

    Falls back to scanning the bare target itself when the input is an IP or has
    no enumerable domain, so a deep scan always does *something* useful."""
    domain = recon.extract_registrable_domain(target)
    if domain is None:
        # No enumerable domain (e.g. an IP): degrade to a single passive scan of
        # the given target so the deep-scan entry point is still usable.
        host = recon._host_of(target) or target
        url = target if "://" in target else f"https://{host}"
        result = DeepScanResult(domain=host)
        scan = await scan_fn(target_url=url, max_crawl_pages=max_crawl_pages,
                             verify=verify, only_verified=only_verified)
        result.live_hosts = [url]
        result.hosts = [_summarise_scan(host, url, scan)]
        result.scans = [scan]
        return result

    original_host = recon._host_of(target)
    result = DeepScanResult(domain=domain)
    async with client_factory() as client:
        enum = await enumerate_fn(client, domain)
        result.subdomains = enum.subdomains
        result.enum_sources = enum.sources

        # Optional: recover historical URLs (Wayback/CommonCrawl) once for the
        # domain. They enrich BOTH host discovery (hostnames seen in the archive)
        # and per-host scan seeds (archived JS bundles) — so a flaky CT source no
        # longer zeroes out the run, and forgotten bundles still get scanned.
        js_by_host: dict[str, list[str]] = {}
        hist_hosts: list[str] = []
        if include_historical:
            hist = await discover_historical_fn(client, domain)
            result.historical_urls = hist.count
            hist_hosts = [recon._host_of(u) for u in hist.urls]
            for u in hist.js_urls():
                js_by_host.setdefault(recon._host_of(u), []).append(u)

        # Candidate hosts, in-scope and deduped. The host the caller actually
        # typed is ALWAYS included first — enumeration must never be able to drop
        # the specified target — followed by the apex, CT subdomains, and any
        # hosts seen in the archive.
        candidates = [
            h for h in dict.fromkeys(
                [original_host, domain, *enum.subdomains, *hist_hosts])
            if h and (h == domain or h.endswith("." + domain))
        ]

        # SSRF guard: never probe/scan a discovered host that resolves to an
        # internal address (a wildcard/misissued cert can name one). Bypassed
        # only by the same ALLOW_PRIVATE_TARGETS opt-in the single-target path uses.
        allow_private = os.environ.get("ALLOW_PRIVATE_TARGETS", "false").lower() == "true"
        safe_hosts: list[str] = []
        for host in candidates:
            cls = "public" if allow_private else await asyncio.to_thread(_target_ip_class, host)
            if cls == "public":
                safe_hosts.append(host)
            elif cls == "private":
                result.hosts.append(HostScan(
                    host=host, url=f"https://{host}",
                    error="skipped: resolves to a private/internal address (SSRF guard)"))
            # 'unresolved' hosts are silently dropped — nothing to scan.

        result.live_hosts = await probe_live_hosts(client, safe_hosts)

        if not result.live_hosts:
            result.error = enum.error or "no live hosts found"
            return result

        targets = result.live_hosts[:max(1, max_targets)]
        for url in targets:
            host = recon._host_of(url)
            try:
                scan = await scan_fn(target_url=url, max_crawl_pages=max_crawl_pages,
                                     verify=verify, only_verified=only_verified,
                                     seed_urls=js_by_host.get(host, []))
            except Exception as exc:  # a single host must not sink the whole run
                logger.debug("deep scan: host %s failed: %s", url, exc)
                result.hosts.append(HostScan(host=host, url=url,
                                             error=f"{type(exc).__name__}: {exc}".strip(": ")))
                continue
            result.scans.append(scan)
            result.hosts.append(_summarise_scan(host, url, scan))

    return result
