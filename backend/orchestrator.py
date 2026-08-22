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
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable
from urllib.parse import urljoin, urlparse

import httpx

import historical
import recon
import scanner
import surface
import takeover

logger = logging.getLogger("secretnode.orchestrator")


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default


MAX_TARGETS          = _env_int("MAX_TARGETS", 25)          # cap hosts scanned per run
PROBE_CONCURRENCY    = _env_int("PROBE_CONCURRENCY", 10)    # parallel liveness probes
PROBE_TIMEOUT        = _env_int("PROBE_TIMEOUT", 10)        # seconds per liveness probe
HOST_SCAN_CONCURRENCY = _env_int("HOST_SCAN_CONCURRENCY", 3)  # hosts scanned in parallel — each
                                     # host scan is itself concurrent, so keep this modest on a Pi

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
    # Public-by-design values (a Firebase web apiKey, a Stripe pk_, a Sentry
    # DSN) are examined and cleared, not dropped — v2.13.0 made that the rule
    # for a single-target scan. The deep scan counted them nowhere and carried
    # them nowhere, so a domain-wide run silently lost the one bucket whose
    # whole purpose is to show its work.
    informational: int = 0
    posture_issues: int = 0
    assets: int = 0
    error: str | None = None
    # A host may be neither scanned nor failed. One that only redirects into
    # another host in this run was deliberately not crawled a second time, and
    # reporting that as an `error` would be wrong twice: it renders red in the
    # per-host table, and the coverage check treats every errored host as
    # unexamined — which would hedge the verdict to PARTIAL over hosts whose
    # content was in fact scanned. `status`/`note` carry that case without
    # overloading a field that means "this failed".
    status: str = ""
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "host": self.host, "url": self.url, "confirmed": self.confirmed,
            "needs_review": self.needs_review, "informational": self.informational,
            "posture_issues": self.posture_issues,
            "assets": self.assets, "error": self.error,
            "status": self.status, "note": self.note,
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
    takeover_findings: list[dict] = field(default_factory=list)  # dangling-CNAME hijack risks
    duration_seconds: float = 0.0   # wall-clock for the whole run
    error: str | None = None

    @property
    def total_confirmed(self) -> int:
        return sum(h.confirmed for h in self.hosts)

    @property
    def total_needs_review(self) -> int:
        return sum(h.needs_review for h in self.hosts)

    @property
    def total_informational(self) -> int:
        return sum(h.informational for h in self.hosts)

    @property
    def total_posture(self) -> int:
        return sum(h.posture_issues for h in self.hosts)

    @property
    def total_assets(self) -> int:
        return sum(h.assets for h in self.hosts)

    @property
    def total_assets_scanned(self) -> int:
        """Coverage across the domain: downloaded plus served-from-cache."""
        return self._sum_scans("assets_scanned") or self.total_assets

    def _sum_scans(self, key: str) -> int:
        return sum(int(s.get(key, 0) or 0) for s in self.scans)

    def _aggregate(self, key: str) -> list[dict]:
        """Flatten a per-host finding list across all scans, tagging each finding
        with the host it came from so the combined report can show provenance."""
        out: list[dict] = []
        for scan in self.scans:
            host = recon._host_of(scan.get("target_url", "")) or scan.get("target_url", "")
            for f in scan.get(key, []):
                out.append({**f, "_host": host})
        return out

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "subdomains": self.subdomains,
            "enum_sources": self.enum_sources,
            "live_hosts": self.live_hosts,
            "hosts": [h.to_dict() for h in self.hosts],
            "historical_urls": self.historical_urls,
            "confirmed_findings": self._aggregate("confirmed_findings"),
            "needs_review_findings": self._aggregate("needs_review_findings"),
            # Omitting this is why a Firebase web apiKey sitting in plain sight
            # in a client's bundle appeared in no deep-scan deliverable at all.
            # It was detected, triaged and correctly classed public-by-design at
            # INFO on its host — then discarded here, so the CSV and SARIF (both
            # of which already render this bucket) had nothing to render. An
            # absent finding and an examined-and-cleared one look identical to
            # the reader, and only one of them is true.
            "informational_findings": self._aggregate("informational_findings"),
            "posture_findings": self._aggregate("posture_findings"),
            # Filtered against the scanned domain, not just each host's own base:
            # a sibling subdomain is the target's own infrastructure, and listing
            # it under "third-party / connected infrastructure" in a paid report
            # invites the obvious client question.
            "associated_hosts": sorted({
                h for s in self.scans
                for h in s.get("associated_hosts", [])
                if not surface.same_scope(self.domain, h)
            }),
            "takeover_findings": self.takeover_findings,
            # Scan-level metrics, rolled up from the per-host scans. These are
            # top-level (not nested under "totals") because report.py reads them
            # from the same keys a single-target scan uses — omitting them is
            # why a deep-scan SARIF reported "assets_fetched: 0" after crawling
            # 25 hosts, and why the CSV/HTML lost the screening funnel entirely.
            "assets_fetched": self.total_assets,
            "assets_cached": self._sum_scans("assets_cached"),
            "assets_scanned": self.total_assets_scanned,
            "raw_findings": self._sum_scans("raw_findings"),
            "validated_findings": self._sum_scans("validated_findings"),
            "suppressed_count": self._sum_scans("suppressed_count"),
            "new_findings_count": self._sum_scans("new_findings_count"),
            "recurring_findings_count": self._sum_scans("recurring_findings_count"),
            "verified_count": self._sum_scans("verified_count"),
            "unverified_count": self._sum_scans("unverified_count"),
            "filtered_unverified_count": self._sum_scans("filtered_unverified_count"),
            # Wall-clock, not the sum of per-host durations: hosts are scanned
            # concurrently, so summing them would overstate the run by the
            # concurrency factor.
            "duration_seconds": round(self.duration_seconds, 2),
            "totals": {
                "subdomains": len(self.subdomains),
                "live_hosts": len(self.live_hosts),
                "hosts_scanned": len(self.hosts),
                "historical_urls": self.historical_urls,
                "assets_fetched": self.total_assets,
                "assets_scanned": self.total_assets_scanned,
                "confirmed": self.total_confirmed,
                "needs_review": self.total_needs_review,
                "informational": self.total_informational,
                "posture_issues": self.total_posture,
                "takeover_risks": len(self.takeover_findings),
                # Present here as well as at the top level because `totals` is
                # the whole payload of the deep_scan_complete WebSocket event —
                # the dashboard has nothing else to read. Without these two it
                # showed a stale per-host asset count and a duration of 0s for
                # a run the report correctly described as 6 assets over 14
                # seconds, which is the dashboard and the deliverable
                # disagreeing about the same scan.
                "raw_findings": self._sum_scans("raw_findings"),
                "duration_seconds": round(self.duration_seconds, 2),
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


_PROBE_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})


async def _probe_one(client: httpx.AsyncClient, host: str) -> tuple[str, str] | None:
    """Return ``(base_url, redirect_host)`` for a reachable host, or None if it is
    unreachable. ANY HTTP response — including 401/403/5xx — means the host is
    live and worth scanning; only a transport error (DNS/connect/timeout) is dead.

    `redirect_host` is the host this one immediately redirects to, or "" when it
    answers directly. It is captured because the probe is the only place that
    sees it: since v2.13.0 the shared client does not follow redirects, so a 301
    arrives here intact. Without it, `www.example.com` and `example.com` look
    like two independent live hosts, and the deep scan crawls the same site
    twice — doubling the requests made against a target and doubling the asset
    and host counts the client's report claims as coverage.
    """
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            r = await client.get(url, timeout=httpx.Timeout(PROBE_TIMEOUT, connect=10.0))
        except httpx.HTTPError:
            continue
        target = ""
        if r.status_code in _PROBE_REDIRECT_CODES:
            loc = r.headers.get("location", "")
            if loc:
                target = (urlparse(urljoin(url, loc.strip())).hostname or "").lower()
        return url, target
    return None


async def probe_live_hosts(
    client: httpx.AsyncClient, hosts: list[str], *, concurrency: int = PROBE_CONCURRENCY,
) -> list[str]:
    """Concurrently probe hosts; return the reachable base URLs, order preserved."""
    return [url for url, _redirect in await probe_live_hosts_detailed(
        client, hosts, concurrency=concurrency)]


async def probe_live_hosts_detailed(
    client: httpx.AsyncClient, hosts: list[str], *, concurrency: int = PROBE_CONCURRENCY,
) -> list[tuple[str, str]]:
    """As `probe_live_hosts`, but each entry is ``(base_url, redirect_host)``."""
    sem = asyncio.Semaphore(max(1, concurrency))

    async def _guarded(h: str) -> tuple[str, str] | None:
        async with sem:
            return await _probe_one(client, h)

    results = await asyncio.gather(*(_guarded(h) for h in hosts))
    return [r for r in results if r]


def collapse_redirect_duplicates(
    probed: list[tuple[str, str]],
) -> tuple[list[str], list[tuple[str, str]]]:
    """Split probed hosts into those worth scanning and those that merely point
    at one of them.

    Returns ``(targets, collapsed)`` where `collapsed` is ``(host, redirect_host)``.

    A host is collapsed only when its redirect lands on a host that is itself
    being scanned — the common apex/www pairing. A redirect to somewhere *not*
    in the set is left alone and scanned normally: it may be the only way that
    content is reachable, and dropping it would lose coverage rather than
    duplicate work. Ordering is preserved, so the caller's cap still applies to
    a stable list.
    """
    live_hosts = {(urlparse(u).hostname or "").lower() for u, _t in probed}
    targets: list[str] = []
    collapsed: list[tuple[str, str]] = []
    kept_hosts: set[str] = set()
    for url, redirect_host in probed:
        host = (urlparse(url).hostname or "").lower()
        # `redirect_host in kept_hosts` is not enough on its own: the apex may be
        # probed after the www that points at it. Checking the full live set
        # decides the pair the same way regardless of enumeration order.
        if redirect_host and redirect_host != host and redirect_host in live_hosts:
            collapsed.append((host, redirect_host))
            continue
        targets.append(url)
        kept_hosts.add(host)
    # Every host redirecting to another that was itself collapsed would leave
    # nothing to scan (a mutual apex/www redirect loop). Falling back to the
    # unfiltered list is the safe answer: duplicate work beats no scan at all.
    if not targets and probed:
        return [u for u, _t in probed], []
    return targets, collapsed


def _summarise_scan(host: str, url: str, scan: dict) -> HostScan:
    return HostScan(
        host=host,
        url=url,
        confirmed=len(scan.get("confirmed_findings", [])),
        needs_review=len(scan.get("needs_review_findings", [])),
        informational=len(scan.get("informational_findings", [])),
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
    broadcast: Callable[[dict], Awaitable[None]] | None = None,
    enumerate_fn: EnumerateFn = recon.enumerate_subdomains,
    scan_fn: ScanFn = scanner.run_scan,
    client_factory: ClientFactory = scanner.build_client,
    discover_historical_fn: Callable[..., Awaitable["historical.HistoricalResult"]]
        = historical.discover_historical_urls,
    takeover_fn: Callable[..., Awaitable[list]] = takeover.scan_hosts_for_takeover,
) -> DeepScanResult:
    """Domain → enumerate → probe → scan each live host → aggregate.

    Falls back to scanning the bare target itself when the input is an IP or has
    no enumerable domain, so a deep scan always does *something* useful."""
    started = time.monotonic()

    # Deep scans do not use the conditional-GET cache yet: it is keyed per
    # target_url and primed by the single-target endpoint, and hosts here run
    # concurrently against shared module state. Start from empty so a deep scan
    # can never inherit a previous single scan's validators and skip an asset it
    # has never actually fetched.
    scanner.load_asset_cache({})

    domain = recon.extract_registrable_domain(target)
    if domain is None:
        # No enumerable domain (e.g. an IP): degrade to a single passive scan of
        # the given target so the deep-scan entry point is still usable.
        host = recon._host_of(target) or target
        url = target if "://" in target else f"https://{host}"
        result = DeepScanResult(domain=host)
        scan = await scan_fn(target_url=url, max_crawl_pages=max_crawl_pages,
                             verify=verify, only_verified=only_verified, broadcast=broadcast)
        result.live_hosts = [url]
        result.hosts = [_summarise_scan(host, url, scan)]
        result.scans = [scan]
        result.duration_seconds = time.monotonic() - started
        return result

    async def emit(event: dict) -> None:
        if broadcast:
            await broadcast(event)

    def log(msg: str, level: str = "INFO") -> dict:
        return {"type": "log", "level": level, "message": msg}

    original_host = recon._host_of(target)
    result = DeepScanResult(domain=domain)
    async with client_factory() as client:
        await emit(log(f"Deep scan of {domain} — enumerating subdomains (Certificate Transparency)…"))
        enum = await enumerate_fn(client, domain)
        result.subdomains = enum.subdomains
        result.enum_sources = enum.sources
        await emit(log(f"Enumerated {len(enum.subdomains)} subdomain(s)"
                       + (f" via {', '.join(enum.sources)}" if enum.sources else "")))

        # Optional: recover historical URLs (Wayback/CommonCrawl) once for the
        # domain. They enrich BOTH host discovery (hostnames seen in the archive)
        # and per-host scan seeds (archived JS bundles) — so a flaky CT source no
        # longer zeroes out the run, and forgotten bundles still get scanned.
        js_by_host: dict[str, list[str]] = {}
        hist_hosts: list[str] = []
        if include_historical:
            await emit(log("Recovering historical URLs from public archives (Wayback/CommonCrawl)…"))
            hist = await discover_historical_fn(client, domain)
            result.historical_urls = hist.count
            hist_hosts = [recon._host_of(u) for u in hist.urls]
            for u in hist.js_urls():
                js_by_host.setdefault(recon._host_of(u), []).append(u)
            await emit(log(f"Recovered {hist.count} historical URL(s); "
                           f"{sum(len(v) for v in js_by_host.values())} archived JS seed(s)"))

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

        # Subdomain-takeover pass (D1): check every in-scope host for a dangling
        # CNAME pointing at an unclaimed third-party service — a hijackable
        # subdomain. Runs on the full candidate set (a takeover target often is
        # not a "normal" live host). Best-effort; never sinks the run.
        if safe_hosts:
            await emit(log(f"Checking {len(safe_hosts)} host(s) for subdomain-takeover risk…"))
            try:
                tos = await takeover_fn(client, safe_hosts)
            except Exception as exc:  # defensive
                logger.debug("takeover pass failed: %s", exc)
                tos = []
            result.takeover_findings = [t.to_dict() if hasattr(t, "to_dict") else t for t in tos]
            if result.takeover_findings:
                await emit(log(f"⚠ {len(result.takeover_findings)} potential subdomain "
                               f"takeover(s) found", "WARN"))

        await emit(log(f"Probing {len(safe_hosts)} candidate host(s) for liveness…"))
        probed = await probe_live_hosts_detailed(client, safe_hosts)
        result.live_hosts = [u for u, _t in probed]

        # Collapse hosts that only redirect into another host already being
        # scanned. `www.example.com` 301-ing to `example.com` is one site, and
        # scanning both crawls every page twice: double the requests against the
        # target, and a report claiming twice the coverage it actually has.
        scan_urls, collapsed = collapse_redirect_duplicates(probed)
        for host, redirect_host in collapsed:
            # Recorded, never silently dropped. A host missing from the per-host
            # table with no explanation is indistinguishable from one the scan
            # failed to reach.
            result.hosts.append(HostScan(
                host=host, url=f"https://{host}", status="redirect",
                note=f"redirects to {redirect_host} — that site was scanned, not this alias",
            ))
        if collapsed:
            await emit(log(
                f"{len(collapsed)} host(s) redirect into another scanned host "
                f"({', '.join(h for h, _t in collapsed)}) — scanning each site once."
            ))

        if not result.live_hosts:
            result.error = enum.error or "no live hosts found"
            result.duration_seconds = time.monotonic() - started
            await emit(log("No live hosts to scan.", "WARN"))
            await emit({"type": "deep_scan_complete", "totals": result.to_dict()["totals"]})
            return result

        targets = scan_urls[:max(1, max_targets)]
        n = len(targets)
        await emit(log(f"{len(result.live_hosts)} host(s) live — scanning {n} "
                       f"(concurrency {HOST_SCAN_CONCURRENCY})"))

        # Scan hosts concurrently with a bounded semaphore instead of one-at-a-time.
        # Results are collected in target order; a single host failing is isolated
        # to that host and never sinks the run.
        sem = asyncio.Semaphore(max(1, HOST_SCAN_CONCURRENCY))
        done = {"n": 0}

        async def _scan_host(url: str) -> tuple[HostScan, dict | None]:
            host = recon._host_of(url)
            async with sem:
                try:
                    scan = await scan_fn(target_url=url, max_crawl_pages=max_crawl_pages,
                                         verify=verify, only_verified=only_verified,
                                         seed_urls=js_by_host.get(host, []), broadcast=broadcast)
                except Exception as exc:  # a single host must not sink the whole run
                    logger.debug("deep scan: host %s failed: %s", url, exc)
                    done["n"] += 1
                    await emit(log(f"[{done['n']}/{n}] {host} — error: {type(exc).__name__}", "WARN"))
                    # Not `f"...: {exc}".strip(": ")` — that strips a character
                    # SET from both ends, so an exception message ending in a
                    # colon lost it. Same family as the scope bug in v2.12.4.
                    detail = str(exc).strip()
                    return HostScan(
                        host=host, url=url,
                        error=f"{type(exc).__name__}: {detail}" if detail
                              else type(exc).__name__,
                    ), None
                done["n"] += 1
                await emit(log(f"[{done['n']}/{n}] {host} — done "
                               f"({len(scan.get('confirmed_findings', []))} confirmed)"))
                return _summarise_scan(host, url, scan), scan

        pairs = await asyncio.gather(*(_scan_host(u) for u in targets))
        for host_scan, scan in pairs:
            result.hosts.append(host_scan)
            if scan is not None:
                result.scans.append(scan)

    result.duration_seconds = time.monotonic() - started
    await emit({"type": "deep_scan_complete", "totals": result.to_dict()["totals"]})
    return result
