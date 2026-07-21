#!/usr/bin/env python3
"""
SecretNode historical path discovery — deep-ASM slice 3.

The passive answer to directory/content brute-forcing. Instead of hammering a
target with guessed paths (active, noisy, needs a signed RoE), we recover the
URLs it has *already exposed* from public web archives:

  • the Wayback Machine (Internet Archive) CDX index, and
  • CommonCrawl's URL index.

Both are third-party archives — no request is ever sent to the target. This
surfaces forgotten endpoints, old admin panels, stale JS bundles and API paths
that a live crawl of the current site would never link to, which is exactly
where credentials tend to linger.

Posture rules mirror the rest of the scanner: passive only, fails closed (any
source erroring yields an empty contribution, never an exception), and
authorized-scope use only.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

logger = logging.getLogger("secretnode.historical")


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default


WAYBACK_CDX_URL       = os.environ.get("WAYBACK_CDX_URL", "http://web.archive.org/cdx/search/cdx")
COMMONCRAWL_COLLINFO  = os.environ.get("COMMONCRAWL_COLLINFO", "https://index.commoncrawl.org/collinfo.json")
HISTORICAL_TIMEOUT    = _env_int("HISTORICAL_TIMEOUT", 30)
HISTORICAL_RETRIES    = _env_int("HISTORICAL_RETRIES", 2)
MAX_HISTORICAL_URLS   = _env_int("MAX_HISTORICAL_URLS", 2000)
ENABLE_COMMONCRAWL    = os.environ.get("ENABLE_COMMONCRAWL", "true").lower() == "true"

_TRANSIENT_STATUS: frozenset[int] = frozenset({429, 500, 502, 503, 504})


@dataclass
class HistoricalResult:
    """Historical URLs recovered for a domain from public archives."""
    domain: str
    urls: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def count(self) -> int:
        return len(self.urls)

    @property
    def paths(self) -> list[str]:
        """Unique URL paths across all discovered URLs — the 'hidden directories'
        view (each distinct path an archive has seen for this domain)."""
        seen: set[str] = set()
        for u in self.urls:
            p = urlparse(u).path or "/"
            seen.add(p)
        return sorted(seen)

    def js_urls(self) -> list[str]:
        """Discovered URLs that look like JavaScript — the highest-value scan
        seeds, since bundled JS is where secrets most often leak.

        Deduplicated by (host, path): archives store the same file under many
        cache-buster query strings (app.js?v=1, app.js?v=2, …); scanning each
        variant re-finds the same secrets, so we keep only one URL per unique
        file. This is what collapses e.g. 11 api_data.js?v=… variants to one."""
        seen: set[tuple[str, str]] = set()
        out: list[str] = []
        for u in self.urls:
            p = urlparse(u)
            if not p.path.lower().endswith(".js"):
                continue
            key = ((p.hostname or "").lower(), p.path)
            if key not in seen:
                seen.add(key)
                out.append(u)
        return out

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "urls": self.urls,
            "count": self.count,
            "paths": self.paths,
            "js_urls": self.js_urls(),
            "sources": self.sources,
            "error": self.error,
        }


def _in_scope(url: str, domain: str) -> bool:
    """True if `url`'s host is `domain` or a subdomain of it."""
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return False
    return bool(host) and (host == domain or host.endswith("." + domain))


def parse_wayback_cdx(payload: object, domain: str) -> list[str]:
    """Parse a Wayback CDX `output=json&fl=original` response into sorted, in-scope
    URLs. The response is a JSON array whose first row is the header ['original'].
    Pure function."""
    domain = (domain or "").strip().lower().rstrip(".")
    if isinstance(payload, (str, bytes)):
        try:
            payload = json.loads(payload)
        except (ValueError, TypeError):
            return []
    if not isinstance(payload, list):
        return []

    found: set[str] = set()
    for row in payload:
        if not isinstance(row, list) or not row:
            continue
        url = str(row[0]).strip()
        if not url or url == "original":     # skip the CDX header row
            continue
        if _in_scope(url, domain):
            found.add(url)
    return sorted(found)


def parse_commoncrawl_jsonl(text: str, domain: str) -> list[str]:
    """Parse a CommonCrawl CDX JSONL response (one JSON object per line, each with
    a `url` field) into sorted, in-scope URLs. Pure function."""
    domain = (domain or "").strip().lower().rstrip(".")
    found: set[str] = set()
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except (ValueError, TypeError):
            continue
        url = str(record.get("url", "")).strip() if isinstance(record, dict) else ""
        if url and _in_scope(url, domain):
            found.add(url)
    return sorted(found)


async def _get_with_retries(
    client: httpx.AsyncClient, url: str,
) -> tuple[httpx.Response | None, str | None]:
    """GET with backoff retries on transient statuses/timeouts. Returns
    (response, None) or (None, error-with-type-name)."""
    last_err = "no attempt made"
    for attempt in range(HISTORICAL_RETRIES + 1):
        try:
            resp = await client.get(
                url, timeout=httpx.Timeout(HISTORICAL_TIMEOUT, connect=10.0),
            )
            if resp.status_code in _TRANSIENT_STATUS and attempt < HISTORICAL_RETRIES:
                last_err = f"HTTP {resp.status_code}"
                await asyncio.sleep(2 ** attempt)
                continue
            return resp, None
        except (httpx.HTTPError, httpx.InvalidURL) as exc:
            last_err = f"{type(exc).__name__}: {exc}".rstrip(": ").strip()
            if attempt < HISTORICAL_RETRIES:
                await asyncio.sleep(2 ** attempt)
                continue
    return None, last_err


async def fetch_wayback(
    client: httpx.AsyncClient, domain: str, *, limit: int,
) -> tuple[set[str], str | None]:
    # matchType=domain covers the apex AND every subdomain in the archive.
    url = (f"{WAYBACK_CDX_URL}?url={domain}&matchType=domain&output=json"
           f"&fl=original&collapse=urlkey&limit={limit}")
    resp, err = await _get_with_retries(client, url)
    if resp is None:
        return set(), err
    if resp.status_code != 200:
        return set(), f"HTTP {resp.status_code}"
    return set(parse_wayback_cdx(resp.text, domain)), None


async def fetch_commoncrawl(
    client: httpx.AsyncClient, domain: str, *, limit: int,
) -> tuple[set[str], str | None]:
    """CommonCrawl needs two hops: discover the newest index's CDX API, then query
    it. Both fail closed."""
    resp, err = await _get_with_retries(client, COMMONCRAWL_COLLINFO)
    if resp is None:
        return set(), err
    if resp.status_code != 200:
        return set(), f"collinfo HTTP {resp.status_code}"
    try:
        indexes = json.loads(resp.text)
        cdx_api = indexes[0]["cdx-api"]          # newest index is first
    except (ValueError, TypeError, KeyError, IndexError) as exc:
        return set(), f"collinfo parse: {type(exc).__name__}"

    resp2, err2 = await _get_with_retries(
        client, f"{cdx_api}?url={domain}&matchType=domain&output=json&limit={limit}")
    if resp2 is None:
        return set(), err2
    if resp2.status_code != 200:
        return set(), f"HTTP {resp2.status_code}"
    return set(parse_commoncrawl_jsonl(resp2.text, domain)), None


async def discover_historical_urls(
    client: httpx.AsyncClient,
    domain: str,
    *,
    limit: int = MAX_HISTORICAL_URLS,
    enable_commoncrawl: bool = ENABLE_COMMONCRAWL,
) -> HistoricalResult:
    """Recover a domain's historically-exposed URLs from public archives
    (Wayback + optionally CommonCrawl), merged and deduplicated.

    Never contacts the target. Fails closed: `error` is set only when every
    enabled source fails; if any source returns data the result is usable."""
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain:
        return HistoricalResult(domain=domain, error="empty domain")

    sources: list[tuple[str, object]] = [("wayback", fetch_wayback)]
    if enable_commoncrawl:
        sources.append(("commoncrawl", fetch_commoncrawl))

    all_urls: set[str] = set()
    ok_sources: list[str] = []
    errors: list[str] = []
    for name, fetch in sources:
        try:
            urls, err = await fetch(client, domain, limit=limit)
        except Exception as exc:  # a source must never crash the run
            urls, err = set(), f"{type(exc).__name__}: {exc}".rstrip(": ").strip()
        if urls:
            all_urls |= urls
            ok_sources.append(name)
        if err:
            errors.append(f"{name}: {err}")

    urls = sorted(all_urls)
    if len(urls) > limit:
        urls = urls[:limit]

    error = None if ok_sources else ("; ".join(errors) or "no sources returned data")
    return HistoricalResult(domain=domain, urls=urls, sources=ok_sources, error=error)
