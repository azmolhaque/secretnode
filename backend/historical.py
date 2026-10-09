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
from datetime import date
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
    # URL -> earliest archive capture date, ISO `YYYY-MM-DD`.
    #
    # The CDX index returns a timestamp on every row at no extra cost, and this
    # module threw it away for three releases by asking for `fl=original` alone.
    # That timestamp is the only thing in the whole scanner that can answer
    # "how long has this credential been public?", which is the question that
    # separates "rotate" from "rotate and assume it has been used".
    #
    # Populated only from Wayback: CommonCrawl's index is queried per-collection
    # and its timestamps describe the crawl, not the first appearance of the URL.
    first_seen: dict[str, str] = field(default_factory=dict)

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
            "first_seen": self.first_seen,
        }


def _in_scope(url: str, domain: str) -> bool:
    """True if `url`'s host is `domain` or a subdomain of it."""
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return False
    return bool(host) and (host == domain or host.endswith("." + domain))


def _cdx_date(stamp: str) -> str | None:
    """`20210314071233` -> `2021-03-14`, or None if it is not a CDX timestamp.

    Only the date is kept. The hour a crawler happened to visit is noise against
    a question measured in months, and a narrower value invites false precision.
    """
    digits = (stamp or "").strip()
    if len(digits) < 8 or not digits[:8].isdigit():
        return None
    year, month, day = digits[:4], digits[4:6], digits[6:8]
    if not ("1990" <= year <= "2100" and "01" <= month <= "12" and "01" <= day <= "31"):
        return None
    return f"{year}-{month}-{day}"


def parse_wayback_cdx(
    payload: object, domain: str, *, with_dates: bool = False,
) -> list[str] | tuple[list[str], dict[str, str]]:
    """Parse a Wayback CDX `output=json` response into sorted, in-scope URLs.

    The response is a JSON array whose first row is the header. This module now
    requests `fl=original,timestamp`, so each row carries the capture date as
    well; with `with_dates=True` the earliest date seen per URL is returned
    alongside. Pure function.

    The default return stays a bare list because `with_dates` was added after
    callers existed, and a parser that changes shape underneath them is a
    worse bargain than one extra keyword.
    """
    domain = (domain or "").strip().lower().rstrip(".")
    if isinstance(payload, (str, bytes)):
        try:
            payload = json.loads(payload)
        except (ValueError, TypeError):
            return ([], {}) if with_dates else []
    if not isinstance(payload, list):
        return ([], {}) if with_dates else []

    found: set[str] = set()
    earliest: dict[str, str] = {}
    for row in payload:
        if not isinstance(row, list) or not row:
            continue
        url = str(row[0]).strip()
        if not url or url == "original":     # skip the CDX header row
            continue
        if not _in_scope(url, domain):
            continue
        found.add(url)
        if len(row) > 1:
            date = _cdx_date(str(row[1]))
            # Keep the EARLIEST. `collapse=urlkey` already gives one capture per
            # URL in timestamp order, but the min() makes that an assertion
            # rather than a dependency on how the index happens to sort.
            if date and (url not in earliest or date < earliest[url]):
                earliest[url] = date
    urls = sorted(found)
    return (urls, earliest) if with_dates else urls


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


@dataclass(frozen=True)
class Exposure:
    """How long a credential has been reachable, and what that changes."""

    first_seen: str          # ISO date of the earliest archive capture
    days: int                # days from that capture to today
    still_served: bool       # found in the live scan as well as the archive
    verdict: str             # one line, for a report
    advice: str              # how remediation changes, or "" when it does not

    def to_dict(self) -> dict:
        return {
            "first_seen": self.first_seen,
            "days": self.days,
            "still_served": self.still_served,
            "verdict": self.verdict,
            "advice": self.advice,
        }


def _humanise(days: int) -> str:
    if days < 1:
        return "under a day"
    if days < 60:
        return f"{days} days"
    if days < 730:
        return f"{days // 30} months"
    years = days / 365.25
    return f"{years:.1f} years"


def exposure_window(
    first_seen: str, *, still_served: bool, today: date | None = None,
) -> Exposure | None:
    """What an archive capture date means for one credential. Pure function.

    This is the question no other scanner in this niche answers, because most
    never fetch the archive. SecretNode already pays that cost; until now it
    discarded the answer.

    Two situations the report has never been able to tell apart:

      still served   the credential is in a bundle the archive first captured
                     N days ago AND in the one served today. It has been
                     readable by anyone for that whole window, so remediation
                     is not "rotate" — it is "rotate and assume it was used".

      archive only   it was in a bundle once and is not in the current one.
                     That is the scanner reporting GOOD news, which it has had
                     no way to express. Worth saying rather than staying silent:
                     a reader who sees nothing cannot tell a fixed exposure from
                     one that was never looked for.

    Returns None when the date is unusable or in the future — a clock skew or a
    malformed row must not produce a confident claim about a time window.
    """
    try:
        y, m, d = (int(part) for part in first_seen.split("-"))
        seen = date(y, m, d)
    except (ValueError, AttributeError):
        return None
    now = today or date.today()
    days = (now - seen).days
    if days < 0:
        return None

    span = _humanise(days)
    if still_served:
        return Exposure(
            first_seen=first_seen, days=days, still_served=True,
            verdict=(f"Public since at least {first_seen} — {span}. The archive holds "
                     f"a copy of this asset from that date and it is still served today."),
            advice=("Rotate, and treat the credential as used rather than merely "
                    "exposed: anyone who looked in that window could have taken it, "
                    "and archive copies stay readable after the live asset changes. "
                    "Check the provider's audit log over the same period."),
        )
    return Exposure(
        first_seen=first_seen, days=days, still_served=False,
        verdict=(f"Present in an archived copy from {first_seen} ({span} ago) and NOT "
                 f"in the asset served today — it appears to have been removed or rotated."),
        advice=("No action needed on the live asset. The archived copy stays "
                "readable, so confirm the credential was rotated rather than just "
                "deleted from the file — removing a secret from a bundle does not "
                "revoke it."),
    )


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
) -> tuple[set[str], str | None, dict[str, str]]:
    # matchType=domain covers the apex AND every subdomain in the archive.
    # `fl=original,timestamp`, not `fl=original`. The timestamp is returned at
    # no extra cost and is what makes exposure duration answerable; asking for
    # the URL alone discarded it on every scan this scanner has ever run.
    url = (f"{WAYBACK_CDX_URL}?url={domain}&matchType=domain&output=json"
           f"&fl=original,timestamp&collapse=urlkey&limit={limit}")
    resp, err = await _get_with_retries(client, url)
    if resp is None:
        return set(), err, {}
    if resp.status_code != 200:
        return set(), f"HTTP {resp.status_code}", {}
    urls, dates = parse_wayback_cdx(resp.text, domain, with_dates=True)
    return set(urls), None, dates


async def fetch_commoncrawl(
    client: httpx.AsyncClient, domain: str, *, limit: int,
) -> tuple[set[str], str | None, dict[str, str]]:
    """CommonCrawl needs two hops: discover the newest index's CDX API, then query
    it. Both fail closed.

    Returns no dates. CommonCrawl is queried against ONE collection — the newest
    — so its timestamps say when that crawl ran, not when the URL first appeared.
    Reporting a 2026 crawl date as a first-seen for a URL archived in 2019 would
    understate an exposure, which is the direction that matters. Wayback's index
    spans all time and is the honest source for this.
    """
    resp, err = await _get_with_retries(client, COMMONCRAWL_COLLINFO)
    if resp is None:
        return set(), err, {}
    if resp.status_code != 200:
        return set(), f"collinfo HTTP {resp.status_code}", {}
    try:
        indexes = json.loads(resp.text)
        cdx_api = indexes[0]["cdx-api"]          # newest index is first
    except (ValueError, TypeError, KeyError, IndexError) as exc:
        return set(), f"collinfo parse: {type(exc).__name__}", {}

    resp2, err2 = await _get_with_retries(
        client, f"{cdx_api}?url={domain}&matchType=domain&output=json&limit={limit}")
    if resp2 is None:
        return set(), err2, {}
    if resp2.status_code != 200:
        return set(), f"HTTP {resp2.status_code}", {}
    return set(parse_commoncrawl_jsonl(resp2.text, domain)), None, {}


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
    first_seen: dict[str, str] = {}
    ok_sources: list[str] = []
    errors: list[str] = []
    for name, fetch in sources:
        try:
            urls, err, dates = await fetch(client, domain, limit=limit)
        except Exception as exc:  # a source must never crash the run
            urls, err, dates = set(), f"{type(exc).__name__}: {exc}".rstrip(": ").strip(), {}
        if urls:
            all_urls |= urls
            ok_sources.append(name)
        for url, captured in dates.items():
            # Earliest wins across sources, for the same reason it does within
            # one: an exposure window must never be reported shorter than the
            # evidence supports.
            if url not in first_seen or captured < first_seen[url]:
                first_seen[url] = captured
        if err:
            errors.append(f"{name}: {err}")

    urls = sorted(all_urls)
    if len(urls) > limit:
        urls = urls[:limit]
    kept = set(urls)
    first_seen = {u: d for u, d in first_seen.items() if u in kept}

    error = None if ok_sources else ("; ".join(errors) or "no sources returned data")
    return HistoricalResult(domain=domain, urls=urls, sources=ok_sources, error=error,
                            first_seen=first_seen)
