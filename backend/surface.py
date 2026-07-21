#!/usr/bin/env python3
"""
SecretNode surface intelligence — deep-ASM slices 5 & 4.

Two passive extractors that mine content the scanner has *already fetched* (no
new requests to the target beyond the deeper-crawl fetches the caller opts into):

  • extract_endpoints()  — slice 5: pull URLs and API paths referenced inside JS
    bundles / HTML (fetch()/axios targets, route strings, `/api/...` paths). This
    is the passive form of a "deeper crawl": endpoints a live page never links to
    but the JavaScript calls at runtime. Same-site .js endpoints found this way
    make excellent additional scan targets.

  • extract_referenced_hosts() — slice 4: the external hosts an asset talks to
    (CDNs, APIs, analytics, auth providers). Aggregated across a scan, these form
    the target's *associated-asset graph* — its third-party/connected-infra
    attack surface.

All regexes are bounded (no nested quantifiers) to stay linear-time / ReDoS-safe,
matching the scanner's regex-safety guarantees.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

# Absolute (or protocol-relative) URLs. Bounded character classes only.
_ABS_URL = re.compile(
    r"""(?:https?:)?//[A-Za-z0-9.\-]{1,255}(?::\d{1,5})?(?:/[^\s"'<>()\\{}]{0,2048})?"""
)
# Root-relative or ./ ../ paths appearing inside a quote — the common shape of an
# endpoint string in JS/HTML. Requires a leading slash or dot-slash to avoid
# matching arbitrary text.
_REL_PATH = re.compile(
    r"""["'](/[A-Za-z0-9_\-./~]{1,512}(?:\?[^"'\s]{0,512})?)["']"""
)

# Schemes/filetypes that are never useful as endpoints or hosts.
_SKIP_SCHEMES = ("data:", "javascript:", "mailto:", "tel:", "blob:")
_MAX_ENDPOINTS = 1000       # hard cap on what a single asset can contribute


def _valid_host(host: str) -> bool:
    """A plausible DNS hostname (has a dot, no spaces, not an obvious placeholder)."""
    host = (host or "").lower()
    if not host or " " in host or "." not in host:
        return False
    # reject things like "example" tokens with no TLD, or all-numeric non-IP junk
    return bool(re.fullmatch(r"[a-z0-9.\-]{3,255}", host)) and not host.endswith(".")


def extract_endpoints(text: str, base_url: str) -> list[str]:
    """Extract referenced URLs/paths from `text`, resolved to absolute URLs against
    `base_url`. Deterministic, deduplicated, sorted. Pure (no I/O)."""
    if not text:
        return []
    base = base_url or ""
    found: set[str] = set()
    count = 0

    for m in _ABS_URL.finditer(text):
        if count >= _MAX_ENDPOINTS:
            break
        raw = m.group(0)
        if raw.lower().startswith(_SKIP_SCHEMES):
            continue
        # Normalise protocol-relative //host/… using the base's scheme.
        absu = urljoin(base, raw) if raw.startswith("//") else raw
        p = urlparse(absu)
        if p.scheme in ("http", "https") and _valid_host(p.hostname or ""):
            found.add(absu)
            count += 1

    for m in _REL_PATH.finditer(text):
        if count >= _MAX_ENDPOINTS:
            break
        path = m.group(1)
        if path.startswith("//"):          # protocol-relative handled above
            continue
        absu = urljoin(base, path)
        p = urlparse(absu)
        if p.scheme in ("http", "https") and _valid_host(p.hostname or ""):
            found.add(absu)
            count += 1

    return sorted(found)


def extract_referenced_hosts(text: str, base_url: str) -> set[str]:
    """The set of distinct hostnames referenced by absolute URLs in `text`. Pure."""
    hosts: set[str] = set()
    for m in _ABS_URL.finditer(text):
        raw = m.group(0)
        absu = urljoin(base_url or "", raw) if raw.startswith("//") else raw
        host = (urlparse(absu).hostname or "").lower()
        if _valid_host(host):
            hosts.add(host)
    return hosts


def classify_endpoints(endpoints: list[str], base_host: str) -> tuple[list[str], list[str]]:
    """Split endpoints into (same-host, associated-hosts). same-host = endpoints on
    `base_host`; associated-hosts = the distinct OTHER hostnames referenced."""
    base_host = (base_host or "").lower()
    same: list[str] = []
    others: set[str] = set()
    for e in endpoints:
        host = (urlparse(e).hostname or "").lower()
        if host == base_host:
            same.append(e)
        elif host:
            others.add(host)
    return sorted(same), sorted(others)
