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
    `base_url`. Deterministic, deduplicated, sorted. Pure (no I/O).

    Comments are stripped first — a URL in a comment is a citation, not an
    endpoint, and feeding it to the deeper crawl spends a fetch on someone's
    blog post."""
    if not text:
        return []
    text = strip_js_comments(text)
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


def strip_js_comments(text: str) -> str:
    """Blank out `//` line comments and `/* … */` blocks, leaving string
    literals and total length untouched (newlines are preserved, so offsets and
    line numbers still line up).

    Surface intel only. This must NEVER be applied on the secret-detection path:
    credentials hide in comments, and blanking them there would be a false
    negative — the one failure this scanner treats as unacceptable.

    Why it exists: `_ABS_URL` matches protocol-relative `//host`, and a minified
    bundle is full of `//console.log(…)` and `//i.test(v)`. Those were parsed as
    hostnames and shipped to clients under the heading "third-party / connected
    infrastructure", alongside every documentation link a bundled library
    happens to cite — stackoverflow.com, caniuse.com, pastebin.com, an author's
    personal blog. A denylist cannot keep up with that; removing comments
    addresses the cause rather than enumerating the symptoms.
    """
    out = list(text)
    i, n = 0, len(text)
    quote: str | None = None
    while i < n:
        ch = text[i]
        if quote is not None:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in "\"'`":
            quote = ch
            i += 1
            continue
        if ch == "/" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "/":
                end = text.find("\n", i)
                end = n if end == -1 else end
                for k in range(i, end):
                    out[k] = " "
                i = end
                continue
            if nxt == "*":
                end = text.find("*/", i + 2)
                end = n if end == -1 else end + 2
                for k in range(i, end):
                    if out[k] != "\n":
                        out[k] = " "
                i = end
                continue
        i += 1
    return "".join(out)


def extract_referenced_hosts(text: str, base_url: str) -> set[str]:
    """The set of distinct hostnames referenced by absolute URLs in `text`. Pure.

    Comments are removed first: a host cited in a code comment is documentation,
    not infrastructure the target talks to."""
    hosts: set[str] = set()
    for m in _ABS_URL.finditer(strip_js_comments(text)):
        raw = m.group(0)
        absu = urljoin(base_url or "", raw) if raw.startswith("//") else raw
        host = (urlparse(absu).hostname or "").lower()
        if _valid_host(host):
            hosts.add(host)
    return hosts


def same_scope(base_host: str, candidate_host: str) -> bool:
    """True if candidate_host is base_host or a subdomain of it, treating a
    leading `www.` on the base as equivalent to the bare host.

    The `www.` prefix MUST be removed with a prefix check, never with
    str.lstrip("www."). lstrip strips any leading character that appears in the
    SET {'w', '.'}, which is not prefix removal:

        "web3forms.com".lstrip("www.")  ->  "eb3forms.com"
        "wwf.org".lstrip("www.")        ->  "f.org"

    The first admitted eb3forms.com — a domain nobody authorized — as in-scope,
    and this gate decides whether the scanner issues a request, so that was a
    real out-of-scope fetch. The second rejected assets.wwf.org while scanning
    wwf.org, silently reducing coverage on a legitimate target. Every existing
    test used example.com, where the lstrip happens to be a no-op.
    """
    base = (base_host or "").lower().strip().strip(".")
    cand = (candidate_host or "").lower().strip().strip(".")
    if not base or not cand:
        return False
    base = base.removeprefix("www.")
    return cand == base or cand.endswith("." + base)


def classify_endpoints(
    endpoints: list[str],
    base_host: str,
    scope_hosts: set[str] | None = None,
) -> tuple[list[str], list[str]]:
    """Split endpoints into (in-scope, associated-hosts).

    In-scope means the endpoint belongs to the target itself: `base_host`, a
    host named in `scope_hosts` (a deep scan's enumerated subdomains), or any
    host sharing the same registrable root. Comparing hostnames by exact string
    put the target's own apex into the client-facing "third-party / connected
    infrastructure" table whenever the scan ran against www., and dropped every
    cross-subdomain endpoint from the in-scope list — which is why scanning
    cindrasec.com and www.cindrasec.com, serving byte-identical content,
    reported 24 endpoints / 8 associated hosts against 19 / 9.
    """
    base = (base_host or "").lower()
    scope = {h.lower().strip(".") for h in (scope_hosts or set()) if h}
    same: list[str] = []
    others: set[str] = set()
    for e in endpoints:
        host = (urlparse(e).hostname or "").lower()
        if not host:
            continue
        if host == base or host in scope or same_scope(base, host):
            same.append(e)
        else:
            others.add(host)
    return sorted(same), sorted(others)
