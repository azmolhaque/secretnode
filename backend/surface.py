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
from collections.abc import Iterable
from dataclasses import dataclass
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
    # A label may not be empty, which rules out a leading or trailing dot and any
    # doubled dot. Only the trailing case was checked, so `.test` — produced by
    # the comment-stripper desync above — passed as a hostname and was printed in
    # a client's "external hosts" list. A name that cannot resolve is not a host.
    if any(not label for label in host.split(".")):
        return False
    # reject things like "example" tokens with no TLD, or all-numeric non-IP junk
    return bool(re.fullmatch(r"[a-z0-9.\-]{3,255}", host))


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

    Regex literals must be tracked too, and skipping that is why v2.12.6 did not
    actually hold. A regex may contain a quote — `/['"]/g` is ordinary in any
    bundle that normalises quoting — and a scanner that only knows about strings
    reads that apostrophe as the *start* of one. From there the tracker is
    inverted for the rest of the file: real code counts as string content, and
    every subsequent comment survives untouched. It fails open, silently, and
    only on input realistic enough that no unit test used it. A live scan of
    pepsico.com still listed `i.test`, `caniuse.com`, `stackoverflow.com` and
    `raw.githubusercontent.com` — the exact strings v2.12.6 was written to
    remove — because one regex early in a bundle disabled the whole pass.

    Telling a regex literal from division is the classic JavaScript lexing
    ambiguity, and it cannot be resolved without knowing whether the previous
    token ends an expression: in `a / b` the slash divides, in `(/ab/)` it opens
    a literal. `_REGEX_MAY_FOLLOW` is that test, kept deliberately conservative —
    when the preceding token is anything that can end a value (identifier,
    literal, `)`, `]`, `}`, `++`, `--`) the slash is division.

    Two bounds keep a misread cheap. A regex literal cannot span a line, so an
    unterminated one is re-read as division rather than swallowing the file; and
    a `/` classified as division is simply skipped, which at worst restores the
    old behaviour for that one line. Guessing "regex" too eagerly is the more
    expensive error — it blanks real code and drops hosts from the graph — so
    the ambiguity resolves toward division.
    """
    out = list(text)
    i, n = 0, len(text)
    quote: str | None = None
    # Last significant (non-whitespace) character seen outside a string/comment.
    # This is what decides the `/` ambiguity below.
    prev = ""
    while i < n:
        ch = text[i]
        if quote is not None:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
                # A closed string ends a value, so a following `/` divides:
                # `"a" / 2`. Leaving `prev` at the *opening* quote would read
                # that slash as opening a regex.
                prev = ch
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
            if _regex_may_follow(text, i, prev):
                end = _skip_regex_literal(text, i)
                if end is not None:
                    # Blank the literal, delimiters included.
                    #
                    # v2.13.1 left it in place, reasoning that a regex is code
                    # rather than a comment and only its extent mattered. That
                    # was right for finding comments and wrong for what runs
                    # next: the idiomatic absolute-URL test, in more or less
                    # every bundle, spells a protocol-relative `//` out of its
                    # own escaped slashes and terminator, and `_ABS_URL` reads
                    # that as a hostname. It is why `i.test` survived that
                    # release and reached a client's "external hosts" list.
                    #
                    # Nothing is lost by blanking. A host written inside a
                    # pattern carries escaped dots, and `_valid_host` rejects a
                    # backslash, so such a host was never extractable anyway.
                    for k in range(i, end):
                        out[k] = " "
                    i = end
                    # A completed regex literal is a value, so a `/` after it
                    # divides rather than opening another literal.
                    prev = ")"
                    continue
        if not ch.isspace():
            prev = ch
        i += 1
    return "".join(out)


# Characters that, as the last token before a `/`, mean a value just ended — so
# the slash is division. Anything else (an operator, an opening bracket, a comma,
# a semicolon, or start-of-input) means a regex literal may begin here.
#
# The quote characters are here because `prev` is set to the *closing* quote when
# a string ends, and a closed string is a value: `"a" / 2` divides.
_VALUE_ENDING_CHARS = frozenset(")]}" + "\"'`")
# Keywords after which a `/` still starts a regex, even though they end in a
# letter and so look like an identifier to the character test above.
_REGEX_PRECEDING_KEYWORDS = frozenset({
    "return", "typeof", "instanceof", "in", "of", "new", "delete", "void",
    "case", "do", "else", "yield", "await", "throw",
})


def _regex_may_follow(text: str, slash: int, prev: str) -> bool:
    """True if a `/` at `slash` can open a regex literal rather than divide."""
    if not prev:
        return True                      # start of input
    if prev in _VALUE_ENDING_CHARS:
        return False                     # `)` `]` `}` end a value -> division
    if prev.isalnum() or prev in "_$":
        # An identifier or number ends a value, so this divides — unless the
        # identifier is actually a keyword like `return` or `typeof`.
        j = slash - 1
        while j >= 0 and text[j].isspace():
            j -= 1
        end = j + 1
        while j >= 0 and (text[j].isalnum() or text[j] in "_$"):
            j -= 1
        return text[j + 1:end] in _REGEX_PRECEDING_KEYWORDS
    return True                          # an operator/punctuator -> regex


def _skip_regex_literal(text: str, start: int) -> int | None:
    """Return the index just past a regex literal opening at `start`, or None if
    this is not one after all (unterminated, or running past end of line).

    A regex literal cannot contain a raw newline, so refusing to cross one bounds
    the damage of a misclassification to a single line instead of the file.
    """
    i = start + 1
    n = len(text)
    in_class = False                     # inside `[...]`, where `/` is literal
    while i < n:
        c = text[i]
        if c == "\n":
            return None
        if c in "<>":
            # Markup, not a pattern. `strip_js_comments` runs over whole HTTP
            # responses, so it sees HTML as well as JavaScript, and `</script>`
            # opens with a slash exactly where a regex literal would. Scanning
            # on from there swallows everything up to the next `/` — which in
            # `</script><img src="https://…` is the one inside the URL, so a
            # real external host was blanked out of the graph.
            #
            # That misparse existed before the body was blanked and cost
            # nothing, because the text was left in place and still matched.
            # Blanking is what made it destructive: it turned a harmless
            # mis-tokenisation into a dropped finding, which is the direction
            # this scanner treats as unacceptable. Caught by a test that
            # predates all of this work.
            #
            # A genuine JS regex containing `<` or `>` simply falls back to the
            # old behaviour for that one literal: left in place, matched as
            # before. No host is lost either way.
            return None
        if c == "\\":
            i += 2
            continue
        if c == "[":
            in_class = True
        elif c == "]":
            in_class = False
        elif c == "/" and not in_class:
            i += 1
            # Trailing flags (g, i, m, s, u, y, d, v).
            while i < n and text[i].isalpha():
                i += 1
            return i
        i += 1
    return None


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


# ─────────────────────────────────────────────────────────────────────────────
# Cloud-storage references
# ─────────────────────────────────────────────────────────────────────────────
#
# `extract_referenced_hosts` keeps the hostname and throws the path away, which
# is correct for an associated-host graph and loses the bucket name for half the
# providers: S3 and GCS both have a path style where the bucket is the first
# path segment, and Azure always puts the container there.
#
# The distinction matters because these are not the same class of fact as
# `fonts.googleapis.com`. A bucket URL in a shipped bundle names storage the
# application reaches, and whether that storage is readable by the world is the
# first question any reviewer asks — a bucket is also the one piece of
# infrastructure that can be exposed without any credential leaking at all.
#
# WHAT THIS DELIBERATELY DOES NOT DO
# ----------------------------------
# It does not request the bucket. Checking whether a bucket is public means
# issuing a LIST or a GET against third-party infrastructure that the
# authorization covering the target does not cover, and that is active probing
# of a system the client may not even own. The reference is the finding; the
# reviewer, who knows which buckets are theirs, decides what to check.

_BUCKET_NAME = re.compile(r"^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$")

# (host suffix, provider) for the virtual-hosted shapes, longest-meaningful first.
_STORAGE_HOST_SUFFIX: tuple[tuple[str, str], ...] = (
    (".s3.amazonaws.com", "AWS S3"),
    (".s3-accelerate.amazonaws.com", "AWS S3"),
    (".storage.googleapis.com", "Google Cloud Storage"),
    (".blob.core.windows.net", "Azure Blob Storage"),
    (".r2.cloudflarestorage.com", "Cloudflare R2"),
    (".digitaloceanspaces.com", "DigitalOcean Spaces"),
)

# Virtual-hosted S3 with a region in the middle: <bucket>.s3.<region>.amazonaws.com
# and the older <bucket>.s3-<region>.amazonaws.com.
_S3_REGIONAL_HOST = re.compile(
    r"^(?P<bucket>[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3[.\-][a-z0-9\-]{3,20}\.amazonaws\.com$"
)
# Path style, where the host names no bucket at all.
_S3_PATH_HOST = re.compile(r"^s3([.\-][a-z0-9\-]{3,20})?\.amazonaws\.com$")


@dataclass(frozen=True)
class StorageRef:
    """One cloud-storage location an asset refers to.

    `bucket` is kept verbatim. Masking or truncating it would make the finding
    unactionable: the reviewer needs the exact name to look it up, and a bucket
    name is not a secret — it is infrastructure, which is the whole reason this
    is reported separately from a credential.
    """

    provider: str
    bucket: str
    host: str
    style: str          # "virtual-hosted" or "path"

    def to_dict(self) -> dict:
        return {"provider": self.provider, "bucket": self.bucket,
                "host": self.host, "style": self.style}


def _first_path_segment(path: str) -> str:
    for part in (path or "").split("/"):
        if part:
            return part.lower()
    return ""


def classify_storage_url(url: str) -> "StorageRef | None":
    """Recognise one cloud-storage URL, or None. Pure function.

    Host-first rather than one combined regex: each provider's shape is checked
    on its own, which keeps every pattern bounded and makes an unrecognised
    provider a miss rather than a mis-attribution.
    """
    try:
        parts = urlparse(url)
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    if not host:
        return None

    # Virtual-hosted: the bucket is the label in front of a known suffix.
    for suffix, provider in _STORAGE_HOST_SUFFIX:
        if host.endswith(suffix):
            bucket = host[: -len(suffix)]
            # DigitalOcean puts the region between bucket and suffix
            # (<space>.<region>.digitaloceanspaces.com); keep the leftmost label.
            if provider == "DigitalOcean Spaces" and "." in bucket:
                bucket = bucket.split(".", 1)[0]
            # Azure's host names the ACCOUNT; the container is the first path
            # segment, and the container is what a reviewer needs.
            if provider == "Azure Blob Storage":
                container = _first_path_segment(parts.path)
                if not container or not _BUCKET_NAME.match(container):
                    return None
                return StorageRef(provider, container, host, "path")
            # Cloudflare R2's host names the ACCOUNT id, bucket is in the path.
            if provider == "Cloudflare R2":
                bucket = _first_path_segment(parts.path)
                if not bucket or not _BUCKET_NAME.match(bucket):
                    return None
                return StorageRef(provider, bucket, host, "path")
            if bucket and _BUCKET_NAME.match(bucket):
                return StorageRef(provider, bucket, host, "virtual-hosted")
            return None

    m = _S3_REGIONAL_HOST.match(host)
    if m:
        return StorageRef("AWS S3", m.group("bucket"), host, "virtual-hosted")

    # Path style: s3.amazonaws.com/<bucket>/… and storage.googleapis.com/<bucket>/…
    if _S3_PATH_HOST.match(host):
        bucket = _first_path_segment(parts.path)
        if bucket and _BUCKET_NAME.match(bucket):
            return StorageRef("AWS S3", bucket, host, "path")
        return None
    if host == "storage.googleapis.com":
        bucket = _first_path_segment(parts.path)
        if bucket and _BUCKET_NAME.match(bucket):
            return StorageRef("Google Cloud Storage", bucket, host, "path")
        return None
    # Backblaze serves files as f<nnn>.backblazeb2.com/file/<bucket>/<key>.
    if host.endswith(".backblazeb2.com"):
        segments = [p for p in (parts.path or "").split("/") if p]
        if len(segments) >= 2 and segments[0].lower() == "file":
            bucket = segments[1].lower()
            if _BUCKET_NAME.match(bucket):
                return StorageRef("Backblaze B2", bucket, host, "path")
        return None
    return None


def extract_storage_references(text: str, base_url: str) -> set[StorageRef]:
    """Every distinct cloud-storage location referenced by absolute URLs in
    `text`. Pure, and makes no request of its own.

    Comments are stripped first, for the same reason `extract_referenced_hosts`
    strips them: a bucket named in a code comment is documentation rather than
    infrastructure the application reaches.
    """
    found: set[StorageRef] = set()
    for m in _ABS_URL.finditer(strip_js_comments(text)):
        raw = m.group(0)
        absu = urljoin(base_url or "", raw) if raw.startswith("//") else raw
        ref = classify_storage_url(absu)
        if ref is not None:
            found.add(ref)
    return found


def dedupe_storage_references(refs: Iterable[dict]) -> list[dict]:
    """One row per `(provider, bucket)`, in a stable order.

    The same bucket is routinely referenced through more than one URL style and
    from more than one host — a path-style backup URL in one bundle and a
    virtual-hosted asset URL in another name one piece of infrastructure, and a
    reviewer checking it checks it once. The record kept is the first seen,
    which keeps `host`/`style` as an example of where the bucket was referenced
    rather than a claim that it was the only place.

    Both the single-target scan and the cross-host deep scan need exactly this
    rule, so it lives here instead of being written twice: two copies would be
    free to drift, and the one that drifted would be the one nobody reread.
    """
    by_bucket: dict[tuple[str, str], dict] = {}
    for ref in refs:
        key = (str(ref.get("provider", "")), str(ref.get("bucket", "")))
        if not key[1]:
            continue
        by_bucket.setdefault(key, dict(ref))
    return [by_bucket[k] for k in sorted(by_bucket)]


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
