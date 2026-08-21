#!/usr/bin/env python3
"""
netguard.py — the single answer to "may this scanner send a request here?"

WHY THIS MODULE EXISTS
----------------------
The address check lived in two places (`main.assert_public_target`,
`cli.assert_public_target`) and was applied exactly once per scan: to the URL
the operator typed. Everything the scanner fetched afterwards — every redirect
hop, every discovered asset — went out unchecked, because `build_client()` sets
``follow_redirects=True`` and httpx resolves and connects on its own.

That is a real hole, not a theoretical one. A single 302 is enough:

    https://authorized-target.example/  ->  302  ->  http://169.254.169.254/…

The pre-flight check passed (the target is public), the redirect was followed,
and the cloud instance-metadata response was scanned for credentials and written
into a client report. Any open redirect on an authorized target reaches the same
place, so this does not even require a hostile target — only a common bug on a
legitimate one.

Three separate things were wrong with the unguarded chain, and they need naming
separately because they fail differently:

  1. **SSRF.** A redirect reaches loopback, RFC1918, link-local (including the
     169.254.169.254 metadata endpoint) and every other address the pre-flight
     check exists to refuse.
  2. **Scope.** `_accept_asset` refuses to *discover* a third-party host, then a
     redirect fetches one anyway. For a tool whose authorization ledger asserts
     "we only scanned what was authorised", traffic to an unauthorized host is
     the violation the ledger was built to prevent.
  3. **Attribution.** `fetch_url` returned the URL it *asked for*, never the one
     that answered. A credential served by a redirect target was reported at the
     original URL — so a client report names their own host for a secret that
     lives somewhere else, and the remediation instruction points at the wrong
     system.

FAILURE PHILOSOPHY
------------------
Address checks fail **closed**: an unresolvable host, a malformed address, an
address in any non-public class — all refused. A DNS failure is not permission
to connect.

Scope checks fail **loud**: refusing a redirect silently would trade an SSRF
for a coverage loss that nothing reports, and a scan that quietly stopped
reading is how a meaningless CLEAN verdict gets produced. The caller is handed
the reason so it can be broadcast.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlparse

import surface

# RFC 6598 shared address space (carrier-grade NAT). Not covered by
# `is_private`, and routable inside plenty of provider and campus networks —
# which is exactly the property that makes it an SSRF destination.
_CGNAT_V4 = ipaddress.ip_network("100.64.0.0/10")

# Redirect chains longer than this are either a loop or a tarpit. httpx's own
# default is 20; a passive asset fetch has no legitimate need for more than a
# handful (http->https, apex->www, path normalisation, one CDN hop).
MAX_REDIRECTS = int(os.environ.get("MAX_REDIRECTS", "5") or 5)


class BlockedTarget(Exception):
    """A URL the scanner must not request. The message is operator-facing and
    names both the host and the reason — it is surfaced in scan logs."""


def private_targets_allowed() -> bool:
    """Read at call time, never cached into a module constant.

    A cached constant is why the two previous copies of this check could
    disagree: `main.py` snapshotted the value at import while `cli.py` read it
    per call, so a test (or a `.env` reload) that changed the variable moved one
    and not the other. The check that decides whether a request leaves the
    machine should read the live setting.
    """
    return os.environ.get("ALLOW_PRIVATE_TARGETS", "false").lower() == "true"


def is_forbidden_address(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True if `ip` is anything other than an ordinary public unicast address.

    IPv4-mapped IPv6 (``::ffff:127.0.0.1``) needs no special case here —
    CPython's ``ipaddress`` already reports the mapped address's properties on
    the v6 object, so the loopback/private/link-local flags below are correct
    for it. That is worth stating rather than leaving a reader to wonder,
    because the mapped form is the classic way this check gets bypassed and
    "we tested it" is the only reason to trust that it is not bypassed here.
    """
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    ):
        return True
    if ip.version == 4 and ip in _CGNAT_V4:
        return True
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None and mapped in _CGNAT_V4:
        return True
    return False


def resolve_host(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Every address `host` resolves to. Raises BlockedTarget if it resolves to
    nothing — an unresolvable host is refused, not waved through."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise BlockedTarget(f"Could not resolve host: {host} ({exc})") from exc
    out: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for *_ignored, sockaddr in infos:
        try:
            out.append(ipaddress.ip_address(sockaddr[0]))
        except ValueError:
            # A resolver returned something that is not an address. Refusing is
            # the only safe reading; there is nothing here to connect to.
            raise BlockedTarget(f"Host {host} resolved to a malformed address: {sockaddr[0]!r}")
    if not out:
        raise BlockedTarget(f"Host {host} resolved to no addresses")
    return out


def assert_public_host(host: str) -> None:
    """Raise BlockedTarget unless every address `host` resolves to is public.

    *Every* address, not the first: a host with both a public A record and a
    private AAAA record is a rebinding primitive, and which one the HTTP client
    picks is not ours to predict.
    """
    if private_targets_allowed():
        return
    if not host:
        raise BlockedTarget("Could not parse a hostname from the target URL")
    for ip in resolve_host(host):
        if is_forbidden_address(ip):
            raise BlockedTarget(
                f"{host} resolves to a private/internal address ({ip}). "
                "Refusing to send the request — set ALLOW_PRIVATE_TARGETS=true "
                "only for authorized internal-lab testing."
            )


def assert_public_target(url: str) -> None:
    """URL-level form of `assert_public_host`, for pre-flight checks."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise BlockedTarget(
            f"Refusing a non-HTTP target URL ({parsed.scheme or 'no scheme'}://…). "
            "Only http and https are scannable."
        )
    assert_public_host(parsed.hostname or "")


def check_redirect_hop(origin_url: str, next_url: str, enforce_scope: bool) -> None:
    """Validate one hop of a redirect chain, or raise BlockedTarget.

    `origin_url` is the URL originally requested — the one the authorization and
    scope decisions were made against — not the previous hop. Chaining scope
    off the previous hop would let a chain walk anywhere one host at a time,
    which is the whole trick: A redirects to B (in scope), B redirects to C
    (in scope *for B*), and C is a host nobody authorized.
    """
    parsed = urlparse(next_url)
    if parsed.scheme not in ("http", "https"):
        raise BlockedTarget(
            f"Refusing a redirect to a non-HTTP scheme ({parsed.scheme or 'none'}): {next_url}"
        )
    host = parsed.hostname or ""
    if not host:
        raise BlockedTarget(f"Refusing a redirect with no hostname: {next_url}")

    # Scope first, addresses second, deliberately. Scope is offline,
    # deterministic and cheap; resolution is a network round-trip that tells a
    # DNS server we were interested in a host we have already decided not to
    # contact. Refusing before the lookup keeps that signal from leaving at all,
    # and makes the refusal reason the accurate one — an out-of-scope host that
    # happens not to resolve should be reported as out of scope, not as a DNS
    # failure.
    if enforce_scope:
        origin_host = urlparse(origin_url).hostname or ""
        if not surface.same_scope(origin_host, host):
            raise BlockedTarget(
                f"Redirect leaves the authorized scope: {origin_host} -> {host}. "
                "Refusing to follow — the engagement covers the target domain, "
                "not every host it redirects to."
            )

    assert_public_host(host)
