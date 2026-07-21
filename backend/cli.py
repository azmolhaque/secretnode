#!/usr/bin/env python3
"""
SecretNode CLI — run a single passive scan and emit a report.

Designed for CI/CD and one-off use (the API server + dashboard remain the
interactive path). Emits SARIF by default so it can gate a pipeline or be
uploaded to GitHub code scanning.

Examples
--------
    python cli.py https://example.com -f sarif -o secretnode.sarif
    python cli.py https://example.com --crawl 5 --fail-on-findings
    GEMINI_API_KEY=... python cli.py https://example.com --verify

Authorized use only — scan infrastructure you own or are explicitly permitted
to test. See SECURITY.md.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import os
import socket
import sys
from urllib.parse import urlparse

import historical
import orchestrator
import recon
import report
import scanner


def assert_public_target(url: str) -> None:
    """Refuse private/loopback/link-local/reserved targets (SSRF guard), unless
    ALLOW_PRIVATE_TARGETS=true is explicitly set for authorized lab testing.
    Mirrors the guard the API server applies."""
    if os.environ.get("ALLOW_PRIVATE_TARGETS", "false").lower() == "true":
        return
    host = urlparse(url).hostname
    if not host:
        raise SystemExit("Invalid target URL: no hostname")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise SystemExit(f"Could not resolve target host: {host} ({exc})")
    for _family, _t, _p, _c, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise SystemExit(
                f"Refusing to scan {host} — resolves to a private/internal address ({ip}). "
                "Set ALLOW_PRIVATE_TARGETS=true only for authorized internal-lab testing."
            )


def build_output(result: dict, fmt: str) -> str:
    if fmt == "sarif":
        return report.generate_sarif_report(result)
    if fmt == "csv":
        return report.generate_csv_report(result)
    if fmt == "html":
        return report.generate_html_report(result)
    return json.dumps(result, indent=2)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="secretnode",
        description="Passive credential-leak scanner (authorized use only).",
    )
    ap.add_argument("target", help="Target URL (must start with http:// or https://)")
    ap.add_argument("-f", "--format", choices=["sarif", "json", "csv", "html"], default="sarif")
    ap.add_argument("--crawl", type=int, default=1, help="Same-domain pages to crawl (default: 1)")
    ap.add_argument("--verify", action="store_true",
                    help="Live-verify confirmed findings against provider APIs (authorized use only)")
    ap.add_argument("--only-verified", dest="only_verified", action="store_true",
                    help="Drop confirmed-inactive findings (keep verified + unverifiable types)")
    ap.add_argument("-o", "--output", help="Write report to this file (default: stdout)")
    ap.add_argument("--fail-on-findings", action="store_true",
                    help="Exit non-zero if any confirmed findings (use as a CI gate)")
    ap.add_argument("--subdomains", action="store_true",
                    help="Passive attack-surface discovery: enumerate the target's subdomains "
                         "via Certificate Transparency (crt.sh) and print them. Never contacts "
                         "the target. Authorized use only.")
    ap.add_argument("--historical", action="store_true",
                    help="Passive path discovery: recover historically-exposed URLs for the domain "
                         "from public web archives (Wayback Machine + CommonCrawl) and print them. "
                         "Never contacts the target. Authorized use only.")
    ap.add_argument("--deep-scan", dest="deep_scan", action="store_true",
                    help="Domain-wide deep scan: enumerate subdomains, probe which hosts are live, "
                         "scan each, and write a combined report. Passive; authorized use only.")
    ap.add_argument("--max-targets", dest="max_targets", type=int, default=orchestrator.MAX_TARGETS,
                    help=f"Max live hosts to scan in a --deep-scan run (default: {orchestrator.MAX_TARGETS})")
    ap.add_argument("--with-historical", dest="with_historical", action="store_true",
                    help="In a --deep-scan, also recover historical JS bundles from public archives "
                         "(Wayback/CommonCrawl) and scan them as seeds — catches secrets in forgotten "
                         "bundles no live page links to. Slower; passive.")
    return ap


async def _run_deep_scan(args) -> int:
    """Domain-wide deep scan: enumerate → probe live hosts → scan each → combined report."""
    result = await orchestrator.run_deep_scan(
        args.target,
        max_crawl_pages=max(1, args.crawl),
        verify=args.verify,
        only_verified=args.only_verified,
        max_targets=max(1, args.max_targets),
        include_historical=args.with_historical,
    )
    if args.output:
        report_fmt = (args.format if args.format in ("json",) else "html")
        body = (json.dumps(result.to_dict(), indent=2) if report_fmt == "json"
                else report.generate_deep_scan_html(result.to_dict()))
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(body)
        print(f"Deep-scan report written to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(json.dumps(result.to_dict(), indent=2) + "\n")

    t = result.to_dict()["totals"]
    hist = f", {t['historical_urls']} historical URL(s)" if t.get("historical_urls") else ""
    print(
        f"SecretNode deep scan of {result.domain}: {t['subdomains']} subdomain(s), "
        f"{t['live_hosts']} live, {t['hosts_scanned']} scanned{hist} — "
        f"{t['confirmed']} confirmed, {t['needs_review']} needs-review, "
        f"{t['posture_issues']} posture issue(s).",
        file=sys.stderr,
    )
    if args.fail_on_findings and t["confirmed"]:
        return 1
    return 0


async def _run_subdomain_enum(target: str) -> int:
    """Passive subdomain discovery mode: expand a domain into its known subdomain
    surface from Certificate Transparency and print the results as JSON."""
    domain = recon.extract_registrable_domain(target)
    if domain is None:
        raise SystemExit(
            f"Cannot enumerate subdomains for {target!r} — need a domain "
            "(subdomain enumeration does not apply to bare IP addresses)."
        )
    async with scanner.build_client() as client:
        result = await recon.enumerate_subdomains(client, domain)
    print(json.dumps(result.to_dict(), indent=2))
    sources = ", ".join(result.sources) if result.sources else "none"
    print(
        f"SecretNode: discovered {result.count} subdomain(s) for {domain} "
        f"(sources: {sources})." + (f" [error: {result.error}]" if result.error else ""),
        file=sys.stderr,
    )
    return 0


async def _run_historical(target: str) -> int:
    """Passive path discovery: recover historically-exposed URLs from public
    archives (Wayback + CommonCrawl) — the passive alternative to brute-forcing."""
    domain = recon.extract_registrable_domain(target)
    if domain is None:
        raise SystemExit(
            f"Cannot run historical discovery for {target!r} — need a domain "
            "(does not apply to bare IP addresses)."
        )
    async with scanner.build_client() as client:
        result = await historical.discover_historical_urls(client, domain)
    print(json.dumps(result.to_dict(), indent=2))
    sources = ", ".join(result.sources) if result.sources else "none"
    print(
        f"SecretNode: recovered {result.count} historical URL(s) "
        f"({len(result.paths)} unique path(s), {len(result.js_urls())} JS) for {domain} "
        f"(sources: {sources})." + (f" [error: {result.error}]" if result.error else ""),
        file=sys.stderr,
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    # Passive discovery mode: enumerate subdomains and exit. Accepts a bare domain
    # (no scheme) since it never fetches the target — only Certificate Transparency.
    if args.subdomains:
        return asyncio.run(_run_subdomain_enum(args.target))

    # Passive historical path discovery from public archives; accepts a bare domain.
    if args.historical:
        return asyncio.run(_run_historical(args.target))

    # Domain-wide deep scan: enumerate → probe → scan each live host. Accepts a
    # bare domain; the orchestrator applies the SSRF guard per discovered host.
    if args.deep_scan:
        return asyncio.run(_run_deep_scan(args))

    if not args.target.startswith(("http://", "https://")):
        raise SystemExit("Target must start with http:// or https://")
    assert_public_target(args.target)

    result = asyncio.run(scanner.run_scan(
        target_url=args.target,
        max_crawl_pages=max(1, args.crawl),
        verify=args.verify,
        only_verified=args.only_verified,
    ))

    output = build_output(result, args.format)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output)
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(output + "\n")

    n = len(result.get("confirmed_findings", []))
    print(
        f"SecretNode: {n} confirmed finding(s) across {result.get('assets_fetched', 0)} asset(s).",
        file=sys.stderr,
    )
    if args.fail_on_findings and n:
        print(f"::error::SecretNode found {n} confirmed credential exposure(s)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
