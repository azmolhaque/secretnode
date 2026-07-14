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
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
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
