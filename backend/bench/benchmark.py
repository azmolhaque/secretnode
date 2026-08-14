#!/usr/bin/env python3
"""
Measure SecretNode against the ground-truth corpus.

    python -m bench.benchmark                 # detection layer, offline
    python -m bench.benchmark --http          # full pipeline over real HTTP
    python -m bench.benchmark --json out.json # machine-readable result

Complements `bench/run_bench.py`, which scores 45 flat samples across 22
detectors through extract_secrets and stays the fast `make bench` gate. This one
covers all 63 detectors and, with --http, puts asset discovery in scope.

Two modes, because they answer different questions and conflating them is how a
benchmark starts lying:

  offline  Runs the detector layer (regex + base64/inline-JSON decode + entropy
           + placeholder filter) directly over the corpus files. No network, no
           AI, no discovery. Deterministic, fast, and the number that belongs in
           a release note — it is a property of the detectors alone.

  --http   Serves the corpus and runs a real scan against it, so discovery is in
           scope too: a secret in a bundle the spider never fetched is missed
           just as completely as one the regex never matched, and only this mode
           can see that. Requires ALLOW_PRIVATE_TARGETS=true (the SSRF guard is
           doing its job) and, for the confirmed-stage numbers, a Gemini key.

Reported per stage, never as one figure. A scanner that matches everything and
then has its AI reject it is not the same tool as one that never matched, and a
single "accuracy" number hides which one you have.
"""

from __future__ import annotations

import argparse
import asyncio
import http.server
import json
import os
import socketserver
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "benchmark")

import scanner  # noqa: E402
from bench import groundtruth as corpus_mod  # noqa: E402


@dataclass
class Result:
    mode: str
    found_values: set[str] = field(default_factory=set)
    found_by_pattern: dict[str, set[str]] = field(default_factory=dict)
    extra: list[tuple[str, str]] = field(default_factory=list)   # (pattern, value)
    assets: int = 0
    duration: float = 0.0
    stage_counts: dict[str, int] = field(default_factory=dict)


def _score(c: corpus_mod.Corpus, res: Result) -> dict:
    """Precision and recall against declared ground truth.

    A planted value counts as found only when the detector that reports it is
    the one the corpus declared. Right value, wrong type is not a hit: the
    remediation text, the severity and the live verifier all key off the type,
    so a misattributed finding sends the client to the wrong provider."""
    expected = [s for s in c.specimens]
    hits, misses, mistyped = [], [], []

    # Compare on the same form the pipeline reports. Findings carry
    # `_cap_raw(value)` — head + tail, capped at RAW_MATCH_CAP — so a naive
    # comparison against the full planted value scored every credential longer
    # than 80 characters as both a miss AND a false positive. Seven of the
    # sixty-three, all of them the long ones: JWT, Azure, Firebase FCM.
    def forms(value: str) -> set[str]:
        return {value, scanner._cap_raw(value)}

    for s in expected:
        by_pattern = res.found_by_pattern.get(s.pattern, set())
        if forms(s.value) & by_pattern:
            hits.append(s)
        elif forms(s.value) & res.found_values:
            mistyped.append(s)
        else:
            misses.append(s)

    planted_forms: set[str] = set()
    for s in expected:
        planted_forms |= forms(s.value)
    seen_fp: set[tuple[str, str]] = set()
    decoy_hits = []
    for pat, val in res.extra:
        if val in planted_forms or (pat, val) in seen_fp:
            continue
        seen_fp.add((pat, val))
        decoy_hits.append((pat, val))

    tp, fn, fp = len(hits), len(misses) + len(mistyped), len(decoy_hits)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    return {
        "mode": res.mode,
        "planted": len(expected),
        "decoys": len(c.decoys),
        "true_positives": tp,
        "false_negatives": len(misses),
        "mistyped": len(mistyped),
        "false_positives": fp,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "assets_scanned": res.assets,
        "duration_seconds": round(res.duration, 2),
        "stage_counts": res.stage_counts,
        "missed_detectors": sorted(s.pattern for s in misses),
        "mistyped_detectors": sorted(s.pattern for s in mistyped),
        "false_positive_values": [
            {"pattern": p, "value_prefix": v[:12] + "…"} for p, v in decoy_hits
        ],
        # Travels with the number, in both the printed report and the JSON, so
        # it cannot be quoted without its qualifier.
        "validity_caveat": (
            "Recall here is INTERNAL validity only: the specimens were built to "
            "satisfy SecretNode's own patterns, so a detector matching its own "
            "canonical example proves the detector is wired up, not that it "
            "catches credentials in the wild. This is a regression net and a "
            "precision measurement, not an external-validity study. A defensible "
            "recall number needs a corpus nobody derived from these regexes — "
            "SecretBench, or the gitleaks/trufflehog fixtures."
        ),
    }


def run_offline(c: corpus_mod.Corpus) -> Result:
    res = Result(mode="offline (detection layer)")
    started = time.monotonic()
    for rel, content in c.files.items():
        res.assets += 1
        # scanner.scan_asset, not extract_secrets: the pipeline scans a source
        # map as its decoded originals, and a harness that skips that step
        # measures itself rather than the scanner.
        for _attributed_url, findings in scanner.scan_asset(
            "bench", "http://corpus.local", f"http://corpus.local/{rel}", content
        ):
            for f in findings:
                res.found_values.add(f.raw_match)
                res.found_by_pattern.setdefault(f.secret_type, set()).add(f.raw_match)
                res.extra.append((f.secret_type, f.raw_match))
    res.duration = time.monotonic() - started
    res.stage_counts = {"raw_findings": len(res.extra)}
    return res


class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *_args):  # keep the benchmark output readable
        pass


def _serve(directory: Path, port: int) -> socketserver.TCPServer:
    handler = lambda *a, **kw: _QuietHandler(*a, directory=str(directory), **kw)  # noqa: E731
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("127.0.0.1", port), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def run_http(c: corpus_mod.Corpus, directory: Path, port: int) -> Result:
    if os.environ.get("ALLOW_PRIVATE_TARGETS", "").lower() != "true":
        raise SystemExit(
            "HTTP mode scans 127.0.0.1, which the SSRF guard refuses by default.\n"
            "This is authorised lab use of a corpus you just generated, so:\n"
            "  ALLOW_PRIVATE_TARGETS=true python -m bench.benchmark --http")

    res = Result(mode="http (full pipeline)")
    httpd = _serve(directory, port)
    try:
        started = time.monotonic()
        scan = asyncio.run(scanner.run_scan(
            target_url=f"http://127.0.0.1:{port}/",
            scan_id="benchmark",
            max_crawl_pages=2,
        ))
        res.duration = time.monotonic() - started
    finally:
        httpd.shutdown()
        httpd.server_close()

    res.assets = int(scan.get("assets_fetched", 0) or 0)
    res.stage_counts = {
        k: int(scan.get(k, 0) or 0)
        for k in ("assets_fetched", "raw_findings", "validated_findings",
                  "suppressed_count")
    }
    res.stage_counts["confirmed"] = len(scan.get("confirmed_findings", []))
    res.stage_counts["needs_review"] = len(scan.get("needs_review_findings", []))

    # Score against everything the pipeline surfaced to a human — confirmed and
    # needs-review alike. Counting only `confirmed` would score the Gemini key's
    # presence rather than the scanner, and the two must not be conflated.
    for bucket in ("confirmed_findings", "needs_review_findings"):
        for f in scan.get(bucket, []):
            value = f.get("matched_value") or f.get("raw_match") or ""
            stype = f.get("secret_type", "")
            if not value:
                continue
            res.found_values.add(value)
            res.found_by_pattern.setdefault(stype, set()).add(value)
            res.extra.append((stype, value))
    return res


def _print(report: dict, c: corpus_mod.Corpus) -> None:
    print(f"\n{'=' * 68}")
    print(f"  SecretNode {scanner.version.TOOL_VERSION} — {report['mode']}")
    print(f"{'=' * 68}")
    print(f"  Corpus: {report['planted']} planted secrets across "
          f"{len(scanner.SECRET_PATTERNS)} detectors, {report['decoys']} decoys")
    print(f"  Assets scanned: {report['assets_scanned']}   "
          f"Duration: {report['duration_seconds']}s")
    if report["stage_counts"]:
        print("  Funnel: " + "  ".join(f"{k}={v}" for k, v in report["stage_counts"].items()))
    print()
    print(f"  True positives   {report['true_positives']:>3} / {report['planted']}")
    print(f"  False negatives  {report['false_negatives']:>3}   (planted, never reported)")
    print(f"  Mistyped         {report['mistyped']:>3}   (found, wrong detector)")
    print(f"  False positives  {report['false_positives']:>3}   (decoy reported as a secret)")
    print()
    print(f"  Precision {report['precision']:.3f}    "
          f"Recall {report['recall']:.3f}    F1 {report['f1']:.3f}")
    print(f"\n  {report['validity_caveat']}")

    if report["missed_detectors"]:
        print(f"\n  Missed ({len(report['missed_detectors'])}):")
        for name in report["missed_detectors"]:
            print(f"    · {name}")
    if report["mistyped_detectors"]:
        print(f"\n  Mistyped ({len(report['mistyped_detectors'])}):")
        for name in report["mistyped_detectors"]:
            print(f"    · {name}")
    if report["false_positive_values"]:
        print(f"\n  False positives ({len(report['false_positive_values'])}):")
        for fp in report["false_positive_values"]:
            print(f"    · {fp['pattern']}: {fp['value_prefix']}")
    print()


def main() -> int:
    ap = argparse.ArgumentParser(description="Benchmark SecretNode against ground truth.")
    ap.add_argument("--http", action="store_true",
                    help="Serve the corpus and run a full scan (needs ALLOW_PRIVATE_TARGETS=true)")
    ap.add_argument("--port", type=int, default=8137)
    ap.add_argument("--dir", type=Path, default=Path("bench-corpus"))
    ap.add_argument("--json", type=Path, help="Write the report as JSON")
    ap.add_argument("--fail-under", type=float, default=None,
                    help="Exit non-zero if F1 falls below this (CI gate)")
    args = ap.parse_args()

    c = corpus_mod.write(args.dir)
    res = run_http(c, args.dir, args.port) if args.http else run_offline(c)
    report = _score(c, res)
    _print(report, c)

    if args.json:
        args.json.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"  JSON written to {args.json}\n")

    if args.fail_under is not None and report["f1"] < args.fail_under:
        print(f"  FAIL: F1 {report['f1']:.3f} < {args.fail_under}\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
