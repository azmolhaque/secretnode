#!/usr/bin/env python3
"""
SecretNode — Watch: multi-target continuous-monitoring delivery.

WHAT THIS ADDS OVER A PLAIN SCAN
--------------------------------
`run_scan` answers "what is exposed right now?" for one target. Continuous
monitoring has to answer a different question: **what changed since last time,
and does any of it need a human today?**

SecretNode already tracks `new_findings_count` and `recurring_findings_count`.
What it has never tracked is the opposite direction — findings that were present
last month and are gone now. That omission matters commercially as much as
technically: a monitoring subscription proves its worth by showing what got
fixed, and until now the data to say so was thrown away.

    scan(t0) ─┐
              ├─► compute_delta ─► WatchDelta{new, resolved, recurring}
    scan(t1) ─┘                          │
                                         ├─► classify() ─► URGENT / REVIEW / ROUTINE
                                         └─► render_digest() ─► client-facing draft

THE RESOLUTION TRAP (read before changing compute_delta)
--------------------------------------------------------
A finding can vanish from a scan for two completely different reasons:

  1. Someone rotated the credential or removed the file.   → genuinely resolved
  2. This run simply saw less than last run — the asset 404'd, a WAF blocked
     the fetch, the crawl budget ran out, the scan errored halfway.

Only the first is "fixed". Reporting the second to a paying client as "resolved"
is a false statement in a deliverable, and it is the failure mode this module is
most likely to produce, because both cases look *identical* in the findings list.

So resolution is asserted only when the current scan completed AND its coverage
is comparable to the previous run. Otherwise the disappearances are surfaced as
`unverified_disappearances` and the digest says plainly that it could not tell.
A weaker claim that is true beats a stronger one that might not be.

WHAT THIS MODULE DELIBERATELY DOES NOT DO
-----------------------------------------
It does not send anything to a client. `render_digest()` produces a *draft* for
human review. Two checkpoints are never automated in this business — the
authorization to scan at all, and the final severity call on anything critical —
and a monitoring loop that emailed clients on its own would quietly erase the
second one.
"""

from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

# Severity ordering, most severe first. Mirrors the pattern registry's vocabulary
# in scanner.py; anything unrecognised sorts last rather than raising, because a
# monitoring run must not die on an unexpected severity string.
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# A new finding at or above this severity wakes a human the same day rather than
# waiting for the monthly digest.
URGENT_SEVERITIES = frozenset({"critical", "high"})

# If this run scanned less than this fraction of what the previous run scanned,
# treat missing findings as "could not confirm" rather than "resolved". 0.5 is
# deliberately generous: normal churn (a bundle renamed, one page redirecting)
# moves coverage by a few percent, so anything near half is a real anomaly.
COVERAGE_PARITY_THRESHOLD = 0.5

ROSTER_PATH = pathlib.Path(__file__).parent.parent / "watch-roster.json"


def _severity_rank(sev: str) -> int:
    try:
        return SEVERITY_ORDER.index((sev or "").lower())
    except ValueError:
        return len(SEVERITY_ORDER)


@dataclass
class WatchTarget:
    """One monitored asset in the roster."""
    client: str
    target_url: str
    crawl_pages: int = 3
    deep: bool = False
    verify: bool = False
    notes: str = ""

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "WatchTarget":
        missing = [k for k in ("client", "target_url") if not d.get(k)]
        if missing:
            raise ValueError(f"watch roster entry missing required field(s): {', '.join(missing)}")
        return WatchTarget(
            client=str(d["client"]),
            target_url=str(d["target_url"]),
            crawl_pages=int(d.get("crawl_pages", 3)),
            deep=bool(d.get("deep", False)),
            verify=bool(d.get("verify", False)),
            notes=str(d.get("notes", "")),
        )


@dataclass
class WatchDelta:
    """What changed for one target between two scans.

    `resolution_confirmed` is the honesty flag: when False, `resolved` is empty
    and anything that disappeared is in `unverified_disappearances` instead.
    """
    target_url: str
    current_scan_id: str
    previous_scan_id: str | None
    new: list[dict[str, Any]] = field(default_factory=list)
    resolved: list[dict[str, Any]] = field(default_factory=list)
    recurring: list[dict[str, Any]] = field(default_factory=list)
    unverified_disappearances: list[dict[str, Any]] = field(default_factory=list)
    first_run: bool = False
    resolution_confirmed: bool = True
    coverage_note: str = ""

    @property
    def has_changes(self) -> bool:
        return bool(self.new or self.resolved or self.unverified_disappearances)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "current_scan_id": self.current_scan_id,
            "previous_scan_id": self.previous_scan_id,
            "new": self.new,
            "resolved": self.resolved,
            "recurring": self.recurring,
            "unverified_disappearances": self.unverified_disappearances,
            "first_run": self.first_run,
            "resolution_confirmed": self.resolution_confirmed,
            "coverage_note": self.coverage_note,
        }


def _coverage_of(scan: dict[str, Any]) -> int:
    """Assets actually examined by a scan.

    Prefers `assets_scanned` (v2.8.0 split coverage from download count) and
    falls back to `assets_fetched` for scans recorded before that existed —
    a Watch client's history predates the field, and treating an older row as
    zero coverage would flag every first comparison as an anomaly.
    """
    for key in ("assets_scanned", "assets_fetched"):
        val = scan.get(key)
        if isinstance(val, int) and val > 0:
            return val
    return 0


def compute_delta(
    current: dict[str, Any],
    previous: dict[str, Any] | None,
) -> WatchDelta:
    """Diff two scan records by finding fingerprint. Pure — no DB, no network.

    Identity is `fingerprint` (sha256 of secret_type|source_url|raw_match), so a
    rotated credential at the same location reads as one resolved + one new
    rather than one unchanged. That is the correct reading: the old value is no
    longer exposed and a different one now is.
    """
    cur_findings = current.get("confirmed_findings") or []
    cur_by_fp = {f.get("fingerprint"): f for f in cur_findings if f.get("fingerprint")}

    if previous is None:
        return WatchDelta(
            target_url=current.get("target_url", ""),
            current_scan_id=current.get("scan_id", ""),
            previous_scan_id=None,
            new=list(cur_by_fp.values()),
            first_run=True,
            coverage_note="First run for this target — everything is reported as new by definition.",
        )

    prev_findings = previous.get("confirmed_findings") or []
    prev_by_fp = {f.get("fingerprint"): f for f in prev_findings if f.get("fingerprint")}

    new = [f for fp, f in cur_by_fp.items() if fp not in prev_by_fp]
    recurring = [f for fp, f in cur_by_fp.items() if fp in prev_by_fp]
    disappeared = [f for fp, f in prev_by_fp.items() if fp not in cur_by_fp]

    # ── The resolution trap (see module docstring) ──────────────────────────
    cur_cov, prev_cov = _coverage_of(current), _coverage_of(previous)
    status_ok = str(current.get("status", "")).lower() in {"complete", "clean"}
    coverage_ok = prev_cov == 0 or (cur_cov / prev_cov) >= COVERAGE_PARITY_THRESHOLD
    confirmed = status_ok and coverage_ok

    if confirmed:
        note = ""
        if disappeared:
            note = (
                f"Coverage comparable to the previous run ({cur_cov} vs {prev_cov} assets), "
                f"so findings absent this run are reported as resolved."
            )
    elif not status_ok:
        note = (
            f"Current scan status is '{current.get('status')}', not a clean completion. "
            f"Findings absent this run are NOT reported as resolved — the scan may simply "
            f"not have reached them."
        )
    else:
        note = (
            f"Coverage dropped materially ({cur_cov} assets this run vs {prev_cov} previously). "
            f"Findings absent this run are NOT reported as resolved: a finding can vanish "
            f"because it was fixed, or because this run never looked at the asset holding it, "
            f"and these are indistinguishable from the findings list alone."
        )

    return WatchDelta(
        target_url=current.get("target_url", ""),
        current_scan_id=current.get("scan_id", ""),
        previous_scan_id=previous.get("scan_id"),
        new=new,
        resolved=disappeared if confirmed else [],
        recurring=recurring,
        unverified_disappearances=[] if confirmed else disappeared,
        first_run=False,
        resolution_confirmed=confirmed,
        coverage_note=note,
    )


def classify(delta: WatchDelta) -> tuple[str, list[str]]:
    """Decide whether this delta needs a human today. Returns (tier, reasons).

    URGENT  — a new finding that is high/critical, or any new finding confirmed
              to be a live credential. Severity alone understates a verified key:
              a MEDIUM secret that is provably active is a working way in, and
              waiting a month to mention it is indefensible.
    REVIEW  — new findings below that bar, or a delta this module could not read
              confidently (coverage anomaly, failed scan). A human confirms
              before anything reaches the client.
    ROUTINE — nothing new; recurring/resolved only. Goes in the digest.
    """
    reasons: list[str] = []

    for f in delta.new:
        sev = (f.get("severity") or "").lower()
        stype = f.get("secret_type", "unknown")
        if f.get("verified") == "verified":
            reasons.append(f"New finding confirmed live: {stype} ({sev or 'unrated'})")
        elif sev in URGENT_SEVERITIES:
            reasons.append(f"New {sev.upper()} finding: {stype}")

    if reasons:
        return "URGENT", reasons

    if not delta.resolution_confirmed:
        return "REVIEW", ["Coverage anomaly — delta could not be read confidently; see coverage note"]
    if delta.new:
        return "REVIEW", [f"{len(delta.new)} new finding(s) below the urgent bar"]
    return "ROUTINE", []


def _fmt_finding(f: dict[str, Any]) -> str:
    sev = (f.get("severity") or "unrated").upper()
    stype = f.get("secret_type", "unknown")
    src = f.get("source_url") or f.get("target_url") or "—"
    verified = " · **confirmed live**" if f.get("verified") == "verified" else ""
    return f"- **{sev}** — {stype} in `{src}`{verified}"


def render_digest(
    delta: WatchDelta,
    client: str,
    period: str,
    generated_at: str | None = None,
) -> str:
    """Render a client-facing monthly digest as markdown.

    This is a DRAFT for human review, never sent automatically. Deterministic by
    design: the numbers in a client deliverable should come from the data, not
    from a model's paraphrase of it. A model may later be used to improve the
    prose around these facts — not to produce the facts.
    """
    tier, reasons = classify(delta)
    ts = generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    new_sorted = sorted(delta.new, key=lambda f: _severity_rank(f.get("severity", "")))

    # Internal triage deliberately does NOT appear in the visible body. Every
    # internal note lives in exactly one HTML-comment block at the end, so
    # "delete that block" is the complete and only step to make this
    # client-ready. An earlier draft also printed the tier in the header, which
    # meant a reviewer who removed the comment still shipped the word "URGENT"
    # and the studio's internal vocabulary to a client.
    lines = [
        f"# Watch — monthly summary for {client}",
        "",
        f"**Target:** `{delta.target_url}`  ",
        f"**Period:** {period}  ",
        f"**Generated:** {ts}",
        "",
        "---",
        "",
        "## What changed this period",
        "",
    ]

    if delta.first_run:
        lines += [
            "This is the first monitored run for this target, so there is no previous "
            "scan to compare against. Everything below is a baseline, not a change.",
            "",
        ]

    lines += [
        f"- **New exposures:** {len(delta.new)}",
        f"- **Resolved since last period:** {len(delta.resolved)}"
        + ("" if delta.resolution_confirmed else " *(not assessed this period — see coverage note)*"),
        f"- **Still present:** {len(delta.recurring)}",
    ]
    if delta.unverified_disappearances:
        lines.append(
            f"- **No longer observed, resolution unconfirmed:** {len(delta.unverified_disappearances)}"
        )
    lines.append("")

    if new_sorted:
        lines += ["### New exposures", ""] + [_fmt_finding(f) for f in new_sorted] + [""]

    # Persistent serious exposures get their own section rather than being
    # absorbed into a "still present: N" count. A CRITICAL key that has survived
    # several monitoring periods is the most important fact in the report and
    # the one a client is most likely to have stopped seeing — rendering it as a
    # number is how it gets ignored for another month.
    persistent = sorted(
        [f for f in delta.recurring if (f.get("severity") or "").lower() in URGENT_SEVERITIES],
        key=lambda f: _severity_rank(f.get("severity", "")),
    )
    if persistent:
        lines += [
            "### Still exposed from previous periods",
            "",
            "Reported previously and still present. These are not new, which makes them "
            "easy to stop noticing — they are listed in full for that reason:",
            "",
        ] + [_fmt_finding(f) for f in persistent] + [""]

    if delta.resolved:
        lines += [
            "### Resolved",
            "",
            "Present in the previous scan, absent now, with scan coverage comparable "
            "between the two runs:",
            "",
        ] + [_fmt_finding(f) for f in delta.resolved] + [""]

    if delta.unverified_disappearances:
        lines += [
            "### No longer observed — resolution not confirmed",
            "",
            "These were reported previously and did not appear this period. We are "
            "**not** claiming they are fixed: this run's coverage does not support that "
            "conclusion, and a finding can disappear because the asset holding it was "
            "not reachable rather than because anything changed.",
            "",
        ] + [_fmt_finding(f) for f in delta.unverified_disappearances] + [""]

    if not delta.has_changes and not delta.first_run:
        lines += [
            "No new exposures and nothing resolved this period. A clean period is a "
            "real result, and it is stated here plainly rather than left as silence.",
            "",
        ]

    if delta.coverage_note:
        lines += ["### Coverage", "", delta.coverage_note, ""]

    lines += [
        "---",
        "",
        "## Scope and limits",
        "",
        "Monitoring is passive and read-only: it observes what is reachable from the "
        "public internet and never authenticates, modifies, or exploits. Anything "
        "behind authentication, and any asset not linked from the monitored surface, "
        "is outside this report and is not covered by it.",
        "",
        f"Scan reference: `{delta.current_scan_id}`"
        + (f" · compared against `{delta.previous_scan_id}`" if delta.previous_scan_id else ""),
        "",
    ]

    if reasons:
        lines += [
            "<!-- INTERNAL — remove before sending to the client",
            f"Triage: {tier}",
        ] + [f"  - {r}" for r in reasons] + ["-->", ""]

    return "\n".join(lines)


def load_roster(path: pathlib.Path | None = None) -> list[WatchTarget]:
    """Load the monitored-target roster.

    The real roster names paying clients and their infrastructure, so it is
    gitignored; `watch-roster.example.json` is the committed template. A missing
    roster is an explicit error rather than an empty run, because "monitoring
    completed, zero targets" is the most dangerous possible silent failure for
    a paid subscription.
    """
    p = path or ROSTER_PATH
    if not p.exists():
        raise FileNotFoundError(
            f"Watch roster not found at {p}. Copy watch-roster.example.json to "
            f"watch-roster.json and add the targets under active monitoring."
        )
    raw = json.loads(p.read_text(encoding="utf-8"))
    entries = raw.get("targets") if isinstance(raw, dict) else raw
    if not isinstance(entries, list):
        raise ValueError("Watch roster must be a list of targets, or an object with a 'targets' list.")
    return [WatchTarget.from_dict(e) for e in entries]
