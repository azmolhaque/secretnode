"""
SecretNode — report.py
Generates client-deliverable reports from a completed scan result.

Formats:
  • HTML  — single self-contained, print-styled file. Open it and use the
            browser's "Print → Save as PDF" to produce a PDF deliverable
            without a heavyweight PDF-rendering dependency on the Pi
            (weasyprint/wkhtmltopdf pull in painful native ARM64 deps).
  • CSV   — spreadsheet-friendly export of every finding.
  • JSON  — raw structured scan record.
  • SARIF — Static Analysis Results Interchange Format 2.1.0, so findings can
            be uploaded to GitHub code scanning or ingested by any SARIF-aware
            CI/security pipeline (industrial-grade integration).
"""

from __future__ import annotations

import csv
import html
import io
import json
from datetime import datetime, timezone
from typing import Any

_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# GitHub code-scanning uses a numeric security-severity (CVSS-like) to bucket
# SARIF results; map our qualitative levels onto it.
_SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
_SARIF_SECURITY_SEVERITY = {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.0", "LOW": "3.0"}

_TOOL_VERSION = "2.3.0"
_TOOL_URI = "https://github.com/azmolhaque/secretnode"


def _severity_of(finding: dict[str, Any]) -> str:
    return str(finding.get("severity", "MEDIUM")).upper()


def _sort_key(finding: dict[str, Any]) -> tuple[int, int, str]:
    """Sort by severity (critical first), then AI confidence (high first),
    then secret type for stable ordering."""
    return (
        _SEVERITY_RANK.get(_severity_of(finding), 2),
        -int(finding.get("confidence", 0) or 0),
        finding.get("secret_type", ""),
    )


# ─────────────────────────────────────────────────────────────────────────────
# HTML
# ─────────────────────────────────────────────────────────────────────────────

def generate_html_report(scan: dict[str, Any], agency_name: str = "Independent Security Research") -> str:
    target = html.escape(scan.get("target_url", "unknown"))
    scan_id = html.escape(scan.get("scan_id", ""))
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    confirmed = sorted(scan.get("confirmed_findings", []), key=_sort_key)
    needs_review = scan.get("needs_review_findings", [])
    new_count = scan.get("new_findings_count", len(confirmed))
    recurring_count = scan.get("recurring_findings_count", 0)
    duration = scan.get("duration_seconds", 0)
    assets = scan.get("assets_fetched", 0)

    sev_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in confirmed:
        sev = _severity_of(f)
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    def sev_badge(sev: str) -> str:
        sev = sev.upper()
        return f'<span class="sev sev-{sev.lower()}">{html.escape(sev)}</span>'

    def ver_badge(f: dict[str, Any]) -> str:
        v = str(f.get("verified", "disabled"))
        labels = {
            "verified": ("VERIFIED ACTIVE", "ver-verified"),
            "unverified": ("inactive", "ver-unverified"),
            "unsupported": ("unverified", "ver-unsupported"),
            "disabled": ("", ""),
        }
        text, cls = labels.get(v, ("", ""))
        return f'<span class="ver {cls}">{text}</span>' if text else ""

    def finding_row(f: dict[str, Any]) -> str:
        badge = '<span class="badge new">NEW</span>' if f.get("is_new", True) else '<span class="badge recurring">RECURRING</span>'
        cwe = html.escape(str(f.get("cwe", "")))
        return f"""
        <tr>
          <td>{sev_badge(_severity_of(f))}</td>
          <td>{html.escape(f.get('secret_type',''))}<div class="small">{cwe}</div></td>
          <td class="mono">{html.escape(f.get('source_url', f.get('target_url','')))}</td>
          <td>{f.get('confidence',0)}%</td>
          <td>{badge}{ver_badge(f)}</td>
          <td class="mono small">{html.escape(f.get('raw_match',''))}</td>
          <td class="small">{html.escape(f.get('reason',''))}</td>
        </tr>"""

    def review_row(f: dict[str, Any]) -> str:
        return f"""
        <tr>
          <td>{sev_badge(_severity_of(f))}</td>
          <td>{html.escape(f.get('secret_type',''))}</td>
          <td class="mono">{html.escape(f.get('source_url', f.get('target_url','')))}</td>
          <td class="small">{html.escape(f.get('reason',''))}</td>
        </tr>"""

    findings_html = "\n".join(finding_row(f) for f in confirmed) or \
        '<tr><td colspan="7" class="empty">No confirmed findings — no live credentials detected in this scan.</td></tr>'
    review_html = "\n".join(review_row(f) for f in needs_review) or \
        '<tr><td colspan="4" class="empty">None.</td></tr>'

    # Deduplicated remediation guidance, one block per distinct secret type found.
    remediation_blocks = ""
    seen_types: set[str] = set()
    for f in confirmed:
        st = f.get("secret_type", "")
        if st in seen_types or not f.get("remediation"):
            continue
        seen_types.add(st)
        remediation_blocks += (
            f'<div class="remediation"><b>{html.escape(st)}</b> '
            f'({html.escape(str(f.get("cwe","")))}) — {html.escape(str(f.get("remediation","")))}</div>'
        )
    if not remediation_blocks:
        remediation_blocks = '<div class="small">No remediation items — scan is clean.</div>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Attack Surface Report — {target}</title>
<style>
  @media print {{ .no-print {{ display: none; }} body {{ margin: 0; }} }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; color: #1a202c; margin: 40px; line-height: 1.5; }}
  h1 {{ font-size: 22px; border-bottom: 3px solid #276749; padding-bottom: 10px; }}
  h2 {{ font-size: 16px; margin-top: 32px; color: #276749; }}
  .meta {{ background: #f7fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 16px; margin: 16px 0; }}
  .meta div {{ margin: 4px 0; font-size: 13px; }}
  .meta b {{ display: inline-block; width: 160px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 12px; }}
  th {{ background: #276749; color: white; text-align: left; padding: 8px; }}
  td {{ padding: 8px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }}
  tr:nth-child(even) {{ background: #f7fafc; }}
  .mono {{ font-family: 'Courier New', monospace; word-break: break-all; }}
  .small {{ font-size: 11px; color: #4a5568; }}
  .empty {{ text-align: center; color: #718096; font-style: italic; padding: 20px; }}
  .badge {{ padding: 2px 8px; border-radius: 10px; font-size: 10px; font-weight: bold; }}
  .badge.new {{ background: #fed7d7; color: #c53030; }}
  .badge.recurring {{ background: #e2e8f0; color: #4a5568; }}
  .sev {{ padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: bold; color: #fff; }}
  .sev-critical {{ background: #c53030; }}
  .sev-high {{ background: #dd6b20; }}
  .sev-medium {{ background: #d69e2e; }}
  .sev-low {{ background: #3182ce; }}
  .ver {{ padding: 2px 7px; border-radius: 4px; font-size: 9px; font-weight: bold; margin-left: 4px; }}
  .ver-verified {{ background: #c53030; color: #fff; }}
  .ver-unverified {{ background: #e2e8f0; color: #4a5568; }}
  .ver-unsupported {{ background: #edf2f7; color: #718096; }}
  .summary-grid {{ display: flex; gap: 12px; margin: 16px 0; flex-wrap: wrap; }}
  .stat {{ flex: 1; min-width: 110px; background: #f7fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 12px; text-align: center; }}
  .stat .num {{ font-size: 24px; font-weight: bold; color: #276749; }}
  .stat .label {{ font-size: 11px; color: #718096; text-transform: uppercase; }}
  .remediation {{ background: #f7fafc; border-left: 3px solid #276749; padding: 10px 12px; margin: 8px 0; font-size: 12px; border-radius: 0 4px 4px 0; }}
  footer {{ margin-top: 40px; font-size: 11px; color: #a0aec0; border-top: 1px solid #e2e8f0; padding-top: 12px; }}
  .no-print {{ background: #fffaf0; border: 1px solid #f6ad55; padding: 10px; border-radius: 6px; margin-bottom: 20px; font-size: 13px; }}
</style>
</head>
<body>
  <div class="no-print">📄 Tip: use your browser's Print function (Ctrl/Cmd+P) and choose "Save as PDF" to export this report as a PDF deliverable.</div>

  <h1>External Attack Surface &amp; Credential Exposure Report</h1>
  <div class="meta">
    <div><b>Target</b> {target}</div>
    <div><b>Prepared by</b> {html.escape(agency_name)}</div>
    <div><b>Scan ID</b> {scan_id}</div>
    <div><b>Generated</b> {generated_at}</div>
    <div><b>Scan duration</b> {duration}s</div>
    <div><b>Assets analysed</b> {assets}</div>
  </div>

  <div class="summary-grid">
    <div class="stat"><div class="num">{sev_counts['CRITICAL']}</div><div class="label">Critical</div></div>
    <div class="stat"><div class="num">{sev_counts['HIGH']}</div><div class="label">High</div></div>
    <div class="stat"><div class="num">{sev_counts['MEDIUM']}</div><div class="label">Medium</div></div>
    <div class="stat"><div class="num">{new_count}</div><div class="label">New</div></div>
    <div class="stat"><div class="num">{recurring_count}</div><div class="label">Recurring</div></div>
    <div class="stat"><div class="num">{len(needs_review)}</div><div class="label">Needs Review</div></div>
  </div>

  <h2>Confirmed Findings</h2>
  <table>
    <thead><tr><th>Severity</th><th>Type / CWE</th><th>Location</th><th>AI Confidence</th><th>Status</th><th>Matched Value (partial)</th><th>AI Reasoning</th></tr></thead>
    <tbody>{findings_html}</tbody>
  </table>

  <h2>Remediation Guidance</h2>
  {remediation_blocks}

  <h2>Flagged for Manual Review (AI validation unavailable)</h2>
  <table>
    <thead><tr><th>Severity</th><th>Type</th><th>Location</th><th>Note</th></tr></thead>
    <tbody>{review_html}</tbody>
  </table>

  <footer>
    Generated by SecretNode v{_TOOL_VERSION} — passive attack surface scanner. All findings above were discovered via passive
    reconnaissance only; no exploitation, data exfiltration, or write operations were performed against the target.
    Matched credential values are partially redacted in this report.
  </footer>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────────────────────
# CSV
# ─────────────────────────────────────────────────────────────────────────────

def generate_csv_report(scan: dict[str, Any]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "status", "severity", "cwe", "secret_type", "source_url", "confidence",
        "is_new", "verified", "matched_value_partial", "reason", "found_at",
    ])
    for f in sorted(scan.get("confirmed_findings", []), key=_sort_key):
        writer.writerow([
            "CONFIRMED", _severity_of(f), f.get("cwe", ""), f.get("secret_type", ""),
            f.get("source_url", f.get("target_url", "")),
            f.get("confidence", 0), "NEW" if f.get("is_new", True) else "RECURRING",
            f.get("verified", "disabled"), f.get("raw_match", ""), f.get("reason", ""), f.get("found_at", ""),
        ])
    for f in scan.get("needs_review_findings", []):
        writer.writerow([
            "NEEDS_REVIEW", _severity_of(f), f.get("cwe", ""), f.get("secret_type", ""),
            f.get("source_url", f.get("target_url", "")),
            "", "", f.get("raw_match", ""), f.get("reason", ""), f.get("found_at", ""),  # needs-review: no confidence/is_new/verified
        ])
    return buf.getvalue()


# ─────────────────────────────────────────────────────────────────────────────
# SARIF 2.1.0
# ─────────────────────────────────────────────────────────────────────────────

def generate_sarif_report(scan: dict[str, Any]) -> str:
    """Emit findings as SARIF 2.1.0 — uploadable to GitHub code scanning or any
    SARIF-aware pipeline. Confirmed and needs-review findings are both included;
    needs-review findings are downgraded to 'note' level so they don't fail a
    build gate but are still visible for triage."""
    all_findings = [
        (f, False) for f in scan.get("confirmed_findings", [])
    ] + [
        (f, True) for f in scan.get("needs_review_findings", [])
    ]

    # Build a rule per distinct secret type actually present.
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for f, is_review in all_findings:
        secret_type = f.get("secret_type", "Unknown")
        rule_id = "secretnode/" + secret_type.lower().replace(" ", "-").replace("/", "-")
        severity = _severity_of(f)
        cwe = str(f.get("cwe", "CWE-798"))

        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": secret_type.replace(" ", ""),
                "shortDescription": {"text": f"Exposed {secret_type}"},
                "fullDescription": {"text": str(f.get("remediation", "Exposed credential detected."))},
                "helpUri": _TOOL_URI,
                "defaultConfiguration": {"level": _SARIF_LEVEL.get(severity, "warning")},
                "properties": {
                    "tags": ["security", "secret", cwe],
                    "cwe": cwe,
                    "security-severity": _SARIF_SECURITY_SEVERITY.get(severity, "5.0"),
                },
            }

        level = "note" if is_review else _SARIF_LEVEL.get(severity, "warning")
        location_uri = f.get("source_url") or f.get("target_url") or "unknown"
        verified = str(f.get("verified", "disabled"))
        vprefix = "[VERIFIED ACTIVE] " if verified == "verified" else ""
        msg = (
            vprefix + f"{secret_type} ({severity}) detected. "
            f"{'AI validation unavailable — manual review required. ' if is_review else ''}"
            f"{f.get('reason','')}"
        )
        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": msg.strip()},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": location_uri},
                }
            }],
            "partialFingerprints": {"secretnode/v1": f.get("fingerprint", "")},
            "properties": {
                "severity": severity,
                "cwe": cwe,
                "confidence": f.get("confidence", 0),
                "verified": verified,
                "status": "needs_review" if is_review else "confirmed",
            },
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SecretNode",
                    "version": _TOOL_VERSION,
                    "informationUri": _TOOL_URI,
                    "rules": list(rules.values()),
                }
            },
            "results": results,
            "properties": {
                "target_url": scan.get("target_url", ""),
                "scan_id": scan.get("scan_id", ""),
                "assets_fetched": scan.get("assets_fetched", 0),
            },
        }],
    }
    return json.dumps(sarif, indent=2)
