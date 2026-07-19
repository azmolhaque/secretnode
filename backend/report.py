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
from pathlib import Path
from typing import Any

_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# GitHub code-scanning uses a numeric security-severity (CVSS-like) to bucket
# SARIF results; map our qualitative levels onto it.
_SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
_SARIF_SECURITY_SEVERITY = {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.0", "LOW": "3.0"}

_TOOL_URI = "https://github.com/azmolhaque/secretnode"


def _tool_version() -> str:
    """Single-source the version from pyproject.toml so client reports never stamp
    a stale version (they used to be pinned at 2.3.0). Falls back if unreadable."""
    try:
        pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
        for line in pyproject.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if s.startswith("version") and "=" in s:
                return s.split("=", 1)[1].strip().strip('"').strip("'")
    except Exception:
        pass
    return "2.7.0"


_TOOL_VERSION = _tool_version()


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

    confirmed_count = len(confirmed)
    verified_active = sum(1 for f in confirmed if str(f.get("verified", "")).lower() == "verified")
    raw_screened = scan.get("raw_findings", 0)
    scanned_at = html.escape(str(scan.get("created_at", "")) or generated_at)

    # Overall risk posture — drives the executive-summary banner.
    if sev_counts["CRITICAL"]:
        risk_label, risk_color = "CRITICAL", "#c53030"
    elif sev_counts["HIGH"]:
        risk_label, risk_color = "HIGH", "#dd6b20"
    elif sev_counts["MEDIUM"]:
        risk_label, risk_color = "MEDIUM", "#d69e2e"
    elif confirmed_count:
        risk_label, risk_color = "LOW", "#3182ce"
    elif needs_review:
        risk_label, risk_color = "REVIEW REQUIRED", "#805ad5"
    else:
        risk_label, risk_color = "CLEAN", "#276749"

    if confirmed_count:
        verdict_title = (f"{confirmed_count} confirmed credential exposure"
                         f"{'s' if confirmed_count != 1 else ''} detected")
        if verified_active:
            verdict_title += f" — {verified_active} verified currently ACTIVE"
        verdict_sub = ("Treat exposed credentials as compromised: rotate/revoke them at the provider "
                       "immediately, then purge them from the shipped assets. See the findings and "
                       "remediation guidance below.")
    elif needs_review:
        verdict_title = f"No confirmed exposures — {len(needs_review)} item(s) need manual review"
        verdict_sub = ("AI validation was unavailable for some candidates during this scan; a human "
                       "should confirm they are benign before this target is considered clean.")
    else:
        verdict_title = "No exposed credentials detected"
        verdict_sub = (f"{assets} asset(s) were analysed and {raw_screened} high-entropy candidate(s) "
                       "screened; none were confirmed as live secrets. This is a point-in-time assurance "
                       "snapshot of the external attack surface, not a guarantee of absolute security.")

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
        impact = html.escape(f.get('impact', '') or '—')
        vdetail = html.escape(f.get('verified_detail', '') or '')
        # For a VERIFIED-active key, show WHO it belongs to / what it can reach — the
        # concrete blast radius an attacker inherits (R1 verification enrichment).
        vdetail_html = f'<div class="small ver-detail">🔓 live access: {vdetail}</div>' if vdetail else ''
        return f"""
        <tr>
          <td>{sev_badge(_severity_of(f))}</td>
          <td>{html.escape(f.get('secret_type',''))}<div class="small">{cwe}</div></td>
          <td class="impact">{impact}{vdetail_html}</td>
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
        '<tr><td colspan="8" class="empty">No confirmed findings — no live credentials detected in this scan.</td></tr>'
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

    # R9 — verification-evidence callout: the single strongest client-facing signal.
    # For credentials confirmed CURRENTLY ACTIVE (read-only check against the provider),
    # list exactly what an attacker reaches. Only rendered when there is live proof.
    if verified_active:
        ve_rows = ""
        for f in confirmed:
            if str(f.get("verified", "")).lower() != "verified":
                continue
            detail = html.escape(f.get("verified_detail", "") or "live access confirmed")
            loc = html.escape(f.get("source_url", f.get("target_url", "")))
            ve_rows += (
                f'<li><b>{html.escape(f.get("secret_type",""))}</b> '
                f'<span class="mono small">{loc}</span>'
                f'<div class="ver-ev-detail">🔓 confirmed live access: {detail}</div></li>'
            )
        verified_evidence = (
            '<div class="ver-evidence">'
            f'<div class="ve-head">⚠ {verified_active} credential(s) confirmed CURRENTLY ACTIVE'
            ' via a read-only check against the issuing provider</div>'
            f'<ul class="ve-list">{ve_rows}</ul>'
            '<div class="small">These are not look-alikes — each was live at scan time. '
            'Rotate/revoke them at the provider immediately.</div>'
            '</div>'
        )
    else:
        verified_evidence = ""

    # R8 — passive security-posture findings (missing/weak headers, misconfig).
    posture = scan.get("posture_findings", [])

    def _posture_row(p: dict[str, Any]) -> str:
        return (
            f'<tr><td>{sev_badge(_severity_of(p))}</td>'
            f'<td>{html.escape(p.get("name",""))}<div class="small">{html.escape(str(p.get("cwe","")))}</div></td>'
            f'<td class="mono small">{html.escape(p.get("evidence",""))}</td>'
            f'<td class="small">{html.escape(p.get("remediation",""))}</td></tr>'
        )
    posture_html = "\n".join(_posture_row(p) for p in sorted(posture, key=_sort_key)) or \
        '<tr><td colspan="4" class="empty">No header/misconfiguration issues detected.</td></tr>'

    # Attack-surface intelligence (slices 5 & 4): endpoints referenced in code and
    # the external hosts this asset talks to. Capped for readability.
    endpoints = scan.get("discovered_endpoints", []) or []
    assoc_hosts = scan.get("associated_hosts", []) or []
    endpoints_html = "".join(
        f'<li class="mono small">{html.escape(e)}</li>' for e in endpoints[:80]
    ) or '<li class="small empty">None discovered.</li>'
    if len(endpoints) > 80:
        endpoints_html += f'<li class="small">… and {len(endpoints) - 80} more.</li>'
    hosts_html = ", ".join(html.escape(h) for h in assoc_hosts) or "—"

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
  .verdict {{ background: #f7fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 16px 18px; margin: 18px 0; }}
  .verdict-row {{ display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }}
  .risk-pill {{ color: #fff; font-weight: bold; font-size: 12px; letter-spacing: 0.06em; padding: 4px 12px; border-radius: 4px; }}
  .verdict-title {{ font-size: 16px; font-weight: 600; }}
  .verdict-sub {{ font-size: 13px; color: #4a5568; margin-top: 8px; }}
  .scope p {{ font-size: 13px; color: #2d3748; }}
  td.impact {{ font-size: 12px; color: #742a2a; font-weight: 600; max-width: 260px; }}
  .ver-evidence {{ background: #fff5f5; border: 1px solid #feb2b2; border-left: 6px solid #c53030; border-radius: 6px; padding: 14px 16px; margin: 16px 0; }}
  .ver-evidence .ve-head {{ font-weight: 700; color: #c53030; font-size: 14px; }}
  .ve-list {{ margin: 10px 0 6px; padding-left: 18px; font-size: 13px; }}
  .ve-list li {{ margin: 6px 0; }}
  .ver-ev-detail {{ font-family: 'Courier New', monospace; font-size: 12px; color: #742a2a; margin-top: 2px; }}
  .stat.alert {{ border-color: #feb2b2; background: #fff5f5; }}
  .stat.alert .num {{ color: #c53030; }}
  .scope-quality {{ background: #f0fff4; border-left: 3px solid #276749; padding: 10px 12px; border-radius: 0 4px 4px 0; margin-top: 10px; }}
</style>
</head>
<body>
  <div class="no-print">📄 Tip: use your browser's Print function (Ctrl/Cmd+P) and choose "Save as PDF" to export this report as a PDF deliverable.</div>

  <h1>External Attack Surface &amp; Credential Exposure Report</h1>

  <div class="verdict" style="border-left:6px solid {risk_color};">
    <div class="verdict-row">
      <span class="risk-pill" style="background:{risk_color};">{html.escape(risk_label)}</span>
      <span class="verdict-title">{html.escape(verdict_title)}</span>
    </div>
    <div class="verdict-sub">{html.escape(verdict_sub)}</div>
  </div>

  {verified_evidence}

  <div class="meta">
    <div><b>Target</b> {target}</div>
    <div><b>Prepared by</b> {html.escape(agency_name)}</div>
    <div><b>Scan ID</b> {scan_id}</div>
    <div><b>Scan started</b> {scanned_at}</div>
    <div><b>Report generated</b> {generated_at}</div>
    <div><b>Scan duration</b> {duration}s</div>
    <div><b>Assets analysed</b> {assets}</div>
    <div><b>Candidates screened</b> {raw_screened}</div>
  </div>

  <div class="summary-grid">
    <div class="stat"><div class="num">{sev_counts['CRITICAL']}</div><div class="label">Critical</div></div>
    <div class="stat"><div class="num">{sev_counts['HIGH']}</div><div class="label">High</div></div>
    <div class="stat"><div class="num">{sev_counts['MEDIUM']}</div><div class="label">Medium</div></div>
    <div class="stat{' alert' if verified_active else ''}"><div class="num">{verified_active}</div><div class="label">Verified Active</div></div>
    <div class="stat"><div class="num">{new_count}</div><div class="label">New</div></div>
    <div class="stat"><div class="num">{recurring_count}</div><div class="label">Recurring</div></div>
    <div class="stat"><div class="num">{len(needs_review)}</div><div class="label">Needs Review</div></div>
    <div class="stat"><div class="num">{len(posture)}</div><div class="label">Posture Issues</div></div>
  </div>

  <h2>Scope &amp; Methodology</h2>
  <div class="scope">
    <p>SecretNode performed a <b>passive</b> external attack-surface assessment of <span class="mono">{target}</span>:
    it crawled same-domain pages, collected linked JavaScript and declared source-map assets, and screened their
    contents for exposed credentials using its full pattern registry (50+ provider-specific detectors) together with
    Shannon-entropy analysis. High-entropy candidates were then contextually validated to distinguish live secrets
    from mocks, placeholders and minified-code artefacts. <b>No exploitation, authentication, data exfiltration, or
    write operations</b> were performed against the target — testing is passive and authorized-scope only.</p>
    <p class="scope-quality"><b>Detection quality.</b> SecretNode is verification-first: where a credential type
    supports it, a read-only check against the issuing provider confirms whether the key is currently active before
    it is reported — so a "verified" finding is proven, not shape-matched. The deterministic detection layer is
    continuously measured against a labelled benchmark corpus with a precision/recall gate in CI, so this report
    favours confirmed impact over look-alikes and keeps false positives low.</p>
  </div>

  <h2>Confirmed Findings</h2>
  <table>
    <thead><tr><th>Severity</th><th>Type / CWE</th><th>Impact / Blast Radius</th><th>Location</th><th>AI Confidence</th><th>Status</th><th>Matched Value (partial)</th><th>AI Reasoning</th></tr></thead>
    <tbody>{findings_html}</tbody>
  </table>

  <h2>Remediation Guidance</h2>
  {remediation_blocks}

  <h2>Security Posture &amp; Misconfigurations</h2>
  <table>
    <thead><tr><th>Severity</th><th>Issue / CWE</th><th>Evidence</th><th>Remediation</th></tr></thead>
    <tbody>{posture_html}</tbody>
  </table>

  <h2>Flagged for Manual Review (AI unavailable, or a structural match it could not confidently clear)</h2>
  <table>
    <thead><tr><th>Severity</th><th>Type</th><th>Location</th><th>Note</th></tr></thead>
    <tbody>{review_html}</tbody>
  </table>

  <h2>Attack Surface Intelligence</h2>
  <div class="small" style="margin-bottom:6px;"><b>Associated hosts</b> (external services this
  asset references — CDNs, APIs, third parties): <span class="mono">{hosts_html}</span></div>
  <div class="small"><b>Endpoints referenced in code</b> ({len(endpoints)} discovered — URLs/paths
  the JavaScript calls that a page crawl would miss):</div>
  <ul style="margin:6px 0 0; columns:2; font-size:11px;">{endpoints_html}</ul>

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
        "is_new", "verified", "verified_detail", "impact", "matched_value_partial",
        "reason", "found_at",
    ])
    for f in sorted(scan.get("confirmed_findings", []), key=_sort_key):
        writer.writerow([
            "CONFIRMED", _severity_of(f), f.get("cwe", ""), f.get("secret_type", ""),
            f.get("source_url", f.get("target_url", "")),
            f.get("confidence", 0), "NEW" if f.get("is_new", True) else "RECURRING",
            f.get("verified", "disabled"), f.get("verified_detail", ""), f.get("impact", ""),
            f.get("raw_match", ""), f.get("reason", ""), f.get("found_at", ""),
        ])
    for f in scan.get("needs_review_findings", []):
        writer.writerow([
            "NEEDS_REVIEW", _severity_of(f), f.get("cwe", ""), f.get("secret_type", ""),
            f.get("source_url", f.get("target_url", "")),
            "", "", "", "", f.get("impact", ""), f.get("raw_match", ""),
            f.get("reason", ""), f.get("found_at", ""),
        ])
    return buf.getvalue()


# ─────────────────────────────────────────────────────────────────────────────
# SARIF 2.1.0
# ─────────────────────────────────────────────────────────────────────────────

def _rule_id(secret_type: str) -> str:
    """Deterministic SARIF ruleId for a secret type. Shared by the rule catalog
    and each result so results always resolve to a described rule."""
    return "secretnode/" + secret_type.lower().replace(" ", "-").replace("/", "-")


def _catalog_rules() -> dict[str, dict[str, Any]]:
    """Full catalog of every detector as a SARIF reportingDescriptor.

    A SARIF driver should advertise every rule it *can* apply — not only the ones
    that happened to fire on this scan — so consumers (GitHub code scanning, CI
    dashboards) always have the rule's help text, CWE, and default severity. Built
    from the live pattern registry so it never drifts from what the scanner detects.
    """
    try:
        from scanner import SECRET_PATTERNS
    except Exception:  # pragma: no cover - packaged/alternate import path
        try:
            from backend.scanner import SECRET_PATTERNS  # type: ignore
        except Exception:
            return {}
    catalog: dict[str, dict[str, Any]] = {}
    for p in SECRET_PATTERNS:
        rid = _rule_id(p.name)
        sev = str(getattr(p, "severity", "MEDIUM")).upper()
        cwe = str(getattr(p, "cwe", "CWE-798"))
        catalog[rid] = {
            "id": rid,
            "name": p.name.replace(" ", ""),
            "shortDescription": {"text": f"Exposed {p.name}"},
            "fullDescription": {"text": str(getattr(p, "description", "") or f"Exposed {p.name}")},
            "help": {"text": str(getattr(p, "remediation", "") or "Rotate the exposed credential and remove it from client-side code.")},
            "helpUri": _TOOL_URI,
            "defaultConfiguration": {"level": _SARIF_LEVEL.get(sev, "warning")},
            "properties": {
                "tags": ["security", "secret", cwe],
                "cwe": cwe,
                "security-severity": _SARIF_SECURITY_SEVERITY.get(sev, "5.0"),
            },
        }
    return catalog


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

    # Advertise the full detector catalog; add finding-specific rules for any
    # unknown type below so every result still resolves to a described rule.
    rules: dict[str, dict[str, Any]] = _catalog_rules()
    results: list[dict[str, Any]] = []

    for f, is_review in all_findings:
        secret_type = f.get("secret_type", "Unknown")
        rule_id = _rule_id(secret_type)
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
        verified_detail = str(f.get("verified_detail", "") or "")
        # Keep the literal "[VERIFIED ACTIVE]" token intact for downstream matchers,
        # then append the identity/scope (blast radius) when we captured one.
        vprefix = (
            (f"[VERIFIED ACTIVE] ({verified_detail}) " if verified_detail else "[VERIFIED ACTIVE] ")
            if verified == "verified" else ""
        )
        impact = str(f.get("impact", "") or "")
        msg = (
            vprefix + f"{secret_type} ({severity}) detected. "
            f"{'Manual review required — see note. ' if is_review else ''}"
            f"{('Impact: ' + impact + ' ') if impact else ''}"
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
                "verified_detail": verified_detail,
                "impact": impact,
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


# ─────────────────────────────────────────────────────────────────────────────
# Deep-scan (multi-target) summary report — deep-ASM slice 2
# ─────────────────────────────────────────────────────────────────────────────

def generate_deep_scan_html(deep: dict[str, Any]) -> str:
    """Render a single client-facing summary for a domain-wide deep scan: the
    discovered subdomain surface, which hosts were live, and per-host findings.
    Input is orchestrator.DeepScanResult.to_dict()."""
    domain = html.escape(str(deep.get("domain", "")))
    totals = deep.get("totals", {})
    hosts = deep.get("hosts", [])
    sources = ", ".join(deep.get("enum_sources", [])) or "—"
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    confirmed_total = int(totals.get("confirmed", 0))
    pill_color = "#c53030" if confirmed_total else "#276749"
    pill_text = (f"{confirmed_total} confirmed credential exposure(s) across the domain"
                 if confirmed_total else "No confirmed credential exposures across the domain")

    def host_row(h: dict[str, Any]) -> str:
        err = h.get("error")
        conf = int(h.get("confirmed", 0))
        conf_cell = (f'<span class="hit">{conf}</span>' if conf else "0")
        status = ('<span class="err">error</span>' if err else "scanned")
        note = html.escape(str(err)) if err else ""
        return (
            "<tr>"
            f'<td class="mono">{html.escape(str(h.get("host", "")))}</td>'
            f'<td>{status}</td>'
            f'<td style="text-align:center;">{int(h.get("assets", 0))}</td>'
            f'<td style="text-align:center;">{conf_cell}</td>'
            f'<td style="text-align:center;">{int(h.get("needs_review", 0))}</td>'
            f'<td style="text-align:center;">{int(h.get("posture_issues", 0))}</td>'
            f'<td class="small">{note}</td>'
            "</tr>"
        )

    rows = "\n".join(host_row(h) for h in hosts) or \
        '<tr><td colspan="7" class="empty">No live hosts were scanned.</td></tr>'
    subs = ", ".join(html.escape(s) for s in deep.get("subdomains", [])) or "—"

    # Findings aggregated across every host, each tagged with its host of origin.
    _MAX_ROWS = 250
    confirmed_findings = deep.get("confirmed_findings", [])[:_MAX_ROWS]
    review_findings = deep.get("needs_review_findings", [])[:_MAX_ROWS]

    def _sev(f: dict[str, Any]) -> str:
        s = str(f.get("severity", "MEDIUM")).upper()
        return f'<span class="sev sev-{s.lower()}">{html.escape(s)}</span>'

    def _loc(f: dict[str, Any]) -> str:
        return html.escape(str(f.get("source_url", f.get("target_url", ""))))

    def conf_row(f: dict[str, Any]) -> str:
        return ("<tr>"
                f'<td class="mono">{html.escape(str(f.get("_host", "")))}</td>'
                f"<td>{_sev(f)}</td>"
                f'<td>{html.escape(str(f.get("secret_type", "")))}</td>'
                f'<td class="mono small">{_loc(f)}</td>'
                f'<td style="text-align:center;">{int(f.get("confidence", 0) or 0)}%</td>'
                f'<td class="small">{html.escape(str(f.get("reason", "")))}</td>'
                "</tr>")

    def review_row(f: dict[str, Any]) -> str:
        return ("<tr>"
                f'<td class="mono">{html.escape(str(f.get("_host", "")))}</td>'
                f"<td>{_sev(f)}</td>"
                f'<td>{html.escape(str(f.get("secret_type", "")))}</td>'
                f'<td class="mono small">{_loc(f)}</td>'
                f'<td class="small">{html.escape(str(f.get("reason", "")))}</td>'
                "</tr>")

    conf_rows = "\n".join(conf_row(f) for f in confirmed_findings) or \
        '<tr><td colspan="6" class="empty">No confirmed credential exposures.</td></tr>'
    review_rows = "\n".join(review_row(f) for f in review_findings) or \
        '<tr><td colspan="5" class="empty">None.</td></tr>'
    assoc_hosts_html = ", ".join(html.escape(h) for h in deep.get("associated_hosts", [])) or "—"

    takeovers = deep.get("takeover_findings", [])

    def takeover_row(t: dict[str, Any]) -> str:
        sev = str(t.get("severity", "HIGH")).upper()
        cname = html.escape(str(t.get("cname", "")) or "—")
        return ("<tr>"
                f'<td class="mono">{html.escape(str(t.get("host", "")))}</td>'
                f'<td><span class="sev sev-{sev.lower()}">{sev}</span></td>'
                f'<td>{html.escape(str(t.get("service", "")))}</td>'
                f'<td class="mono small">{cname}</td>'
                f'<td class="small">{html.escape(str(t.get("evidence", "")))}</td>'
                "</tr>")

    takeover_rows = "\n".join(takeover_row(t) for t in takeovers) or \
        '<tr><td colspan="5" class="empty">None detected.</td></tr>'

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Domain Attack-Surface Report — {domain}</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; color: #1a202c; margin: 40px; line-height: 1.5; }}
  h1 {{ font-size: 22px; border-bottom: 3px solid #276749; padding-bottom: 10px; }}
  h2 {{ font-size: 16px; margin-top: 30px; color: #276749; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 12px; }}
  th {{ background: #276749; color: #fff; text-align: left; padding: 8px; }}
  td {{ padding: 8px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }}
  tr:nth-child(even) {{ background: #f7fafc; }}
  .mono {{ font-family: 'Courier New', monospace; word-break: break-all; }}
  .small {{ font-size: 11px; color: #4a5568; }}
  .empty {{ text-align: center; color: #718096; font-style: italic; padding: 20px; }}
  .hit {{ color: #c53030; font-weight: bold; }}
  .err {{ color: #dd6b20; font-weight: bold; }}
  .sev {{ padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: bold; color: #fff; }}
  .sev-critical {{ background: #c53030; }}
  .sev-high {{ background: #dd6b20; }}
  .sev-medium {{ background: #d69e2e; }}
  .sev-low {{ background: #3182ce; }}
  .verdict {{ background: #f7fafc; border: 1px solid #e2e8f0; border-left: 6px solid {pill_color};
             border-radius: 6px; padding: 16px 18px; margin: 18px 0; }}
  .risk-pill {{ color: #fff; font-weight: bold; font-size: 12px; letter-spacing: 0.06em;
               padding: 4px 12px; border-radius: 4px; background: {pill_color}; }}
  .grid {{ display: flex; gap: 12px; margin: 16px 0; flex-wrap: wrap; }}
  .stat {{ flex: 1; min-width: 120px; background: #f7fafc; border: 1px solid #e2e8f0;
          border-radius: 6px; padding: 12px; text-align: center; }}
  .stat .num {{ font-size: 24px; font-weight: bold; color: #276749; }}
  .stat .label {{ font-size: 11px; color: #718096; text-transform: uppercase; }}
  footer {{ margin-top: 40px; font-size: 11px; color: #a0aec0; border-top: 1px solid #e2e8f0; padding-top: 12px; }}
</style></head><body>
  <h1>Domain Attack-Surface Report — {domain}</h1>
  <div class="verdict"><span class="risk-pill">{'EXPOSURE' if confirmed_total else 'CLEAN'}</span>
    &nbsp;<b>{pill_text}.</b>
    <div class="small" style="margin-top:8px;">Passive assessment — subdomains discovered from
    Certificate Transparency ({html.escape(sources)}); live hosts scanned for exposed credentials and
    security-header posture. No exploitation, brute-force, or write operations were performed.</div>
  </div>

  <div class="grid">
    <div class="stat"><div class="num">{int(totals.get('subdomains', 0))}</div><div class="label">Subdomains found</div></div>
    <div class="stat"><div class="num">{int(totals.get('live_hosts', 0))}</div><div class="label">Live hosts</div></div>
    <div class="stat"><div class="num">{int(totals.get('hosts_scanned', 0))}</div><div class="label">Hosts scanned</div></div>
    <div class="stat"><div class="num">{int(totals.get('historical_urls', 0))}</div><div class="label">Historical URLs</div></div>
    <div class="stat"><div class="num">{confirmed_total}</div><div class="label">Confirmed exposures</div></div>
    <div class="stat"><div class="num">{int(totals.get('needs_review', 0))}</div><div class="label">Needs review</div></div>
    <div class="stat"><div class="num">{int(totals.get('posture_issues', 0))}</div><div class="label">Posture issues</div></div>
    <div class="stat"><div class="num">{int(totals.get('takeover_risks', 0))}</div><div class="label">Takeover risks</div></div>
  </div>

  <h2>Subdomain Takeover Risks</h2>
  <div class="small" style="margin-bottom:6px;">A host whose DNS still points at an unclaimed
  third-party service can be hijacked by an attacker to serve content from your domain. Treat any
  finding here as urgent: remove the dangling record or re-claim the resource.</div>
  <table>
    <thead><tr><th>Host</th><th>Severity</th><th>Service</th><th>CNAME</th><th>Evidence</th></tr></thead>
    <tbody>{takeover_rows}</tbody>
  </table>

  <h2>Per-host results</h2>
  <table>
    <thead><tr><th>Host</th><th>Status</th><th>Assets</th><th>Confirmed</th><th>Needs review</th><th>Posture</th><th>Note</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>

  <h2>Confirmed Findings (all hosts)</h2>
  <table>
    <thead><tr><th>Host</th><th>Severity</th><th>Type</th><th>Location</th><th>Confidence</th><th>AI Reasoning</th></tr></thead>
    <tbody>{conf_rows}</tbody>
  </table>

  <h2>Flagged for Manual Review (all hosts)</h2>
  <div class="small">Candidates a human should confirm — a structural match the AI could not
  confidently clear, or a scan where AI validation was unavailable. Not confirmed exposures.</div>
  <table>
    <thead><tr><th>Host</th><th>Severity</th><th>Type</th><th>Location</th><th>Note</th></tr></thead>
    <tbody>{review_rows}</tbody>
  </table>

  <h2>Discovered subdomain surface</h2>
  <div class="small mono">{subs}</div>

  <h2>Associated hosts (third-party / connected infrastructure)</h2>
  <div class="small mono">{assoc_hosts_html}</div>

  <footer>Generated by SecretNode v{_TOOL_VERSION} — passive attack-surface scanner.
  Report generated {generated}. Discovery via Certificate Transparency; all host scans passive
  (no exploitation, data exfiltration, or write operations). Authorized-scope testing only.</footer>
</body></html>"""
