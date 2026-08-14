#!/usr/bin/env python3
"""
QA harness for the v2.12.4 dashboard fixes (defects 3 and 4).

Loads the real frontend in Chromium, stubs only the network boundary
(fetch + WebSocket), and replays the exact event sequence from the
2026-08-14 16:11 UTC deep scan of cindrasec.com — two per-host sub-scans
under one parent scan ID.

Run against the fixed file and against the pre-fix file: a test that cannot
fail on the old code proves nothing.

    pip install playwright && playwright install chromium
    python backend/tests/qa_dashboard.py            # tests the working tree
    python backend/tests/qa_dashboard.py <path>     # or any index.html

Not a pytest: it needs a browser, which the unit suite deliberately does not.
Run it when touching the WebSocket event handling in frontend/index.html.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

PARENT = "6ad578be-81f2-4120-ad33-6a7bffd54f8b"   # names the HTML/CSV/SARIF exports
HOST_A = "7ac347b1-17b3-4f1b-8083-b15e795e5578"   # cindrasec.com
HOST_B = "7c19405d-c259-4cc5-81ff-c7760826e693"   # www.cindrasec.com — started last

BOOTSTRAP = """
window.__ws = null;
sessionStorage.setItem('secretnode_api_key', 'qa-key');

class FakeWebSocket {
  static OPEN = 1;
  constructor(url) {
    this.url = url; this.readyState = 1;
    window.__ws = this;
    setTimeout(() => this.onopen && this.onopen(), 0);
  }
  send() {}
  close() { this.readyState = 3; }
}
window.WebSocket = FakeWebSocket;

const realFetch = window.fetch.bind(window);
window.fetch = async (url, opts) => {
  const u = String(url);
  if (u.includes('/api/deep-scans')) {
    return new Response(JSON.stringify({ scan_id: '__PARENT__' }),
                        { status: 200, headers: { 'Content-Type': 'application/json' } });
  }
  // Everything else (stats, version, history polls) returns something benign
  // rather than a network error, so page bootstrap does not derail the test.
  return new Response('{}', { status: 200,
                              headers: { 'Content-Type': 'application/json' } });
};
""".replace("__PARENT__", PARENT)


# The sequence as it actually happened: both hosts start before either
# reports assets, which is exactly why the bug survived the live run.
EVENTS_CONCURRENT = [
    {"type": "scan_start", "scan_id": HOST_A, "target_url": "https://cindrasec.com"},
    {"type": "scan_start", "scan_id": HOST_B, "target_url": "https://www.cindrasec.com"},
    {"type": "assets_found", "count": 3, "urls": ["https://cindrasec.com/app.js"]},
    {"type": "assets_found", "count": 3, "urls": ["https://www.cindrasec.com/app.js"]},
    {"type": "deep_scan_complete", "totals": {"assets_fetched": 6, "hosts_scanned": 2,
                                              "duration_seconds": 22.17, "raw_findings": 0}},
]

# The same run at concurrency 1, or with hosts of uneven speed: host A finishes
# and reports its assets before host B starts. This is the ordering the live
# scan never happened to produce.
EVENTS_SEQUENTIAL = [
    {"type": "scan_start", "scan_id": HOST_A, "target_url": "https://cindrasec.com"},
    {"type": "assets_found", "count": 3, "urls": ["https://cindrasec.com/app.js"]},
    {"type": "scan_start", "scan_id": HOST_B, "target_url": "https://www.cindrasec.com"},
    {"type": "assets_found", "count": 3, "urls": ["https://www.cindrasec.com/app.js"]},
    {"type": "deep_scan_complete", "totals": {"assets_fetched": 6, "hosts_scanned": 2,
                                              "duration_seconds": 22.17, "raw_findings": 0}},
]


def run_case(page, url: str, events: list[dict]) -> dict:
    page.goto(url)
    page.wait_for_function("typeof window.startScan === 'function'")

    page.evaluate("""() => {
        document.getElementById('deep-input').checked = true;
        document.getElementById('target-input').value = 'cindrasec.com';
    }""")
    page.evaluate("() => window.startScan()")
    page.wait_for_function("window.__ws !== null")

    for ev in events:
        page.evaluate(
            "e => window.__ws.onmessage({ data: JSON.stringify(e) })", ev
        )

    # animateNumber() steps the stat tiles every 30ms, so reading them
    # synchronously measures the animation, not the value.
    page.wait_for_function(
        "() => document.getElementById('stat-assets').textContent === '6'", timeout=5000
    )

    return page.evaluate("""() => ({
        scanId:  document.getElementById('scan-id-display').textContent,
        badge:   document.getElementById('asset-count-badge').textContent,
        assets:  Array.from(document.getElementById('asset-list').children)
                      .map(d => d.textContent.replace('→ ', '').trim())
                      .filter(t => t && !t.startsWith('No assets')),
        tiles:   document.getElementById('stat-assets').textContent,
    })""")


def check(label: str, got, want) -> bool:
    ok = got == want
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    if not ok:
        print(f"           expected: {want!r}")
        print(f"           actual:   {got!r}")
    return ok


def _launch_kwargs() -> dict:
    """Prefer a Playwright-managed browser; fall back to a preinstalled one."""
    root = Path(os.environ.get("PLAYWRIGHT_BROWSERS_PATH", ""))
    if root.is_dir():
        for exe in sorted(root.glob("chromium-*/chrome-linux/chrome")):
            return {"executable_path": str(exe)}
    return {}


def main() -> int:
    default = Path(__file__).resolve().parents[2] / "frontend" / "index.html"
    target = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else default
    url = target.as_uri()
    expected_id = f"ID: {PARENT[:8]}…"
    failures = 0

    with sync_playwright() as pw:
        browser = pw.chromium.launch(**_launch_kwargs())
        ctx = browser.new_context()
        ctx.add_init_script(BOOTSTRAP)
        page = ctx.new_page()
        page.on("pageerror", lambda e: print(f"  [pageerror] {e}"))

        for name, events in (("concurrent (as it ran live)", EVENTS_CONCURRENT),
                             ("sequential (concurrency 1)", EVENTS_SEQUENTIAL)):
            print(f"\n── deep scan, {name} ──")
            r = run_case(page, url, events)
            failures += not check(
                "scan ID matches the parent that names the exports", r["scanId"], expected_id)
            failures += not check(
                "both hosts' assets survive the run",
                sorted(r["assets"]),
                ["https://cindrasec.com/app.js", "https://www.cindrasec.com/app.js"])
            failures += not check("asset badge agrees with the list", r["badge"], "2 URLs")
            failures += not check("stat tile takes the deep-scan total", r["tiles"], "6")

        # A single-target scan must be untouched: there the queued ID and the
        # scan_start ID are the same value, so the new guard is a no-op.
        print("\n── single-target scan (guard must be a no-op) ──")
        page.goto(url)
        page.wait_for_function("typeof window.startScan === 'function'")
        page.evaluate("""() => {
            document.getElementById('deep-input').checked = true;
            document.getElementById('target-input').value = 'cindrasec.com';
        }""")
        page.evaluate("() => window.startScan()")
        page.wait_for_function("window.__ws !== null")
        for ev in [
            {"type": "scan_start", "scan_id": PARENT, "target_url": "https://cindrasec.com"},
            {"type": "assets_found", "count": 2, "urls": ["https://cindrasec.com/app.js",
                                                          "https://cindrasec.com/sw.js"]},
        ]:
            page.evaluate("e => window.__ws.onmessage({ data: JSON.stringify(e) })", ev)
        r = page.evaluate("""() => ({
            scanId: document.getElementById('scan-id-display').textContent,
            count:  document.getElementById('asset-list').children.length,
        })""")
        failures += not check("scan ID still displayed", r["scanId"], expected_id)
        failures += not check("assets still rendered", r["count"], 2)

        browser.close()

    print(f"\n{'ALL CHECKS PASSED' if not failures else f'{failures} CHECK(S) FAILED'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
