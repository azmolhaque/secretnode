# SecretNode — ASM Scanner

![CI](https://github.com/azmolhaque/secretnode/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-yellow)
![Tests](https://img.shields.io/badge/tests-111%20passing-brightgreen)
![SARIF](https://img.shields.io/badge/export-SARIF%202.1.0-8a2be2)
![Verification](https://img.shields.io/badge/detection-verification--first-critical)

Passive Attack Surface Management scanner for detecting credential leaks in public-facing infrastructure.
Pipeline: **browser-like spider (+ source-map mining) → regex (54 patterns) + base64 decode → entropy filter → AI validation (Gemini) → optional live verification → Discord alerts**, with a live dashboard, SQLite history, scan diffing, false-positive suppression, a **CLI + GitHub Action**, and **SARIF / HTML / CSV** report export. Runs anywhere Python 3.11+ runs — tuned for Raspberry Pi 5 (ARM64, 16 GB RAM).

> **⚠ Authorized use only.** This is a passive, read-only tool for finding *your own* exposed credentials on
> infrastructure you own or are explicitly authorized to test. See [`SECURITY.md`](SECURITY.md).

> **v2.0.1 — Security hardening pass**
> This build fixes several issues found in an agency-readiness review before deployment:
> - **Path traversal** in the static file server — fixed.
> - **No authentication** on the API/WebSocket/dashboard — now requires `SECRETNODE_API_KEY` on every request; the server refuses to boot without it.
> - **Secrets leaking unredacted into Discord** via the code-snippet field — fixed; snippets are now redacted before dispatch.
> - **Stored/reflected XSS** in the dashboard via unescaped AI-reasoning/source-URL fields — fixed with a proper `escapeHtml()` pass.
> - **Insecure CORS** (`*` + credentials) — replaced with an explicit `ALLOWED_ORIGINS` allowlist.
> - **No SSRF guard** — scans against private/loopback/link-local targets (e.g. cloud metadata IPs) are now blocked by default (`ALLOW_PRIVATE_TARGETS=false`).
> - **No scan-scope restriction** — JS asset discovery now stays on the target's own domain by default (`SCOPE_SAME_DOMAIN=true`).
> - **No persistence** — scan results are now saved to SQLite (`storage.py`) via the previously-unused `aiosqlite` dependency, so history survives restarts. New endpoint: `GET /api/scans/history`.
>
> **Before your first run:** copy `.env.example` to `.env` and set `SECRETNODE_API_KEY` (e.g. `openssl rand -hex 24`). The dashboard will prompt you for this key on first load and remember it for the browser session.

> **v2.0.2 — Industrial-grade reliability pass**
> - **Fixed a silent data-loss bug**: findings that failed AI validation after all retries used to vanish with no log — now they're returned as a clearly-flagged `needs_review` finding (never dropped), broadcast to the dashboard, persisted, and Discord-alerted if the underlying pattern is CRITICAL severity.
> - **Concurrent-scan cap** (`MAX_CONCURRENT_SCANS`, default 3) — protects the Pi 5 from resource exhaustion if multiple scans are triggered at once; returns a clear `429` instead of silently degrading.
> - **Raw-findings safety cap** (`MAX_RAW_FINDINGS_PER_SCAN`, default 500) — a minified/obfuscated bundle full of high-entropy noise can no longer generate unbounded Gemini calls or memory use.
> - **Audit logging** — every scan request now logs the requesting IP and target URL.
> - **Input validation** — `target_url` now has a max length; malformed requests fail fast with a clear 400 instead of propagating.
> - **Richer health check** (`/api/health`) reports Gemini/Discord configuration status and active scan count — useful for uptime monitoring.
> - **20-test pytest smoke suite** added (`backend/tests/test_scanner.py`) covering entropy scoring, redaction, scope restriction, and the needs-review regression — run with `pytest backend/tests/ -v`.

> **v2.1.0 — New features**
> - **Scan diffing** — every scan now compares against the most recent prior scan of the same `target_url` and marks each confirmed finding `NEW` or `RECURRING`. Discord only alerts on genuinely new findings, so re-scanning a long-lived target no longer spams the channel.
> - **False-positive suppression** — mark any finding as a false positive from the dashboard (FP button) or via `POST /api/findings/suppress`. Suppressed fingerprints are silently filtered out of all future scans of that target. Manage the list via `GET /api/findings/suppressed` / `DELETE /api/findings/suppress/{fingerprint}`.
> - **Client-ready report export** — `GET /api/scans/{scan_id}/report?format=html|csv|json`. The HTML report is self-contained and print-styled (browser "Print → Save as PDF" gives you a PDF deliverable without a heavy PDF-rendering dependency on the Pi). Buttons added to the dashboard.
> - **Multi-page crawling** — scans can now shallow-crawl same-domain pages linked from the target (`crawl_pages`, default 1 = target page only, capped at `MAX_CRAWL_PAGES_CAP`). Set the "PAGES" field in the dashboard or pass `crawl_pages` in the API body.
> - **robots.txt awareness** — logs a notice if the target disallows crawling (informational only — this is an authorized security tool, not a generic bot, so it does not block the scan).
> - **13 new tests** (fingerprinting, page-link extraction, storage diffing/suppression roundtrips) — suite is now 33 tests total.

> **v2.2.0 — Capability & industrial-grade release**
> - **Detection registry expanded 16 → 37 patterns** — OpenAI, Anthropic, GitLab, GitHub fine-grained PATs, Slack tokens, npm, PyPI, DigitalOcean, HashiCorp Vault, Google OAuth secrets, Square, Postman, Databricks, Telegram, Discord, Datadog, Azure Storage keys, Firebase, bearer tokens, PGP keys, and **database URIs / basic-auth URLs with embedded credentials**.
> - **Every finding now carries `severity`, a `CWE` id, and a `remediation` string** — flowing into all reports and exports.
> - **SARIF 2.1.0 export** (`?format=sarif`) — upload findings to GitHub code scanning or any SARIF-aware CI pipeline.
> - **Severity-aware reports** — HTML/CSV sort critical-first and include per-type remediation guidance.
> - **Environment-tunable engine** — the tuning constants the docs referenced are now actually read from env vars.
> - **Industrial-grade scaffolding** — MIT `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `pyproject.toml` (ruff + pytest), **GitHub Actions CI** (lint + tests on 3.11/3.12 + Docker build), `Dockerfile` + `docker-compose.yml`.
> - **Suite grew 33 → 58 tests.** Run with `pytest`.

> **v2.3.0 — ASM-industry alignment: verification-first & CI-native**
> Grounded in 2025–2026 ASM / secret-scanning practice (verification-first detection + CI-native gating).
> - **Optional live verification** (`VERIFY_SECRETS` / `?verify=true`) — read-only "is this key still active?" checks against each secret's own provider (GitHub, GitLab, Stripe, SendGrid, OpenAI, Slack, npm, Mailgun, Telegram, Cloudflare, DigitalOcean, Datadog, Notion, Linear, Figma, Postman, Doppler), à la TruffleHog `--only-verified`. **Off by default**, fails closed, never touches the scan target. Each finding gains a `verified` status, and `only_verified` mode drops dead-key noise.
> - **Base64 decoding** of encoded blobs + **example/placeholder allowlisting** (e.g. AWS's `AKIAIOSFODNN7EXAMPLE`) — fewer false positives, more real catches.
> - **CLI (`backend/cli.py`) + GitHub Action (`action.yml`)** — scan and emit SARIF from CI with `--fail-on-findings` as a build gate.
> - **Registry now 44 patterns** (added Slack app-level, GitHub server/refresh, OpenAI service-account, New Relic, Grafana, HCP Terraform).
> - **Suite grew 58 → 82 tests.**

> **v2.4.0 — Field-hardening: WAF-resilient fetching, deeper coverage, current-gen detectors**
> Driven by real Pi-5 dashboard runs against live targets that exposed three gaps.
> - **Browser-like HTTP client (headline fix)** — a `SecretNode-bot` User-Agent got an instant **HTTP 403** from Cloudflare/WAF-fronted sites, so the scan couldn't even fetch the root. Now presents a current Chrome fingerprint (UA + Client-Hints + `Sec-Fetch-*` + HTTP/2) and, on a WAF challenge, **retries with a rotated fingerprint** and prints a diagnostic naming the likely cause. Resilience for *authorized* testing — scope, SSRF guard, passive-only behaviour and the authorization gate are unchanged (`SECRETNODE_USER_AGENT` to override).
> - **Source-map mining** — declared `//# sourceMappingURL=` maps (`.js.map`) are fetched and scanned. Source maps carry the **un-minified original source** (comments, endpoints, hard-coded secrets stripped from the shipped bundle). `FOLLOW_SOURCE_MAPS` / `MAX_SOURCE_MAPS`.
> - **Broader discovery** — `<script type="module">`, `<link rel="modulepreload">` and `preload as="script">` are now discovered; a **content-type gate** skips binary assets early.
> - **10 current-generation detectors** — Supabase (2), Sentry DSN, Linear, Notion, Doppler, PostHog, Figma, Cloudflare (2026 prefixes), and Google Cloud **service-account JSON** keys. **Registry now 54 patterns.**
> - **Dashboard** — live-verification `VERIFY` toggle; a clean post-scan WS close shows `WS: IDLE` (not a red error) and a mid-scan drop auto-reconnects once; the assets panel reflects every collected asset.
> - **Suite grew 82 → 111 tests.** New optional deps `h2` + `brotli` degrade gracefully if absent.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Browser Dashboard (Vanilla JS + Tailwind CSS)                   │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────────┐  │
│  │ Scan Control│  │ Live Terminal│  │ Verified Findings Table│  │
│  └──────┬──────┘  └──────┬───────┘  └────────────┬───────────┘  │
│         │ POST /api/scans │ WebSocket /ws/logs/{id}│             │
└─────────┼─────────────────┼────────────────────────┼────────────┘
          │                 │                         │
┌─────────▼─────────────────▼─────────────────────────▼──────────┐
│  FastAPI (main.py)  —  uvicorn + uvloop                          │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  ConnectionManager: per-scan WS fan-out + global feed    │   │
│  │  ScanRegistry:      asyncio.Task map  + ScanState        │   │
│  └──────────────────────────┬───────────────────────────────┘   │
└─────────────────────────────┼───────────────────────────────────┘
                              │ asyncio.create_task
┌─────────────────────────────▼───────────────────────────────────┐
│  scanner.py  —  Core Engine                                      │
│                                                                  │
│  spider_target()                                                 │
│    └─ fetch_url()  × N  (asyncio.Semaphore(20), retry×3)        │
│    └─ extract_js_urls()  (regex HTML parse)                      │
│                                                                  │
│  extract_secrets()                                               │
│    └─ 54 SECRET_PATTERNS  (AWS, GCP, Slack, JWT, GitHub…)       │
│    └─ shannon_entropy()   (filter < 3.5 bits)                   │
│                                                                  │
│  validate_with_gemini()  — two-tier engine (google-genai SDK)   │
│    └─ Tier 1 pre-filter:  gemini-3.1-flash-lite (thinking:min)  │
│    └─ Tier 2 deep-valid.: gemini-3.5-flash      (thinking:high) │
│    └─ Structured output → Pydantic GeminiVerdict               │
│       {is_valid, confidence, reason}                            │
│                                                                  │
│  dispatch_discord()                                              │
│    └─ Rich embed via httpx.post                                  │
│    └─ Gate: is_valid=true AND confidence ≥ 80                   │
└─────────────────────────────────────────────────────────────────┘
```

### Key Design Decisions

| Component | Choice | Reason |
|---|---|---|
| Event loop | `uvloop` | 2–4× faster than default asyncio on ARM64 |
| HTTP | `httpx.AsyncClient` | Native async, connection pooling, retries |
| Concurrency | `asyncio.Semaphore(20)` | Bounds RAM on Pi 5 during deep JS analysis |
| AI | Two-tier Gemini (`google-genai`): 3.1-flash-lite → 3.5-flash | Cheap pre-filter kills noise; strong tier deep-validates real/critical findings with structured output |
| Transport | WebSocket fan-out | Browser gets live logs without polling |
| Frontend | Vanilla JS + Tailwind CDN | Zero build step, deployable immediately |

---

## File Structure

```
secretnode/
├── backend/
│   ├── main.py              # FastAPI app: REST + WebSocket + static server + auth/SSRF guards
│   ├── scanner.py           # Async scan engine (54 patterns, source maps, entropy, base64, Gemini, Discord)
│   ├── verifier.py          # Optional live credential verification (off by default)
│   ├── cli.py               # CLI entrypoint (scan → SARIF/JSON/CSV/HTML; CI gate)
│   ├── storage.py           # SQLite persistence: scan history + false-positive suppression
│   ├── report.py            # HTML / CSV / SARIF report generation (+ verified status)
│   └── tests/               # 82-test pytest suite
├── frontend/
│   └── index.html           # Live dashboard SPA (vanilla JS + Tailwind)
├── .github/
│   ├── workflows/ci.yml     # CI: ruff + pytest (3.11/3.12) + Docker build
│   ├── ISSUE_TEMPLATE/      # Bug / feature templates
│   └── pull_request_template.md
├── action.yml               # Composite GitHub Action (SARIF in CI)
├── Dockerfile               # Non-root, healthchecked container image
├── docker-compose.yml
├── pyproject.toml           # Packaging + ruff + pytest config
├── Makefile                 # setup / test / lint / run / docker shortcuts
├── requirements.txt
├── setup.sh                 # One-shot bootstrap (venv, deps, .env, systemd)
├── .env.example
├── LICENSE  SECURITY.md  CONTRIBUTING.md  CHANGELOG.md
└── README.md
```

---

## Quick Start (Raspberry Pi 5)

### 1. Clone / transfer files
```bash
git clone https://github.com/azmolhaque/secretnode.git
cd secretnode
```

### 2. Run setup
```bash
chmod +x setup.sh
./setup.sh
```

The script will:
- Check Python 3.11+
- Install system dependencies (libxml2, libxslt for lxml on ARM64)
- Create a Python virtual environment at `.venv/`
- Install all Python requirements
- Generate a `.env` file template
- Optionally install a systemd service
- Offer to start the server immediately

### 3. Configure credentials
```bash
nano .env
```
Fill in `GEMINI_API_KEY` and `DISCORD_WEBHOOK_URL`.

### 4. Start manually (if needed)
```bash
cd backend
source ../.venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 8000 --loop uvloop
```

### 5. Access dashboard
```
http://<raspberry-pi-ip>:8000
```

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/health` | Health check |
| POST | `/api/scans` | Start a new scan |
| POST | `/api/scans/{id}/stop` | Cancel a running scan |
| GET | `/api/scans` | List all scans (session) |
| GET | `/api/scans/{id}` | Get scan detail + findings |
| GET | `/api/scans/{id}/status` | Lightweight status poll |
| GET | `/api/active` | List running scans |
| WS | `/ws/logs/{scan_id}` | Per-scan live event stream |
| WS | `/ws/logs` | Global event stream |

### WebSocket Event Types

| type | Payload | Description |
|---|---|---|
| `scan_start` | `{scan_id, target_url}` | Scan initiated |
| `log` | `{level, message}` | Terminal log line |
| `status` | `{stage}` | Pipeline stage change |
| `assets_found` | `{count, urls[]}` | Assets collected (JS + source maps) |
| `raw_count` | `{count}` | Raw regex candidates |
| `finding` | `{data: ValidatedFinding}` | Confirmed secret |
| `scan_complete` | `{scan_id, result}` | Scan finished |
| `scan_cancelled` | `{scan_id}` | User stopped scan |
| `scan_error` | `{error}` | Fatal scan error |

---

## Secret Patterns Detected (44)

Every pattern carries a **severity** and a **CWE** id, and only fires after passing a Shannon-entropy
filter (so obvious placeholders like `YOUR_API_KEY_HERE` are dropped before the AI stage).

**CRITICAL** — AWS Access/Secret Key · GitHub PAT (classic + fine-grained) · GitLab PAT · Stripe Secret Key ·
OpenAI Key · Anthropic Key · Slack Token · npm Token · PyPI Token · DigitalOcean PAT · HashiCorp Vault Token ·
Azure Storage Key · HCP Terraform · OpenAI Service-Account · PEM/PGP Private Key · **Database URI with credentials**

**HIGH** — Google Cloud/OAuth · GitHub OAuth · Slack Webhook · SendGrid · Twilio · Heroku · Shopify · Mailgun ·
Square · Postman · Databricks · Telegram Bot · Discord Bot · Datadog · Firebase FCM · Slack App-Level · GitHub Server/Refresh · New Relic · Grafana · JWT · **Basic-auth URL**

**MEDIUM** — Stripe Publishable Key · Bearer Token · Generic High-Entropy Secret

Matches are also checked against **base64-decoded** content and filtered through an **example/placeholder allowlist**. Many types (GitHub, GitLab, Stripe, SendGrid, OpenAI, Slack, npm, Mailgun, Telegram, Cloudflare, DigitalOcean, Datadog, Notion, Linear, Figma, Postman, Doppler) can be **live-verified** (see below). New patterns land with a `severity`, `cwe`, and `remediation` — see [`CONTRIBUTING.md`](CONTRIBUTING.md).

---

## Reports & exports

`GET /api/scans/{id}/report?format=html|csv|json|sarif`

| Format | Use |
|---|---|
| `html` | Self-contained, print-styled report → browser **Print → Save as PDF** for a client deliverable |
| `csv`  | Spreadsheet-friendly export (severity, CWE, confidence, status per finding) |
| `json` | Raw structured scan record |
| `sarif`| **SARIF 2.1.0** — upload to GitHub code scanning or ingest in any SARIF-aware CI/security pipeline |

---

## Using the API

Every `/api/*` call needs the `X-API-Key` header; WebSocket connections pass `?api_key=`.
FastAPI also serves interactive docs at **`/docs`** (Swagger UI) and **`/redoc`**.

```bash
export KEY=your_secretnode_api_key

# 1) Health / config check
curl -s localhost:8000/api/health | jq

# 2) Start a scan (crawl up to 3 same-domain pages)
curl -s -X POST localhost:8000/api/scans \
  -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '{"target_url":"https://example.com","crawl_pages":3}' | jq
#   -> { "scan_id": "…", "ws_url": "/ws/logs/…", … }

# 3) Stream live events (needs a websocket client, e.g. websocat)
websocat "ws://localhost:8000/ws/logs/<scan_id>?api_key=$KEY"

# 4) Fetch findings once complete
curl -s localhost:8000/api/scans/<scan_id> -H "X-API-Key: $KEY" | jq '.confirmed_findings'

# 5) Export a report — html | csv | json | sarif
curl -s "localhost:8000/api/scans/<scan_id>/report?format=sarif" \
  -H "X-API-Key: $KEY" -o findings.sarif

# 6) Mark a false positive (never re-alerts on future scans of this target)
curl -s -X POST localhost:8000/api/findings/suppress \
  -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '{"fingerprint":"<fp>","target_url":"https://example.com","note":"mock key"}'

# 7) Review persisted history (survives restarts)
curl -s localhost:8000/api/scans/history -H "X-API-Key: $KEY" | jq '.scans[] | {target_url, confirmed_count, created_at}'
```

**CI integration:** run a scan, export SARIF, and upload it to GitHub code scanning with
`github/codeql-action/upload-sarif`, or feed it to any SARIF-aware pipeline.

---

## Verification (opt-in) — is the secret actually live?

Following the industry shift to **verification-first** detection, SecretNode can confirm whether a
confirmed finding is a **currently active** credential — the single biggest lever against
false-positive fatigue.

- **Off by default.** Enable per scan (`{"verify": true}` / `--verify`) or globally (`VERIFY_SECRETS=true`).
- **Read-only.** One "whoami"-style call to the secret's **own provider** (never the scan target):
  GitHub, GitLab, Stripe, SendGrid, OpenAI, Slack, npm, Mailgun, Telegram, Cloudflare, DigitalOcean, Datadog, Notion, Linear, Figma, Postman, Doppler. Fails closed on any error.
- Each finding gets a `verified` status: `verified` (active), `unverified` (dead / unconfirmed),
  `unsupported` (no safe auto-check — verify manually).
- **`only_verified`** drops confirmed-inactive findings so a pipeline only fails on live secrets.

> ⚠️ Verifying a credential means using it (read-only) against its issuer. Only do this on assets
> you own or are authorized to test. See [`SECURITY.md`](SECURITY.md).

---

## Run in CI (CLI + GitHub Action)

**CLI** — emits SARIF/JSON/CSV/HTML; `--fail-on-findings` makes it a build gate:

```bash
python backend/cli.py https://example.com -f sarif -o secretnode.sarif
python backend/cli.py https://example.com --crawl 5 --fail-on-findings
GEMINI_API_KEY=... python backend/cli.py https://example.com --verify
```

**GitHub Action** — scan and upload results to code scanning:

```yaml
- uses: azmolhaque/secretnode@main
  with:
    target: https://example.com
    fail-on-findings: "true"
    gemini-api-key: ${{ secrets.GEMINI_API_KEY }}
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: secretnode.sarif
```

---

## Run with Docker

```bash
cp .env.example .env    # then set SECRETNODE_API_KEY, GEMINI_API_KEY, DISCORD_WEBHOOK_URL
docker compose up --build
# dashboard: http://localhost:8000
```

Or a one-off container:

```bash
docker build -t secretnode .
docker run -p 8000:8000   -e SECRETNODE_API_KEY=$(openssl rand -hex 24)   -e GEMINI_API_KEY=... -e DISCORD_WEBHOOK_URL=...   secretnode
```

The image runs as a non-root user, includes a `/api/health` healthcheck, and persists scan
history in a named volume.

---

## Security & Legal

> **⚠ AUTHORIZED USE ONLY**
> This tool is for security professionals conducting authorized penetration tests and bug bounty reconnaissance on infrastructure they own or have explicit written permission to test. Unauthorized scanning is illegal and unethical.

- Secrets found are partially redacted in reports, logs, and Discord alerts
- Scan history is persisted to SQLite (`backend/data/secretnode.db`) — survives restarts
- The API/WebSocket/dashboard require `SECRETNODE_API_KEY` on every request (the server refuses to boot without one)

---

## Tuning for Raspberry Pi 5

The defaults are already tuned for the Pi 5's capabilities:

```python
CONCURRENCY_LIMIT    = 20   # parallel HTTP fetches
FETCH_TIMEOUT        = 20.0 # seconds per request  
MIN_ENTROPY_THRESHOLD = 3.5  # bits — filters ~80% of false matches before AI
MAX_ASSET_BYTES      = 5MB  # skip oversized JS bundles
GEMINI_CONFIDENCE_MIN = 80  # only alert on high-confidence findings
```

All of these are now **environment variables** (set them in `.env`) — no code edits needed:

- To reduce Gemini API costs, set `MIN_ENTROPY_THRESHOLD=4.0`.
- To scan deeper, set `CONCURRENCY_LIMIT=40` (watch RAM with `htop`).
- See `.env.example` for the full list of tunables.

### Fetching & coverage (v2.4.0)

| Variable | Default | Purpose |
|---|---|---|
| `SECRETNODE_USER_AGENT` | *(unset → real Chrome UA)* | Force a specific User-Agent (e.g. a client-approved test-agent string). Unset = current-Chrome fingerprint with automatic rotation on a WAF challenge. |
| `FOLLOW_SOURCE_MAPS` | `true` | Follow declared `//# sourceMappingURL=` maps (`.js.map`) and scan their un-minified original source. |
| `MAX_SOURCE_MAPS` | `40` | Cap on source maps fetched per scan. |
| `SCOPE_SAME_DOMAIN` | `true` | Keep asset/source-map discovery on the target's own registrable domain. |

> **Why a browser User-Agent?** A `SecretNode-bot` agent gets an instant HTTP 403 from
> Cloudflare/WAF-fronted sites, so an authorized scan of a target *you own* couldn't reach the
> same surface an attacker would. Presenting a normal browser fingerprint is standard for
> security scanners (Burp, ZAP, nuclei all do it) and is resilience for **authorized** testing —
> the SSRF guard, same-domain scope, passive-only behaviour and the authorization gate
> (see [`SECURITY.md`](SECURITY.md)) are all unchanged.
