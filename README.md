# SecretNode — ASM Scanner

![CI](https://github.com/azmolhaque/secretnode/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-yellow)
![Tests](https://img.shields.io/badge/tests-805%20passing-brightgreen)
![Version](https://img.shields.io/badge/version-2.14.4-blue)
![SARIF](https://img.shields.io/badge/export-SARIF%202.1.0-8a2be2)
![Verification](https://img.shields.io/badge/detection-verification--first-critical)

Passive Attack Surface Management scanner for detecting credential leaks in public-facing infrastructure.
Pipeline: **browser-like spider (+ source-map mining, guarded redirects) → regex (71 patterns) + composite/proximity rules + base64 decode → entropy filter → AI validation (Gemini) *or* deterministic offline triage → optional live verification → Discord alerts**, with a live dashboard, SQLite history, scan diffing, false-positive suppression, a **CLI + GitHub Action**, and **SARIF / HTML / CSV / JSON** report export. It scans a single target, or takes a **whole domain** and enumerates it — subdomain discovery, liveness probing, subdomain-takeover checks and historical-URL mining, then scans every live host concurrently and aggregates the result into one report. Runs anywhere Python 3.11+ runs — tuned for Raspberry Pi 5 (ARM64, 16 GB RAM).

> **⚠ Authorized use only.** This is a passive, read-only tool for finding *your own* exposed credentials on
> infrastructure you own or are explicitly authorized to test. See [`SECURITY.md`](SECURITY.md).

> **v2.14.4 — a host that was never read reported as scanned** ·
> [full changelog](CHANGELOG.md) ·
> [releases](https://github.com/azmolhaque/secretnode/releases)
>
> A live deep scan of a 258-subdomain estate. v2.13.1's coverage verdict and
> posture section both worked on it; reading the report against its own CSV
> turned up three defects anyway.
>
> **`i.test` was still there, from a construct the earlier fix never saw.** The
> bundle supplied with the report came back *clean* when tested directly, which
> pointed at a different shape: `/^https?:\/\//i.test(u)`, the idiomatic
> absolute-URL test. v2.13.1 taught the stripper to recognise a regex literal but
> left its text in place — and that literal's own escaped slashes spell
> `//i.test`. Bodies are now blanked; a host inside a pattern has escaped dots
> and was never extractable anyway.
>
> **Blanking then turned a harmless misparse into a dropped finding**, caught by a
> test predating all of this work. `</script>` opens with a slash exactly where a
> literal would, so scanning on swallowed a real external host out of the graph.
> Latent and free for two releases; a false negative only once an unrelated
> improvement changed what happened to the text it mis-tokenised.
>
> **One host's evidence was printed for a whole posture group** — `server:
> AmazonS3` shown against a host actually disclosing `Microsoft-IIS/10.0`. For
> version disclosure the evidence *is* the finding. And **`AmazonS3` is not a
> version disclosure**: the check was `any(c.isdigit())`, and the 3 is part of a
> product name.
>
> The two releases before it: **v2.14.1** bounded three limits that were
> documented, asserted or implied but unenforced; **v2.14.0** gave recall a number
> measured against a corpus this project did not write (80.6%), which immediately
> found the current OpenAI key formats undetected.
>
> Release notes live in [`CHANGELOG.md`](CHANGELOG.md), which is the single source of truth — this
> README no longer keeps a second copy that can drift out of date.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Browser Dashboard (Vanilla JS, self-hosted CSS — no CDN)        │
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
│    └─ 71 SECRET_PATTERNS  (AWS, GCP, Slack, JWT, GitHub…)       │
│    └─ shannon_entropy()   (filter < 3.5 bits)                   │
│                                                                  │
│  validate_with_gemini()  — two-tier engine (google-genai SDK)   │
│    └─ Tier 1 pre-filter:  gemini-3.5-flash-lite (thinking:min)  │
│    └─ Tier 2 deep-valid.: gemini-3.6-flash      (thinking:high) │
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
| Concurrency | `asyncio.Semaphore(20)` | Bounds *in-flight fetches* — not retained bytes |
| Memory ceiling | `MAX_TOTAL_ASSET_BYTES` (256 MB) | Bounds what a scan *keeps*; the semaphore never did |
| AI | Two-tier Gemini (`google-genai`): 3.5-flash-lite → 3.6-flash | Cheap pre-filter kills noise; strong tier deep-validates real/critical findings with structured output |
| Transport | WebSocket fan-out | Browser gets live logs without polling |
| Frontend | Vanilla JS, self-hosted CSS + fonts | Zero build step, deployable immediately, fully offline-capable (no Tailwind CDN — removed; see `frontend/index.html`) |

---

## File Structure

```
secretnode/
├── backend/
│   ├── main.py              # FastAPI app: REST + WebSocket + static server + auth/SSRF guards
│   ├── scanner.py           # Async scan engine (71 patterns, source maps, entropy, base64, Gemini, Discord)
│   ├── verifier.py          # Optional live credential verification (off by default)
│   ├── netguard.py          # "May this scanner request this?" — pre-flight AND every redirect hop
│   ├── triage.py            # Deterministic verdicts with no API key, no network, no model
│   ├── composite.py         # R7 proximity rules: an anchor supplies the identity a value lacks
│   ├── cli.py               # CLI entrypoint (scan → SARIF/JSON/CSV/HTML; CI gate)
│   ├── storage.py           # SQLite persistence: scan history + false-positive suppression
│   ├── report.py            # HTML / CSV / SARIF report generation (+ verified status)
│   ├── watch.py             # Continuous monitoring: scan-to-scan delta, triage, client digest
│   ├── ops/                 # Operations layer: local-LLM adapter + grounding/prompt guards
│   │   ├── llm.py           #   Ollama, schema-constrained, Pi-tuned, fails loudly
│   │   ├── guards.py        #   Grounding (anti-hallucination) + refuse secrets in prompts
│   │   ├── ledger.py        #   Authorization ledger — the gate every scan passes
│   │   ├── contacts.py      #   Verified contact lookup (`python3 -m ops.contacts acme.com`)
│   │   └── selfcheck.py     #   `python3 -m ops.selfcheck` — verify it works on this Pi
│   └── tests/               # pytest suite (see badge above for current count)
├── frontend/
│   └── index.html           # Live dashboard SPA (vanilla JS, self-hosted CSS)
├── .github/
│   ├── workflows/ci.yml     # CI: ruff + pytest (3.11/3.12) + Docker build
│   ├── ISSUE_TEMPLATE/      # Bug / feature templates
│   └── pull_request_template.md
├── watch-roster.example.json # Template for the monitored-target roster (real one is gitignored)
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

## Secret Patterns Detected (63)

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

# 3b) Or hand it a whole domain — enumerate, probe, then scan every live host
curl -sX POST localhost:8000/api/deep-scans \
  -H "X-API-Key: $SECRETNODE_API_KEY" -H 'content-type: application/json' \
  -d '{"domain":"example.com","crawl_pages":3,"max_targets":25,"include_historical":true}'
#   -> same {scan_id, ws_url} shape; findings and reports are aggregated across hosts

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

## Watch — continuous monitoring (v2.9.0)

A single scan says what is exposed now. Monitoring has to say **what changed, and whether
it needs a human today.** `backend/watch.py` is that layer — pure functions over two scan
records, no network and no database of its own:

```python
from watch import compute_delta, classify, render_digest

delta        = compute_delta(current_scan, previous_scan)   # new / resolved / recurring
tier, why    = classify(delta)                              # URGENT | REVIEW | ROUTINE
draft        = render_digest(delta, client="Acme Ltd", period="August 2026")
```

**Triage rules.** A new CRITICAL/HIGH finding is `URGENT`. So is any new finding that
live-verification confirmed is an *active* credential — a MEDIUM secret that provably
works is a way in, and holding it for the monthly report is indefensible. Everything else
new is `REVIEW`; a period with no new findings is `ROUTINE`.

**Resolution is claimed carefully.** A finding vanishes from a scan for two reasons that
look identical in the data: it was fixed, or this run saw less than the last one (asset
404'd, WAF blocked it, crawl budget ran out, scan errored). Resolution is asserted only
when the scan completed *and* coverage is within 50% of the previous run. Otherwise those
findings are reported as "no longer observed, resolution unconfirmed" and the digest says
so in plain language. A weaker claim that is true beats a stronger one that might not be.

**Nothing is sent automatically.** `render_digest()` returns a draft for human review, with
all internal triage notes inside a single HTML comment — delete that block and the document
is client-ready. Two checkpoints are never automated here: the authorization to scan at
all, and the final severity call on anything critical.

**Roster.** Copy `watch-roster.example.json` to `watch-roster.json` (gitignored — it names
clients and their infrastructure) and list the monitored targets. A missing roster raises
rather than running zero targets, because "monitoring completed, nothing to do" is the most
dangerous way for a paid subscription to fail. Listing a host schedules a scan; it does not
authorize one — that still comes from a signed RoE.

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

### Where the passive line actually falls

Worth stating precisely, because "passive scanner" gets used loosely:

- **By default, SecretNode never contacts a third-party provider with a credential it found.** It
  reads what the target already serves in public — pages, JavaScript bundles, source maps,
  configuration — and never authenticates, never writes, never modifies.
- **Liveness checking is a separate, opt-in step.** `--verify` exists (see
  [Verification](#verification-opt-in--is-the-secret-actually-live)), it is off unless asked for,
  and it is the smallest metadata call that establishes whether a key is still valid. It stops
  there.
- **The distinction is the point.** A report that says *"exposed, and I have not confirmed it is
  active"* is weaker copy and a more honest artifact. Choosing when to cross that line belongs to
  whoever signed the authorization, not to the tool.

---

## Who builds this

SecretNode is written and maintained by **[Md. Azmol Haque Rony](https://github.com/azmolhaque)**
— Google VRP–credited, Dhaka, Bangladesh. It is MIT-licensed and free to use, and it is also the
delivery engine behind the continuous-monitoring tier at **[Cindrasec](https://cindrasec.com)**
(also in [বাংলা](https://cindrasec.com/bn/)), an attack-surface and AI/LLM security studio for
founders and SMEs.

The code is public for a specific reason: a client evaluating a security vendor can read exactly
what the scanner does with their credentials instead of taking the vendor's word for it. That is
harder to fake than a testimonial.

Related published research, in 9 languages each:

- [Anatomy of an Exposed IAM Frontend — Google VRP](https://github.com/azmolhaque/security-writeups/blob/main/2026-05-exposed-iam-frontend-google-vrp.md) — a full authentication bypass on Google-acquisition infrastructure, fixed in 9 days, and why it resolved to credit rather than cash.
- [The Same Model, 4.6× the Exposure](https://github.com/azmolhaque/security-writeups/blob/main/2026-07-prompt-injection-content-dependent.md) — prompt-injection resistance measured over 256 trials per attack: 46.9% vs 10.2% for the same model, with non-overlapping 95% confidence intervals.

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
