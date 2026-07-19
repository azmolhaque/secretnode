# Changelog

All notable changes to SecretNode are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **Subdomain-takeover detection (deep-dive slice D1).** New `backend/takeover.py` flags hosts whose
  DNS still points (via CNAME) at an **unclaimed third-party service** (S3, GitHub Pages, Heroku,
  Netlify, Shopify, Fastly, Zendesk, …) — a hijackable subdomain an attacker can claim to serve
  content from the target's domain. High-precision by design: a host is flagged only when the
  response carries a service's *specific* unclaimed-resource signature (generic 404s excluded), with
  the CNAME recorded as corroborating evidence. The deep scan runs a concurrent takeover pass over
  every in-scope host; results surface as CRITICAL/HIGH findings with a "Subdomain Takeover Risks"
  section + KPI in the combined report. Passive (DNS + one GET), stdlib-only, ReDoS-free.
- **Surface intelligence: endpoints + associated-host graph (deep-ASM slices 5 & 4).** New
  `backend/surface.py` mines every fetched asset (passively, no new target requests) for two things:
  **(5)** URLs/paths referenced in the JavaScript — `fetch()`/`axios` targets, `/api/…` routes a live
  page crawl never links to — and then fetches same-site `.js` endpoints **one level deeper** so
  code-referenced bundles get secret-scanned too; and **(4)** the external hosts each asset talks to
  (CDNs, APIs, third parties), aggregated into an **associated-asset graph**. `run_scan` now returns
  `discovered_endpoints` + `associated_hosts`; both reports gain an "Attack Surface Intelligence"
  section. Extractor regexes are bounded/ReDoS-safe. Config: `EXTRACT_SURFACE`, `MAX_ENDPOINT_SEEDS`,
  `MAX_DISCOVERED_ENDPOINTS`.
- **Dashboard domain-mode + deep-scan API (deep-ASM slice 6).** The whole deep-ASM pipeline is now
  drivable from the web UI, not just the CLI. New `POST /api/deep-scans` runs a domain-wide deep scan
  as a streaming background task — per-host progress flows over the existing `/ws/logs/{scan_id}`
  WebSocket (`run_deep_scan` gained a `broadcast` hook and emits enumerate/probe/per-host/complete
  events), and the report endpoint serves the combined multi-target report for deep results.
  Frontend: a **DEEP toggle** turns the target box into a whole-domain scan (bare domain in →
  enumerate + historical + probe + scan-all), finalising on `deep_scan_complete` rather than
  per-host. API tests added (route, auth, input caps, start). Passive; authorized-scope only.
- **Historical bundles fed into the scan (deep-ASM slice 3.5).** `run_scan()` gains a `seed_urls`
  parameter — externally-supplied asset URLs are fetched and scanned alongside the live crawl,
  deduped against it (capped by `MAX_SEED_URLS`). `run_deep_scan(include_historical=True)` now
  recovers the domain's historical JS bundles (Wayback/CommonCrawl) and routes each host its own
  archived bundles as seeds, so a secret in a forgotten bundle **no live page links to** still gets
  fetched and confirmed. CLI: `python cli.py <domain> --deep-scan --with-historical`; the combined
  report gains a "Historical URLs" metric. This turns discovery into findings — the payoff of the
  whole passive discovery chain.
- **Historical path discovery (deep-ASM slice 3).** New `backend/historical.py` recovers a domain's
  historically-exposed URLs from **public web archives (Wayback Machine + CommonCrawl)** — the
  passive alternative to directory/content brute-forcing, so no request ever touches the target. Two
  sources merged with backoff retries and fail-closed handling (matching the subdomain layer);
  surfaces forgotten endpoints, stale JS bundles and old admin paths a live crawl would never link
  to. `HistoricalResult` exposes the raw URLs, the unique-path view ("hidden directories"), and a
  `js_urls()` helper (highest-value scan seeds). CLI: `python cli.py <domain> --historical`. Config:
  `WAYBACK_CDX_URL`, `COMMONCRAWL_COLLINFO`, `ENABLE_COMMONCRAWL`, `HISTORICAL_TIMEOUT`,
  `HISTORICAL_RETRIES`, `MAX_HISTORICAL_URLS`.
- **Multi-target orchestration (deep-ASM slice 2).** New `backend/orchestrator.py` closes the loop
  from discovery to findings: a single domain → passive subdomain enumeration → liveness probe of
  each host → the existing passive secret+posture scan per live host → one aggregated
  `DeepScanResult`. Includes a per-host **SSRF guard** (a discovered host that resolves to a
  private/internal address is skipped unless `ALLOW_PRIVATE_TARGETS=true`), a `MAX_TARGETS` cap,
  concurrent probing, and per-host error isolation (one host failing never sinks the run). New
  combined client report `report.generate_deep_scan_html()` (subdomain surface + live hosts +
  per-host confirmed/needs-review/posture). CLI: `python cli.py <domain> --deep-scan -o report.html`.
  Config: `MAX_TARGETS`, `PROBE_CONCURRENCY`, `PROBE_TIMEOUT`.
- **Passive subdomain enumeration (deep-ASM slice 1).** New `backend/recon.py` expands a domain
  into its known subdomain surface from **Certificate Transparency** — fully passive, it never
  contacts the target, so it runs before a client engagement is signed. Queries **two independent CT
  sources (crt.sh + Certspotter)** with backoff retries and merges them, so a single flaky/rate-
  limited source (crt.sh 502s often) no longer zeroes out a good result; the result lists which
  sources succeeded and only reports an error if *all* fail. `extract_registrable_domain()`
  normalises URL/host/IP inputs (two-label public-suffix table incl. `.bd`). Exposed via the CLI:
  `python cli.py <domain> --subdomains`. First layer of the passive attack-surface pipeline
  (subdomains → historical paths → associated assets → existing secret/posture scan).

### Fixed
- **False-negative: structural keys wrongly entropy-gated.** The Shannon-entropy floor
  (`MIN_ENTROPY_THRESHOLD=3.5`) was applied uniformly to every detector, silently dropping
  genuinely low-entropy but well-formed provider keys (e.g. an AWS key ID at ~3.27 bits) before
  they ever reached AI validation — the worst failure mode for a scanner. Entropy is now
  class-aware: the *generic* keyword=value catch-all keeps the full 3.5 bar, while
  *structural/provider* detectors (AKIA…, ghp_…, sk_live_…, PEM, fixed-format tokens) only clear a
  low anti-degenerate floor (`MIN_STRUCTURAL_ENTROPY=2.5`) that still rejects obvious junk like
  `AKIAAAAAAAAAAAAAAAAA`. Precision/recall stays 1.000/1.000.
- **False-negative: AI-dismissed structural matches silently dropped.** A finding was routed to
  manual review only when AI validation was *unavailable*; a structural/provider match the AI
  *actively* rejected with a real confidence matched no bucket and was discarded — so a live key the
  AI merely under-called on (e.g. lacking page context) vanished with no trace. New
  `classify_validated()` sends any structural match the AI does **not confidently dismiss** to
  manual review instead of dropping it; the generic catch-all keeps aggressive filtering, so the
  "no false positives in Confirmed" promise holds. Suite **187 → 197**.

## [2.6.0] — Detection quality, safety & attack-surface breadth

A measured capability pass grounded in a fresh audit vs 2026 secret-scanning SOTA
(TruffleHog/Gitleaks) — nine independent, test-backed slices. Test suite **145 → 187**,
all green; ruff clean; the scanner stays passive and verification stays off-by-default.
See `docs/TECHNICAL-AUDIT-AND-ROADMAP.md`.

### Added
- **Verified-credential identity/scope (R1).** A live credential now reports *who it belongs to and
  what it reaches* — GitHub `@acct` + token scopes, Stripe account + LIVE/charges, Slack workspace/
  user, OpenAI org, npm/GitLab/Telegram handle, SendGrid send-scope, Mailgun domain count — surfaced
  in HTML/CSV/SARIF as the concrete blast radius. Never includes the secret value itself.
- **FP/FN benchmark harness (R2).** `backend/bench/` labelled corpus + `make bench` precision/recall
  report + a pytest CI gate. Current: **precision 1.000 · recall 1.000 · F1 1.000 · 0 false positives.**
- **Live-verification coverage 9 → 17 providers (R6).** Added Cloudflare, DigitalOcean, Datadog,
  Notion, Linear, Figma, Postman, Doppler — read-only, fail-closed.
- **Source-map original-source scanning (R5).** Decodes a `.map`'s `sourcesContent` and scans it as
  real code with per-file attribution — catches secrets escaped in the raw JSON or stripped from prod.
- **Passive attack-surface / security-posture checks (R8).** `posture.py` flags missing/weak security
  headers (HSTS, CSP, clickjacking, X-Content-Type-Options, Referrer/Permissions-Policy), software
  version disclosure, and insecure cookies — so even a clean *credential* scan returns actionable ASM
  findings, in a dedicated report section + KPI tile.
- **Executive-summary report (R9).** A verification-evidence callout (each verified-active key + its
  identity), a "Verified Active" KPI tile, and an honest measured-precision statement.
- **SARIF full detector catalog (R4).** The driver advertises every detector as a rule (help text,
  CWE, severity) even on a clean scan.

### Security / hardening
- **Regex ReDoS-proofing (R3).** A per-pattern match cap plus an automated backtracking gate
  (empirical fuzz over all 54 detectors × adversarial inputs + a static nested-quantifier guard).

### Notes
- New env toggles: `SCAN_SOURCEMAP_CONTENT`, `MAX_SOURCEMAP_SOURCES`, `SCAN_HTTP_POSTURE`,
  `MAX_MATCHES_PER_PATTERN`.
- Backward compatible: `verify_finding()` keeps its string-only API; new `verify_finding_detailed()`
  returns identity detail.

## [2.5.4] — Impact-aware validation: sell impact, not known-public information

From a real scan: a Firebase Web `apiKey` shipped in client JS was reported as a
HIGH "compromised Google Cloud API Key — rotate immediately". But Firebase web keys
are **public by design** (identifiers, not secrets) — a finding a client would dismiss
as known information. The same key, matched by a different detector, was even correctly
called *"not a sensitive secret"*. Clients pay for **impact**, so validation is now
impact-aware.

### Added
- **Public-by-design classification.** The validator's Gemini schema now returns
  `public_by_design` and `impact`. The system prompt teaches the model to separate
  identifiers meant to ship in client code (Firebase web `apiKey`, browser/Maps keys,
  Stripe/PayPal **publishable** `pk_` keys, Sentry DSNs, PostHog/Segment write keys,
  Algolia search-only keys, Mapbox `pk.` tokens) from genuinely exploitable secrets
  (private keys, service-account JSON, `sk_`/AWS secret keys, DB URIs, session tokens).
  A public-by-design value is **not** reported as an exposure and is downgraded to
  **INFO** severity regardless of the pattern's registry severity — killing the
  embarrassing Firebase-key false positive.
- **Impact / blast-radius on every finding.** Each confirmed finding now carries a one-line
  *what an attacker could actually do* statement, surfaced as a dedicated **Impact / Blast
  Radius** column in the HTML report, an `impact` column in CSV, an `impact` property + inline
  `Impact:` text in SARIF, and an **IMPACT / BLAST RADIUS** block in the dashboard's finding
  detail. The deliverable now leads with impact instead of "CWE-798, rotate it".

### Tests
- New `backend/tests/test_v254.py` (7 tests): schema carries the new fields (and old-style
  construction still works), public-by-design → INFO, a real secret keeps its severity and
  carries impact, and impact appears in HTML/CSV/SARIF. Suite **138 → 145**.

## [2.5.3] — AI config-error handling + toast-flood fix

From a real scan run with an **invalid `GEMINI_API_KEY`**: every finding returned
`400 INVALID_ARGUMENT: API key not valid`, the engine retried each one 3×/tier, and
all 13 findings were dumped into needs-review — producing a screen-covering flood of
identical alerts.

### Fixed
- **Permanent AI config errors now fail fast and are surfaced once.** A `400/401/403/404`
  (invalid or blocked key, or a model the key can't call) is no longer retried; the first
  occurrence latches AI off for the rest of the scan, so later findings make **zero**
  further API calls (was ~6× the necessary calls). Affected findings are returned
  *skipped/unvalidated* (confidence 50) with a single actionable reason — e.g. *"GEMINI_API_KEY
  was rejected by Google (invalid key) — set a valid key from https://aistudio.google.com/apikey"*
  or a model-availability hint for a 404 — instead of a needs-review flood. Transient
  errors (429/5xx) are unchanged: they still retry and degrade to needs-review, preserving
  the never-drop-a-finding guarantee.
- **Toast notifications no longer cover the screen.** Identical messages are de-duplicated
  into a single toast with a `×N` counter, and at most 5 are shown at once (oldest evicted).

### Tests
- New `backend/tests/test_v253.py` (5 tests): invalid-key fail-fast (1 call, not 3),
  skipped-not-needs-review with actionable guidance, the scan-wide short-circuit (0 further
  calls), the 404 model-guidance path, and that a transient 429 still degrades to
  needs-review. Toast cap/dedupe verified in-browser + by logic test. Suite **133 → 138**.

## [2.5.2] — Reports: fix clean-scan export + higher-quality client deliverable

Driven by a dashboard error on a real clean scan — `Report export failed: Scan is
not complete yet (status: clean)`.

### Fixed
- **A clean (zero-finding) scan can now be exported.** A no-findings scan finishes
  with status `clean`, but the report endpoint only accepted `complete`, so it
  returned HTTP 409 and no report could be produced. It now accepts both terminal
  states (`complete` and `clean`) and only rejects genuinely unfinished scans.
- **Client reports no longer stamp a stale version.** `report.py` hard-coded
  `v2.3.0`; the version is now read from `pyproject.toml`, so reports always carry
  the running version.

### Added
- **Executive-summary verdict banner** on the HTML report — a colour-coded risk pill
  (CRITICAL/HIGH/MEDIUM/LOW/REVIEW REQUIRED/CLEAN) with a plain-language verdict. A
  clean scan now reads *"No exposed credentials detected — N assets analysed, M
  candidates screened"* (the zero-finding assurance statement), instead of empty tables.
- **Scope & Methodology section** — states the passive, authorized-only method and the
  coverage (assets analysed, candidates screened, duration), so the deliverable stands
  on its own for a client. Metadata now includes scan-start time and candidates screened.

### Tests
- New `backend/tests/test_v252.py` (6 tests): clean-scan assurance report, findings
  verdict/risk, non-stale version, clean-scan CSV/SARIF, and the report endpoint gate
  (clean → 200, unfinished → 409). Suite **127 → 133**.

## [2.5.1] — Deploy resilience: optional uvloop, self-diagnosing setup, no flaky tests

Hardening driven by a real Raspberry Pi 5 deploy (Python 3.13) where a flaky
piwheels install and a hard `import uvloop` combined to produce a **blank dashboard**.

### Fixed
- **`uvloop` is now optional, not fatal.** `backend/main.py` imported `uvloop`
  unconditionally at module load; if the C-extension was missing or broken (common on
  ARM64 / partial installs), the whole server crashed on startup and the dashboard
  rendered blank. It now falls back to the stdlib asyncio loop with a warning. The
  `uvicorn` launch flags (`setup.sh`, `Dockerfile`) use `--loop auto`, which prefers
  uvloop when present and degrades gracefully otherwise.
- **Flaky test removed.** `test_finds_aws_key` generated a *random* key each run and
  failed ~4% of the time when the draw fell below the entropy gate — it now regenerates
  until it clears the threshold, so it is deterministic (still no literal secret in source).

### Changed
- **Setup is self-diagnosing.** `setup.sh` now (a) verifies the app by importing the real
  `main` module (catches a single half-installed dependency, not just five hand-picked
  ones), and (b) after starting the service, **probes `/api/health`** — so an
  "active but not serving" server is reported immediately with a `journalctl` hint,
  instead of surfacing as a blank browser tab.

### Tests
- New `backend/tests/test_v251.py` — proves the app imports and serves with `uvloop`
  absent, and that `/` and `/api/health` return content with no external CDN references.
  Suite **124 → 127**.

## [2.5.0] — AI engine upgrade: `google-genai` SDK + two-tier Gemini 3.x validation

The `google-generativeai` SDK was **deprecated by Google (Nov 2025)** and the
hard-coded `gemini-1.5-flash` model is legacy. This release migrates the contextual
validator to the official **`google-genai`** SDK and a modern two-tier engine, with
strict structured output and cost-aware model routing — without weakening the
"never silently drop a finding" guarantee that has anchored SecretNode since v2.0.

### Changed
- **New SDK — `google-genai` 2.11.0** replaces the deprecated `google-generativeai`.
  Client is a lazily-built singleton (`genai.Client()` reading `GEMINI_API_KEY`), so
  the module still imports with no key present and a bad key degrades to needs-review
  instead of crashing at startup.
- **Two-tier validation engine** (`validate_with_gemini`):
  - **Tier 1 — pre-filter:** `gemini-3.1-flash-lite` with `thinking_level='minimal'`
    cheaply strips structural noise, mocks and placeholder keys.
  - **Tier 2 — deep validation:** `gemini-3.5-flash` with `thinking_level='high'`
    confirms anything the pre-filter flags as real, or that carries an escalate-severity
    (default `CRITICAL`) — the cheap model is never the last word on a critical secret.
  - Models, thinking levels and the escalate-severity set are all env-overridable
    (`GEMINI_TIER1_MODEL`, `GEMINI_TIER2_MODEL`, `GEMINI_TIER1_THINKING`,
    `GEMINI_TIER2_THINKING`, `GEMINI_ESCALATE_SEVERITIES`). A legacy single
    `GEMINI_MODEL` is honoured as the Tier-1 model for back-compat.
- **Strict structured output** — a Pydantic v2 `GeminiVerdict` (`{is_valid: bool,
  confidence: int(0-100), reason: str}`) is bound to the SDK's native `response_schema`
  with `response_mime_type='application/json'`. This **removes the old regex JSON-scrape
  + `json.loads` fallback**; fields map straight into the SQLite layer with no coercion.
- **Implicit context caching** — the identical system-instruction prefix on every call
  lets Gemini's automatic (free) implicit caching discount shared tokens on repeat
  scans. Explicit `caches.create` was intentionally **not** used: this per-finding
  workload has no large shared prefix and would not clear the minimum-token floor.

### Fixed
- **Graceful degradation preserved and broadened** — a 429 / token-exhaustion / transport
  error on either tier retries with backoff and then falls back (deep→pre-filter verdict,
  or → `needs_review` with the `NEEDS_REVIEW_SENTINEL`), so findings are surfaced to a
  human, never dropped.
- **Dependency conflicts resolved** — `google-genai` requires `httpx>=0.28.1` and
  `pydantic>=2.12.5`; both pins were bumped (`httpx` 0.27.2→0.28.1, `pydantic`
  2.10.3→2.12.5). `websockets==14.1` already satisfied its range. No httpx-0.28
  breaking APIs are used by the backend.

### Frontend / UI-UX (multi-device, offline, fewer moving parts)
- **Fully responsive dashboard** — the fixed desktop-only layout (a 5-column stat grid,
  a single-row 6-control scan bar, a 2-column panel grid) is now intrinsically responsive
  via `auto-fit`/`minmax` grids and `flex-wrap`, with small-screen refinements. Verified at
  375 / 768 / 1440 px with **zero horizontal overflow** — fixing the clipped buttons and
  cut-off table seen on the Pi's phone view. Desktop layout is unchanged.
- **Removed all external CDNs** — the **Tailwind Play CDN** (a production anti-pattern that
  compiled in-browser and needed internet) and **Google Fonts** are gone. The handful of
  Tailwind utilities actually used were replaced with plain CSS, and the animation keyframes
  the runtime used to inject are now local. The dashboard renders **fully offline** — no
  more flash-of-unstyled-content or blocked requests on a flaky/air-gapped Pi.
- **Self-hosted fonts** — Share Tech Mono, Orbitron and Exo 2 (latin subset, ~100 KB total,
  woff2) are served from `/static/fonts` with `preload` + `font-display:swap`.
- **A11y/polish** — `prefers-reduced-motion` support, `color-scheme`/description meta, a
  softer initial WS state, and touch-friendly wrapping controls. Version strings bumped to
  v2.5.0 throughout the UI.

### Tests
- New `backend/tests/test_v250.py` — 13 tests covering the `GeminiVerdict` schema,
  Tier-1→Tier-2 escalation (noise rejection, positive escalation, critical-always-escalates),
  structured-output parsing + text-JSON fallback, and graceful degradation (429 →
  needs_review, deep-tier failure → pre-filter fallback, never-None). Suite **111 → 124**,
  fully offline via a fake client. Ruff clean.

## [2.4.0] — Field-hardening: WAF-resilient fetching, deeper coverage, current-gen detectors

Driven by real dashboard runs on a Raspberry Pi 5 against live targets, where three
gaps surfaced: WAF-fronted sites returned an instant **HTTP 403** so the scan could not
even fetch the root; coverage was **thin** (only linked `.js` files were mined); and the
UI's post-scan WebSocket close looked like an error.

### Added
- **Source-map mining** — declared `//# sourceMappingURL=` maps (`.js.map`) are now fetched
  and scanned. Source maps carry the **un-minified original source** — comments, endpoints
  and hard-coded secrets stripped from the shipped bundle — a well-established ASM technique
  that meaningfully deepens coverage. (`FOLLOW_SOURCE_MAPS`, `MAX_SOURCE_MAPS`.)
- **Broader asset discovery** — `<script type="module">`, `<link rel="modulepreload">` and
  `<link rel="preload" as="script">` are now discovered in addition to classic `<script src>`.
- **10 current-generation detectors** — Supabase (access token + `sb_secret_`), Sentry DSN,
  Linear, Notion (`ntn_`/`secret_`), Doppler, PostHog, Figma, Cloudflare (2026 `cfat_`/`cfut_`/`cfk_`),
  and Google Cloud **service-account JSON** keys (`private_key_id`). Registry now **54 patterns**.
- **Live-verification toggle in the dashboard** — the existing opt-in `verify` path now has a
  `VERIFY` checkbox in the UI (previously only reachable via the API/CLI).
- **Content-type gate** — binary assets (images, fonts, video) are skipped early, saving
  bandwidth and CPU on the Pi.

### Changed
- **Browser-like HTTP client (the headline fix)** — replaced the `SecretNode-bot` User-Agent
  with a current Chrome fingerprint (UA + Client-Hints + `Sec-Fetch-*` + HTTP/2). On a WAF/CDN
  challenge (401/403/406/429/503) the fetcher now **retries with a rotated fingerprint** and
  emits a diagnostic that names the likely cause, instead of giving up on the first 403. This
  is resilience for **authorized** testing — scope, SSRF guard, passive-only behaviour and the
  authorization gate are unchanged. Override with `SECRETNODE_USER_AGENT`.
- **Dashboard WebSocket UX** — a clean post-scan close now shows `WS: IDLE` (not a red
  `DISCONNECTED`); only an unexpected mid-scan drop warns and auto-reconnects once.
- **Discovered-assets panel** now reflects every collected asset (JS + source maps), not just
  the linked `.js` list — so the panel is no longer empty for single-bundle targets.
- Test suite grown **82 → 111** (WAF-retry, source-maps, module/preload discovery, content-type
  gate, browser client, 10 new detectors). Ruff clean.
- New optional dependencies: `h2` (HTTP/2) and `brotli` (br decompression); both degrade
  gracefully if absent.

## [2.3.0] — ASM-industry alignment: verification-first & CI-native

Informed by 2025–2026 ASM / secret-scanning practice, where **verification-first**
detection (confirming a credential is actually *live*) and **CI-native gating** are the
dominant themes.

### Added
- **Optional live verification** (`verifier.py`, `VERIFY_SECRETS` / `?verify=true`) — the
  "is this credential still active?" step (à la TruffleHog `--only-verified`). Read-only
  identity checks against each secret's own provider (GitHub, GitLab, Stripe, SendGrid,
  OpenAI, Slack, npm, Mailgun, Telegram). **Off by default**, fails closed, never touches
  the scan target. Findings gain a `verified` status (verified / unverified / unsupported).
- **`only_verified` mode** — drop confirmed-inactive (dead) findings to kill false-positive
  fatigue, while keeping types that can't be auto-verified.
- **Base64 decoding pass** — secrets hidden inside base64-encoded blobs are now decoded and
  detected.
- **Example / placeholder allowlist** — documentation example keys (e.g. AWS's
  `AKIAIOSFODNN7EXAMPLE`) and obvious placeholders are filtered out to reduce noise.
- **CLI (`backend/cli.py`) + composite GitHub Action (`action.yml`)** — run a scan and emit
  SARIF/JSON/CSV/HTML from CI, with `--fail-on-findings` as a build gate.
- **7 more detectors** (Slack app-level, GitHub server/refresh, OpenAI service-account, New
  Relic, Grafana, HCP Terraform) — registry now **44 patterns**.
- **Verification surfaced everywhere** — HTML badge, CSV column, and SARIF `verified`
  property (verified findings get a `[VERIFIED ACTIVE]` message prefix).

### Changed
- Test suite grown **58 → 82** (verification, decoding, allowlist, CLI, SARIF). Ruff clean.

## [2.2.0] — Capability & industrial-grade release

### Added
- **Expanded detection registry** — grew from 16 to 37 secret patterns, adding modern
  providers: OpenAI, Anthropic, GitLab, GitHub fine-grained PATs, Slack tokens, npm,
  PyPI, DigitalOcean, HashiCorp Vault, Google OAuth client secrets, Square, Postman,
  Databricks, Telegram, Discord, Datadog, Azure Storage keys, Firebase Cloud Messaging,
  bearer tokens, PGP private keys, and **database connection URIs / basic-auth URLs with
  embedded credentials**.
- **Audit metadata on every finding** — each pattern now carries a `severity`, a **CWE**
  id, and a **remediation** string, propagated into every finding, report, and export.
- **SARIF 2.1.0 export** (`GET /api/scans/{id}/report?format=sarif`) — upload findings to
  GitHub code scanning or any SARIF-aware CI/security pipeline. Confirmed findings map to
  `error`/`warning` by severity; needs-review findings are `note` level.
- **Severity-aware reports** — HTML and CSV reports now show severity + CWE, sort
  critical-first, and include a per-type **Remediation Guidance** section.
- **Environment-tunable engine** — `CONCURRENCY_LIMIT`, `MIN_ENTROPY_THRESHOLD`,
  `FETCH_TIMEOUT`, `MAX_ASSET_BYTES`, `GEMINI_CONFIDENCE_MIN`, `MAX_RAW_FINDINGS_PER_SCAN`
  and more are now read from environment variables (previously hard-coded, contrary to
  the docs).
- **Industrial-grade scaffolding** — MIT `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`,
  `pyproject.toml` (ruff + pytest config), GitHub Actions **CI** (lint + tests on Python
  3.11/3.12 + Docker build), `Dockerfile` + `docker-compose.yml`, `.gitignore`,
  `.dockerignore`.
- **25 new tests** (patterns, metadata propagation, env parsing, HTML/CSV/SARIF report
  generation, XSS-escaping, severity ordering) — suite grew from 33 to 58.

### Fixed
- Removed an unused import flagged by the new lint gate.
- Added pytest configuration (`asyncio_mode = auto`) so the async test suite runs
  reliably across pytest-asyncio versions.

## [2.1.0] — New features
- Scan diffing (NEW vs RECURRING), false-positive suppression, client-ready report
  export (HTML/CSV/JSON), multi-page same-domain crawling, robots.txt awareness.

## [2.0.2] — Industrial-grade reliability pass
- Never-drop needs-review findings, concurrent-scan cap, raw-findings safety cap, audit
  logging, input validation, richer health check, initial pytest suite.

## [2.0.1] — Security hardening pass
- Fixed path traversal, added API-key auth, redacted secrets in Discord, fixed dashboard
  XSS, replaced wildcard CORS with an allowlist, added an SSRF guard and scope
  restriction, added SQLite persistence.
