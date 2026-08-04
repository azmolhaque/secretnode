# Changelog

All notable changes to SecretNode are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [2.8.1] — The mask told the truth about short secrets and lied about long ones

Found while re-reading the redaction work from v2.8.0. The masking itself was right; what
reached it was not.

### Fixed

- **Every credential longer than 80 characters masked as `(81 chars)`, with a tail made of
  padding.** `to_dict()` capped `raw_match` with `value[:80] + "…"`, and the mask applied
  downstream then reported `len()` and `value[-4:]` of that capped string. So a 112-character
  token surfaced everywhere as `ghp_AA…******…AAA…  (81 chars)` — a fabricated length, and a
  "tail" consisting of padding and the ellipsis itself.

  Both halves of the mask exist to identify a credential without exposing it, and both were
  useless for exactly the secrets where identification matters most: GCP service-account keys,
  JWTs, PGP blocks, database URIs with long passwords. Two different 100-character tokens found
  on the same host rendered as the same string, so a triager could not tell them apart, and an
  engineer told to rotate "the 81-character key" had nothing to search for.

  The cap now keeps the head *and* the real tail inside the same 80-character budget, and the
  credential's true length travels beside it as `raw_length`. `mask_secret()` and
  `redact_secret()` take that length; `redact_finding()` is the helper report surfaces should
  call so the dashboard, CSV, SARIF, HTML and JSON cannot disagree about how big a key is.

### Tests

- Six cases, including a mutation check that reverting the cap fails them. One v2.8.0 test was
  asserting the cap's trailing ellipsis rather than the invariant underneath it — it now checks
  that the full credential is absent and the value is bounded, which is what it always meant.
  Suite: 382 → 388.

### Known limitation, unchanged

`REPORT_FULL_SECRETS` still cannot reveal a credential longer than the cap, because the full
value is deliberately never persisted. For most secrets the opt-in behaves as documented; for a
long key it returns the capped value. Lifting that means storing credentials verbatim, which is
the thing v2.8.0 set out to stop — so it is recorded here as a trade-off rather than quietly
fixed.

## [2.8.0] — Artifact review: the credential stops at the API boundary

Driven by a side-by-side read of the artifacts from a real v2.7.9 deep scan — the dashboard modal,
the Discord alert, and the SARIF/CSV/HTML exports of the same three findings. v2.7.9 had fixed
redaction in the *reports*; comparing the surfaces showed how much of the same job was left undone
everywhere else, and turned up two correctness bugs that had nothing to do with display.

### Fixed

- **A re-scan of an unchanged site reported CLEAN while the credential was still exposed.** The
  worst bug in this release, and the only one that produces a wrong *answer* rather than a wrong
  *presentation*. The asset cache treated a `304 Not Modified` on the root page as "unchanged and
  previously clean, skip" — but an HTML page is a link graph, not just something to grep. Skipping
  its body meant never parsing its `<script>` tags, so every JS bundle it referenced dropped out of
  the scan. Reproduced on a lab target: scan 1 found a planted key, scan 2 never requested the file
  holding it and reported no findings. Crawled pages now always come back with a body
  (`allow_cache_skip=False`) — the conditional GET is still sent, so the bandwidth saving on
  unchanged terminal assets (JS bundles, source maps) is untouched.
- **The dashboard rendered the full credential.** `redact_secret()` was added to `report.py` in
  v2.7.9 and nowhere else, so `/api/scans/{id}` and the WebSocket stream shipped `raw_match`
  verbatim and the finding-detail modal displayed it — under a heading reading "MATCHED VALUE
  (PARTIAL)" that a 51-character key comfortably fit inside. Redaction now happens at the API
  boundary (`public_scan` / `public_event` in `main.py`) using a `mask_secret()` that has no
  opt-out; `REPORT_FULL_SECRETS` remains available for a report an operator deliberately generates,
  but no longer unmasks every dashboard session and WebSocket subscriber.
- **The `scan_complete` event carried both unmasked finding lists.** Found by capturing a live
  WebSocket stream rather than by reading the code: per-finding events were being scrubbed, but the
  final frame of every scan ships the entire result dict, and it was going out untouched.
- **The code snippet leaked the secret the matched-value field was hiding.** `context_snippet` was
  stored and served verbatim, so the modal and the JSON export both contained the credential in
  full even once `raw_match` was masked. Now masked in `ValidatedFinding.to_dict()`, where the
  complete value is still available to match against — masking it downstream from the 80-character
  `raw_match` cap would have left the tail of a longer secret exposed.
- **The JSON export was the one deliverable format still containing live keys.** HTML, CSV and
  SARIF all redacted; `format=json` returned the stored record as-is.
- **The dashboard showed MEDIUM for findings the reports called HIGH.** The frontend re-derived
  severity from a hardcoded list of 14 secret type names. Every detector added since that list was
  written — the entire AI/ML provider family — fell through to the MEDIUM default. It now reads the
  `severity` field the backend already computes from the pattern registry. A missing `.badge-low`
  style meant LOW findings rendered unstyled; added.
- **Discord alerts announced "SecretNode v2.4.0"** for five releases, and coloured every embed with
  a per-type table covering 16 of 60+ detectors — so an ElevenLabs key and an AWS root key arrived
  looking identical. Version now comes from the shared `version.py`; embed colour is keyed on
  effective severity, and the severity is stated as a field.
- **Deep-scan reports lost every scan-level metric.** `DeepScanResult.to_dict()` never emitted
  `assets_fetched`, so a SARIF from a 25-host run claimed `assets_fetched: 0`; the same omission
  dropped `raw_findings`, `duration_seconds`, posture findings and the verification counts. All are
  now rolled up, with duration measured as wall-clock rather than summed across concurrently
  scanned hosts.
- **A fully-cached re-scan reported "0 assets analysed".** True as a download count, wrong as
  coverage — it reads as "nothing was scanned". Split into `assets_fetched` (downloaded),
  `assets_cached` (unchanged and clean, skipped) and `assets_scanned` (coverage); reports lead with
  coverage and name the cached portion.
- **Deep scans inherited asset-cache state from whatever ran before them in the same process.** The
  cache is module-level and only the single-target endpoint primes it, so a deep scan could report
  a previous scan's cache hits as its own coverage — and, worse, act on a stale validator. Deep
  scans now start from an empty cache, and `run_scan` resets the hit tally alongside the throttle.

### Changed

- Deep-scan HTML gains the redacted matched value, verification status and impact per finding, plus
  an asset-coverage stat — the format a client actually reads was the one carrying the least
  evidence. It also notes that one value appearing on several hosts is a single credential shared
  across environments, which is what a fanned-out dev/QA/preprod exposure actually looks like.
- SARIF results carry `matched_value_partial`, `found_at` and (on deep scans) the originating
  `host`, so a triager can correlate a result against the CSV row and the Discord alert. Run
  properties gained coverage and duration.
- Version is single-sourced in `backend/version.py`; a test now fails the build on any hardcoded
  `SecretNode vX.Y.Z` literal in the backend.

### Tests

- `test_v280.py`: 35 tests covering each fix, including a mutation check that the leak guards can
  actually fail, and a reproduction of the false all-clear. Suite: 347 → 382.


## [2.7.9] — Deep QA before release: reports no longer leak the credential

A full pre-PR QA pass: booted the application, ran real end-to-end scans against a local target
with planted secrets, exercised every export format, the CLI, and a re-scan to prove the cache. It
surfaced one serious defect and one cosmetic one.

### Fixed
- **Client reports contained the full, live credential.** The CSV column was named
  `matched_value_partial` but wrote `raw_match` verbatim, and the HTML report did the same. A report
  is emailed, forwarded and archived — writing a working secret into one turns the deliverable
  itself into a second exposure, and directly contradicts the Rules of Engagement we ask clients to
  sign ("only the minimum evidence needed to prove a finding, with sensitive data redacted").
  Values are now redacted to `sk_798…******…3fc4  (51 chars)`: still greppable, so a developer can
  identify exactly which key to rotate, but not usable. `REPORT_FULL_SECRETS=true` opts back in for
  the case where an operator deliberately needs the full value. SARIF was already clean.
- **Version drift in the dashboard.** The footer and boot log were hardcoded to v2.7.1 and never
  touched by the runtime `/api/health` sync, so a client demo showed a stale version indefinitely.
  The footer is now synced too and the boot log no longer hardcodes a version. `report.py`'s
  fallback constant was also stale.

### Verified end to end (not just unit-tested)
- Application boots; `/api/health` reports the correct version; dashboard serves.
- Real scan of a local target found **both** of this session's headline features working in a live
  system: the v2.7.2 **ElevenLabs detector**, and a v2.7.6 recovery of an Anthropic key that was
  `\uXXXX`-escaped inside `__NEXT_DATA__` (with a raw `<` in the blob, exercising the v2.7.8 fix).
- **Re-scan** repopulated findings rather than losing them, and `asset_cache` correctly recorded
  both assets as `was_clean=False` so they will always be refetched.
- HTML / CSV / SARIF all generate and stamp the right version; SARIF carries all 63 rules.
- CLI produces correct CSV output.
- **SSRF guard confirmed working** — refused a localhost target until `ALLOW_PRIVATE_TARGETS` was
  explicitly set for the lab run.
- Inline dashboard JavaScript passes `node --check` after the mobile-layout edits.

Suite **349 → 353**, all green; ruff clean; bench 1.000/1.000.

## [2.7.8] — Pre-release review: three real bugs, and a quality gate that can fail

A deliberate self-review of everything shipped in v2.7.2–v2.7.7 before opening the PR. It found
three genuine defects — two of them in the very code written to prevent that class of failure —
and one process gap that mattered more than any of them.

### Fixed
- **Inline-JSON extraction truncated at the first raw `<`.** `_INLINE_SCRIPT_RE` used a `[^<]`
  character class, so any blob containing a literal `<` — prose like `"a < b"`, embedded HTML
  fragments, templates — was cut short and failed to parse, losing every secret after that point.
  Now lazily matched to the `</script>` terminator (linear-time, still ReDoS-free: verified at
  0.18s on hostile input).
- **A previously-dirty asset could be lost on 304 when `RETRY_ATTEMPTS=1`.** The refetch was done
  via `continue`, which consumed a retry attempt; with only one attempt configured the request was
  never re-issued and the asset was dropped — **the exact "a finding silently vanishes" failure
  the cache was designed to prevent.** The unconditional refetch now happens inline.
- **An unprompted `304` with no cache entry burned a retry.** Now refetched immediately, and a
  server that answers 304 even unconditionally terminates instead of spinning.

### Added — the detection quality gate is now real
- **The benchmark corpus covers this session's work.** 27 → **45 samples**. All nine v2.7.2 AI/ML
  detectors, the v2.7.6 inline-SSR path, and **eight hard negatives** chosen to be structurally
  confusable with the new patterns: `sk_` + wrong-length hex, a 64-hex SHA digest that resembles an
  OpenRouter key, provider-shaped placeholders, benign inline JSON. Shipping nine detectors with
  zero corpus coverage meant the "measured precision" claim did not cover them.
- **`make bench` can fail.** It previously printed a report and always exited 0, so it could not
  block anything. It now enforces `BENCH_MIN_PRECISION` / `BENCH_MIN_RECALL` (default 1.0), prints
  the offending samples, and exits non-zero.
- **CI runs it.** A precision regression is now release-blocking. Verified end to end by
  deliberately loosening the ElevenLabs regex: precision falls 1.000 → 0.917, the two false
  positives are named, and the build fails.

Suite **337 → 349**, all green; ruff clean; bench 1.000/1.000 on the larger corpus.

## [2.7.7] — R10: asset caching for re-scans

Closes roadmap item **R10**. Re-scanning a target refetched every asset from scratch — wasted
bandwidth on the client's servers and wasted CPU on ours, since most assets neither change between
engagements nor contain anything.

### Added
- **Conditional GET on re-scans.** SecretNode now sends `If-None-Match` / `If-Modified-Since` from
  a per-target cache of HTTP validators (`asset_cache` table, 24h TTL).
- **Correctness rule for 304s.** A `304 Not Modified` is acted on by history, not blindly:
  - asset was **clean** last scan → **skipped entirely** (unchanged + previously clean means still
    clean), and never enters the scan text;
  - asset previously **yielded a finding** → **refetched unconditionally**, so the finding is
    reproduced. A finding that disappeared from a report would read as *resolved*, which is a
    dangerous lie to tell a client.
- `purge_asset_cache()` for clearing one target's cache or all of it.
- Config: `ASSET_CACHE` (default on).

### Privacy: no response bodies are cached
The obvious implementation stores bodies so a 304 can still be scanned. We deliberately do not: a
client's JavaScript can contain live credentials, and caching it would leave a long-lived copy of
their secrets on our disk — which the engagement's confidentiality terms do not allow. The cache
holds **only** the validators, a truncated content hash, and a clean/dirty flag. That is enough to
skip the overwhelming majority of assets, and a test asserts no body content is ever persisted.

+10 tests, including a **mutation check** (with `ASSET_CACHE=false`, five cache tests fail, proving
they exercise the real path) and a real-SQLite round-trip covering upsert, per-target isolation and
purge. Suite **327 → 337**, all green; ruff clean.

## [2.7.6] — Inline SSR state decoding

Server-rendered apps embed their bootstrap state in the HTML — Next.js writes
`<script id="__NEXT_DATA__">`, Nuxt writes `window.__NUXT__`, Redux-style apps write
`window.__INITIAL_STATE__` — and that blob is built server-side, so it regularly carries config a
developer never meant to ship.

### Added
- **Inline JSON/SSR state blobs are decoded before scanning.** New `extract_inline_json_strings()`
  finds inline `<script>` JSON (typed `application/json`, or assigned to `__NEXT_DATA__`,
  `__NUXT__`, `__INITIAL_STATE__`, `__APOLLO_STATE__`, `__PRELOADED_STATE__`, `__remixContext`),
  parses it, and scans the decoded string values.
- Config: `SCAN_INLINE_JSON`, `MAX_INLINE_JSON_BYTES`.

### Why this is narrower than the roadmap claimed
The roadmap listed inline JSON *and* HTML comments as uncovered surface. Measured against the
code, both are already caught — the whole response body goes through the raw-text pass, so a
plainly-embedded secret in a comment or a JSON blob has always been found. The **only** genuine
miss was a value whose JSON **escaping** breaks the credential's shape: a `\uXXXX`-escaped
character mid-token, as emitted by XSS-safe serializers (Next.js's `htmlEscapeJsonString`) or
light obfuscation. The regex sees `sk\u002Dant\u002D…` and no longer recognises it. Decoding the
JSON recovers it — the same rationale that already justifies decoding source-map
`sourcesContent`. The roadmap entry has been corrected rather than left overstating the gap.

Purely local decoding: **no additional requests**, so the scan stays passive. Bounded by a shared
byte budget, non-greedy bounded regexes (no nested quantifiers), and defensive throughout — a
malformed blob is skipped, never fatal.

+14 tests, including a **mutation check**: with `SCAN_INLINE_JSON=false` the recovery tests fail,
proving they exercise the decoder rather than passing incidentally via the raw-text pass.
Suite **313 → 327**, all green; ruff clean.

## [2.7.5] — Scan politeness & resilience

Being a good guest on a client's infrastructure is part of the engagement, not an afterthought:
an authorized scan that trips rate limiting looks like an attack to their SOC and gets the scanner
blocked mid-assessment. This release makes SecretNode back off the way a well-behaved client
should — and fixes a bug that was silently losing assets.

### Fixed
- **`Retry-After` as an HTTP-date no longer loses the asset.** RFC 7231 allows `Retry-After` to be
  either delta-seconds *or* an HTTP-date. The header was parsed with a bare `float()`, so a
  spec-compliant date raised `ValueError`, fell through to the generic exception handler, and made
  the scanner abandon the asset outright — a **false negative caused by the server behaving
  correctly**. `_parse_retry_after()` now handles both forms, clamps past dates to zero, falls back
  on garbage, and never raises.

### Added
- **Jittered backoff.** Retry delays used a deterministic `RETRY_BACKOFF_BASE ** attempt`, so every
  concurrent worker retried on the same tick — a thundering herd against a host that had just asked
  for relief. Backoff now uses **equal jitter** (half fixed, half random, capped by
  `RETRY_MAX_BACKOFF`), which de-synchronises workers while still guaranteeing a minimum pause —
  something full jitter alone does not.
- **Adaptive per-host throttle.** When a host answers **429 or 503**, SecretNode begins pacing
  requests to *that host only*, growing by `THROTTLE_STEP` per signal up to `THROTTLE_MAX_DELAY`
  and decaying as the host recovers (forgotten entirely once healthy). One fragile host no longer
  slows the rest of the engagement, and a healthy host costs **nothing** — pacing starts at zero
  and only appears after the host actually complains. Throttle state resets at the start of each
  scan so pacing learned from one target never penalises the next.
- Config: `RETRY_MAX_BACKOFF`, `THROTTLE_STEP`, `THROTTLE_MAX_DELAY` — documented in `.env.example`.

This is resilience for **authorized** testing, not evasion. The identifiable-source posture is
unchanged: `SECRETNODE_USER_AGENT` still lets an operator present a client-approved agent string,
and scope, SSRF guard, passive-only behaviour and the authorization gate are all untouched.

+19 tests. Suite **294 → 313**, all green; ruff clean.

## [2.7.4] — Mobile & tablet UX for the live dashboard

The dashboard is how a client first sees SecretNode, and it is increasingly opened on a phone.
The findings table had nine columns, so on a phone the two things an operator actually needs —
the severity badge and the DETAIL / FP buttons — were hidden off-screen behind horizontal
scrolling. This release makes the dashboard genuinely usable on touch devices without changing
the desktop layout at all.

### Changed
- **Findings table becomes cards below 900px.** Each row renders as a self-contained card and
  every cell is prefixed with its column name (driven by a `data-label` attribute), so no
  information is lost and nothing scrolls sideways. The redundant row-number column is hidden,
  long source URLs and AI reasoning wrap instead of being ellipsis-clipped, and DETAIL / FP
  become full-width, thumb-sized buttons. The breakpoint is 900px rather than the phone
  breakpoint because a nine-column table is cramped well above phone width — this covers tablets
  in portrait too.
- **Export toolbar reflows** from one cramped row into a two-column grid on small screens.

### Added
- **Touch sizing keyed to `pointer: coarse`, not screen width.** Touch capability is a property
  of the input device, not the viewport, so a tablet gets thumb-sized targets even at 900px while
  a mouse-driven desktop keeps its compact controls. Brings every interactive control to the
  ~40-46px range on touch.
- **iOS auto-zoom fix.** Text inputs render at 16px on touch layouts; below that Safari zooms the
  whole page when an input is focused, which previously left the dashboard mis-scrolled after
  typing a target.
- **Safe-area insets** so the header and main content clear the notch and home indicator on
  modern phones.

### Verified
Measured with Playwright across iPhone SE / iPhone 14 / Pixel 7 / iPad mini / iPad Pro / desktop:
zero page-level horizontal overflow at every width, no interactive control under 32px on touch,
and the desktop table layout confirmed byte-identical in behaviour (`thead` still
`table-header-group`, all nine columns intact). The wide table on large tablets stays contained
in its existing `overflow-x:auto` wrapper rather than breaking the page.

## [2.7.3] — R1 complete: impact-rich verification for AI/ML keys

Closes roadmap item **R1 (verification depth)**. A verified credential no longer reports a bare
"verified" — it reports *what the key actually reaches*, which is the concrete blast radius a
client report needs.

### Added
- **Seven AI/ML provider verifiers**, pairing one with every safe detector from the v2.7.2 pack:
  **ElevenLabs, Groq, Hugging Face, Replicate, OpenRouter, xAI, Pinecone**. Verifier count
  22 → **29 secret types**.
- **Billing-surface as the impact signal.** For AI keys the quantified loss is usually spend, so
  verifiers surface plan tier and remaining quota where the provider exposes it:
  - `ElevenLabs · creator tier · quota 12,345/100,000`
  - `Hugging Face @acme-bot · role: write · 2 org(s)`
  - `OpenRouter · key: prod-key · quota 42/500`
- **Blocked-key handling.** xAI reports disabled keys with HTTP 200; the verifier reads
  `api_key_blocked` / `api_key_disabled` and correctly returns *unverified* rather than claiming a
  dead key is live.

Every verifier keeps the existing contract: exactly ONE read-only identity call to the credential's
own issuer (never the scan target), no writes, **no inference/generation calls** (which would bill
the victim's account), the secret never stored or returned, and fail-closed on any error. Still
OFF by default behind `VERIFY_SECRETS=true` — authorized-scope only.

+9 tests (identity parsing, dead-key, blocked-key, fail-closed, and a guard that every AI detector
ships with a verifier). Suite **285 → 294**, all green; ruff clean.

## [2.7.2] — AI/ML provider detectors + duplicate-finding fix

Grounded in a real authorized-scope scan: an ElevenLabs key shipped in a client-side
`EnvConfig.js` was caught only by the generic catch-all, so it was reported as an untyped
MEDIUM *and* double-counted. Both problems are fixed.

### Added
- **AI/ML provider detector pack (9 new patterns, 54 → 63).** Modern AI stacks leak keys
  constantly because a frontend calls the provider directly instead of proxying through a
  backend. New structural detectors: **ElevenLabs, Groq, Hugging Face, Replicate, Perplexity,
  xAI (Grok), OpenRouter, LangSmith, Pinecone**. Each is prefix + fixed-length, so it stays
  high-precision without the generic entropy gate. ElevenLabs ships provider-specific
  remediation (revoke in dashboard, proxy TTS server-side). +13 tests, incl. near-miss
  precision guards and a ReDoS timing check.

### Fixed
- **One credential no longer reported twice.** `RawFinding.fingerprint` includes `secret_type`,
  so a value matched by both a provider detector *and* the generic catch-all produced two
  findings — double-counting the exposure in client reports, spending a second AI-validation
  call on the same string, and leaving two conflicting severities (HIGH + MEDIUM) for one
  credential. `_collapse_generic_duplicates()` now collapses per `(source_url, raw_match)`,
  keeping the typed detector (accurate severity + provider remediation) and dropping the
  generic claim. The catch-all still fires normally for credentials no detector types. +3 tests.

Suite **282 → 285**, all green; ruff clean.

## [2.7.1] — Gemini validation-engine model refresh

Tracks Google's current Gemini lineup for the two-tier AI validation engine, with no
change to the engine's logic — only the default model IDs (all remain env-overridable).

### Changed
- **Tier-1 pre-filter default → `gemini-3.5-flash-lite`** (was `gemini-3.1-flash-lite`): the
  fastest / most cost-effective 3.5-class model, a natural fit for the high-volume noise-rejection
  tier.
- **Tier-2 deep-validation default → `gemini-3.6-flash`** (was `gemini-3.5-flash`): the stronger
  coding/reasoning workhorse, for confirming genuine high-severity exposures.

### Added
- **Security-specialised Tier-2 option.** `.env.example` documents pointing `GEMINI_TIER2_MODEL`
  at the security-tuned **3.5 Flash Cyber** model (built to reason about software vulnerabilities)
  for security-focused deployments, once a key can call it — a strong fit for the deep
  secret-validation tier.

All model IDs stay overridable via `GEMINI_TIER1_MODEL` / `GEMINI_TIER2_MODEL`; the legacy
single-model `GEMINI_MODEL` override is still honoured. No test or logic changes — suite stays green.

## [2.7.0] — Deep attack-surface platform (passive)

SecretNode grows from a single-URL secret scanner into a **passive attack-surface platform**: give it
a domain and it enumerates the subdomain surface, recovers historically-exposed URLs from public
archives, mines JavaScript for referenced endpoints and third-party hosts, probes which hosts are
live, checks each for **subdomain-takeover risk**, and scans them all — live pages *and* archived
bundles — for exposed credentials and misconfigurations, aggregated into one reviewable report and
drivable from the CLI **or** the dashboard. Every layer stays passive and authorized-scope only.
Test suite **187 → 270**, all green; ruff clean. See `docs/TECHNICAL-AUDIT-AND-ROADMAP.md`.

### Changed
- **Concurrent host orchestration (deep-dive slice D5).** A domain deep scan now scans its hosts in
  parallel with a bounded semaphore (`HOST_SCAN_CONCURRENCY`, default 3) instead of one at a time —
  a large multi-host domain finishes far faster. Results are collected in target order, per-host
  error isolation is preserved (one host failing never sinks the run), and progress is emitted as
  `[k/N] host — done` events. A test proves the parallelism is real *and* stays within the bound.

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
