# SecretNode — Technical Audit & Enhancement Roadmap

## Update — 21 Aug 2026 (current: v2.14.0): the recall number is now external

Every previous version of this document, and every benchmark run it cites,
measured recall against specimens built to satisfy SecretNode's own regexes.
`bench/benchmark.py` said so on every run, in as many words: *"a detector
matching its own canonical example proves the detector is wired up, not that it
catches credentials in the wild."* That caveat was correct and it was load-
bearing — 71/71 was never a recall claim.

`bench/external.py` (`make bench-external`) closes it, using gitleaks' rule
definitions: literal specimens written by another project, for another scanner,
owing nothing to these patterns. **80.6% of 108 specimens**, and the report
splits the misses into the only two buckets that matter — a provider SecretNode
covers and missed (a defect) versus one it never claimed (a roadmap fact).

It paid for itself on the first run, finding gaps no internal benchmark could:

- **The current OpenAI key formats were undetected.** The pattern required
  exactly 20 characters before the `T3BlbkFJ` marker — true of the original
  format, false of the `sk-proj-` (~164 char) and `sk-admin-` (~133 char) keys
  OpenAI issues today. The most commonly leaked AI credential of 2026 was
  invisible, and every internal specimen passed because it was built to the
  pattern the code already had.
- **AWS: only `AKIA`.** `ASIA` is a temporary STS credential and is *more*
  likely to appear in shipped frontend code than a long-lived key, because that
  is exactly what a browser-side credential-vending flow hands out.
- **Stripe: only `sk_live_`.** Restricted keys (`rk_`) and the `prod` label
  were missed; test keys now report at LOW.
- Whole credential families elsewhere: GitLab beyond `glpat-` (deploy, runner,
  feed, trigger, OAuth, SCIM), Grafana Cloud (`glc_`) and legacy (`eyJrIjoi`),
  Cloudflare Origin CA, Hugging Face organisation tokens, AWS Bedrock.

**64 → 71 detectors**, and the internal benchmarks held at 71/71 with zero false
positives offline and end-to-end, so none of it cost precision.

The remaining ten "in-scope misses" were each checked by hand and none is a
defect: two placeholders (`XXXX…`), one degenerate all-ones value the entropy
floor is right to reject, and seven entries in gitleaks' JWT rule file that are
not JWTs (a timestamp, two DIDs, a Docker key fingerprint, a GitLab CI claim
string). The honest reading of 80.6% is that the denominator contains items no
scanner should match.

**The lesson worth carrying forward** is the same one this document keeps
relearning, one level up: it previously said to verify each *gap* against the
current code rather than trusting the list. The stronger discipline is to
verify each *measurement* against a corpus you did not write. A benchmark built
from your own assumptions cannot fail in the direction of those assumptions —
it will report 100% right up until someone else's data disagrees.

*Prepared 18 Jul 2026 · baseline: v2.5.4 · grounded in 2026 secret-scanning SOTA (TruffleHog, Gitleaks, GitHub Secret Scanning).*

## Update — 21 Aug 2026 (current: v2.13.0)

Re-checking the "genuinely still open" list from the 13 Aug update against the
code, then auditing the code against what it *claims* to do rather than against
a feature list. The second half is where the findings were.

**Closed since the last update:**

- **R7 (composite/proximity engine)** — the last open MED item. Shipped in
  v2.13.0 as `composite.py`. Worth recording *why* it mattered, because the
  roadmap framed it as a false-positive control for generic patterns and the
  real value turned out to be the opposite: it closes a **false negative**.
  Keyword-anchored detectors ("AWS Secret Access Key" requires *aws* and
  *secret* within twenty characters) lose their anchor to minification, so the
  shipped bundle keeps the credential and loses the word — the scan reported the
  `AKIA…` ID and missed the secret half entirely. A composite rule uses the
  nearby anchor to supply the identity the value's own shape cannot.
- **Gap #6 (AI dependency)** — `triage.py` renders a deterministic verdict with
  no key, no network and no model. The gap list called for "a stronger offline
  heuristic tier"; measuring what offline mode actually produced showed it was
  worse than the entry implied. Every finding came back `confidence=50` with no
  impact statement and no public-by-design call, so an AWS secret key and a
  Stripe publishable key were indistinguishable — in the **default**
  configuration.

**Still open**, verified against the code rather than assumed:

- wasm-string scanning (the last R5 item) [LOW]
- PyPI distribution (R11) [LOW]
- opt-in authorized known-path probe (`.env`, `.git/config`) [MED] — still
  deliberately deferred; it is active enumeration and would contradict the
  "passive assessment" statement in every client report.
- ASM breadth beyond secrets (gap #8) — unchanged, still the larger later step.

### The lesson this pass actually taught

The 13 Aug update ended by telling the next reader to verify each gap against
the current code. That was right and insufficient. Every one of the four defects
fixed in v2.13.0 was invisible to a gap-oriented read, because none of them is a
*missing* feature — each is a feature that exists, is documented, and does not
do what the surrounding code assumes it does:

- The SSRF guard existed in two places and ran on the fetch path in neither.
  `follow_redirects=True` meant a 302 walked past it into loopback and
  link-local space. The check was present, tested, and bypassed.
- `effective_severity()` existed solely to downgrade public-by-design findings
  to INFO, and routing deleted every finding that could reach it. Unreachable
  code that reads as a working feature.
- The ground-truth corpus declared a `public` class whose contract was "detected
  AND classified public-by-design". Nothing enforced the second clause, so the
  corpus documented an expectation the pipeline had never met.
- `generate_json_report` masked credentials in a hardcoded list of bucket names.
  Correct on the day it was written; a latent credential leak the moment anyone
  added a bucket — which this release did.

Three of the four were caught by *writing a test that tried to break the thing*
or by *making the benchmark score what the pipeline actually emits*. The
ground-truth harness found the composite engine's first false positive on its
first run, and found it in the specific form the corpus was built to contain (a
git SHA is exactly as long as an AWS secret key). The measuring instruments are
carrying the load here — so the highest-value next step is not another detector,
it is the external-validity corpus the benchmark's own output keeps asking for:
SecretBench or the gitleaks/trufflehog fixtures, a corpus nobody derived from
these regexes.

For the next update: check whether each documented *capability* is reachable by
the code path that is supposed to reach it, not only whether it exists.

## Update — 13 Aug 2026 (current: v2.8.2)

The body below is kept as written — it was accurate against v2.5.4 — but four
releases have shipped since, and re-checking each "honest gap" against the current
code turned up drift worth correcting rather than leaving to mislead the next read:

- **Gap #5 (detector breadth)** named Twilio, GCP service-account JSON, and Supabase
  `service_role` as missing. All three now exist: Twilio Auth Token
  (`scanner.py`), Supabase Access Token + Secret Key, and GCP Service Account Key
  (JSON). Detector count is 63, not the 54 the README's architecture diagram
  separately (and wrongly) still said until this pass.
- **R8's follow-up** named CT-log subdomain discovery as the next, higher-risk,
  not-yet-done step. It's done, and substantially more than the follow-up
  described: `recon.py` covers crt.sh + Certspotter CT-log enumeration,
  `takeover.py` covers dangling-CNAME/subdomain-takeover checks, and
  `historical.py` covers historical-URL mining — all with their own test files.
  The README's "whole domain" deep-scan section documents this as a current
  feature, not a roadmap item.
- **Genuinely still open**, confirmed by checking the code rather than assuming
  the gap list is current: the composite/proximity rule engine (R7, for
  generic high-FP patterns), wasm-string scanning (the one remaining R5 item,
  [LOW]), and PyPI distribution (R11, [LOW]). Per-provider verify concurrency
  (listed as an R10 follow-up, [LOW]) is now also done — see below.
- **A correctness bug neither this roadmap nor the gap list anticipated**: while
  making verification concurrent, a test written to prove the new code still
  honoured a cancelled scan failed against it — and the same failure mode
  turned out to already exist in the Gemini-validation stage it was modelled
  on. `asyncio.gather(..., return_exceptions=True)` does not propagate a
  `CancelledError` raised inside a gathered task; it is captured as an
  ordinary per-item result. Both stages had a comment naming "cancellation" as
  an expected case in that per-item fallback, but the fallback code could not
  actually tell a cancellation apart from a real per-item bug — so hitting
  STOP mid-scan silently did nothing during either stage. Fixed in v2.8.2;
  see `CHANGELOG.md`. Worth naming here because it's the kind of gap that a
  feature-gap-oriented audit like this one structurally won't catch — it takes
  writing a test that tries to break the thing, not reading the diff.

The lesson for the next update to this document: verify each "gap" against the
current code before treating it as still true, the same discipline the rest of
this project applies to a detector's false-positive rate.

## Executive summary
SecretNode is **already an industrial-grade, well-architected tool** — not a rescue case. v2.5.4 ships
a layered detection pipeline, 147 passing tests, CI, Docker, SARIF/HTML/CSV/JSON, a CLI, a GitHub
Action, live verification, and AI validation. The right engineering move on a mature codebase is
**measured, tested capability expansion — not a blind rewrite.** This document is honest about what's
strong, what's genuinely missing versus the state of the art, and the sequence to close the gaps.

**Its real niche (and why it fits Cindrasec):** TruffleHog and Gitleaks scan **git history / repos**.
SecretNode scans the **live, deployed public attack surface** — client-side JS, source maps, pages —
with **AI validation + impact-first reporting**. That's a differentiated slice and exactly on-brand
for Cindrasec ("attack surface", "sell impact, not noise"). Don't try to out-TruffleHog TruffleHog at
repo scanning; win the *web-surface* niche.

## Current strengths (real design, credited)
- **Verification-first** — 14 live, read-only, fail-closed verifiers ("is this key still active?"). This
  is the TruffleHog-grade differentiator over regex-only tools like Gitleaks.
- **AI contextual validation** (Gemini structured output) with a **public-by-design downgrade**
  (Firebase web key, `pk_live`, Sentry DSN → INFO). Strong, and unusual in OSS.
- **Impact-aware severity** — leads with blast radius, not pattern shape. On-brand.
- **Layered FP/FN control** — placeholder/example allowlist, Shannon-entropy gate, base64-decode pass,
  fingerprint de-dup.
- **Operational maturity** — scan diffing (NEW/RECURRING), FP suppression, needs-review findings are
  never silently dropped, SSRF guard, same-scope restriction, auth, redaction-before-dispatch.

## Honest gaps vs. 2026 SOTA (grounded in the code)
1. ~~**Verification depth.**~~ ✅ **CLOSED.** R1 shipped in v2.6.0 (identity/scope capture) and was
   completed in **v2.7.3**, which paired a verifier with every AI/ML detector from the v2.7.2 pack.
   Verifiers now return the *identity + scopes + billing surface* a live key maps to — e.g.
   "ElevenLabs · creator tier · quota 12,345/100,000" — the strongest impact statement available,
   and the one Cindrasec reports are built to sell. 29 secret types now have verifiers.
2. ~~**No FP/FN measurement harness.**~~ ✅ **CLOSED** — R2 shipped the labelled corpus, and v2.14.0 added the external-validity harness (`make bench-external`) that gives recall a number from outside this repository. See the 21 Aug 2026 update at the top. There's good FP *handling* but no labeled corpus + precision/recall
   report, so changes aren't measured. Industrial tools track precision/recall on a benchmark.
3. **Regex robustness.** No ReDoS/catastrophic-backtracking audit or regex timeout; a hostile minified
   bundle could stall a detector. No composite/proximity rules (a Gitleaks 2026 feature) for generic
   high-FP patterns.
4. ~~**Surface coverage.**~~ ⚠️ **Largely closed — and the original entry overstated it.** Measured
   against the code: HTML comments and inline JSON were *already* covered, because the whole response
   body goes through the raw-text pass. Source-map `sourcesContent` was closed in R5. The one real
   miss was a value whose JSON **escaping** breaks the credential's shape (`\uXXXX` mid-token, as
   emitted by XSS-safe serializers) — closed in **v2.7.6** by decoding inline SSR state blobs.
   *Still open:* wasm strings [LOW]. **Deliberately not done:** probing for unlinked paths
   (`.env`, `.git/config`, backups) is active enumeration, not passive discovery — it would
   contradict the "passive assessment" statement in every client report. If it is ever added it
   must be a separate, clearly-labelled opt-in mode, not folded into the default scan.
5. **Detector breadth.** ~54 patterns vs TruffleHog's 700+. Quality > quantity, but high-impact
   providers are missing (Twilio, GCP service-account JSON, Azure AD, Cloudflare, Shopify, Supabase
   `service_role`, Vercel, Notion). Each new detector should ship *with* a verifier where safe.
6. **AI dependency.** Validation leans on Gemini; the non-AI path exists (needs_review) but a stronger
   offline heuristic tier would make CI-only/air-gapped use first-class.
7. **Performance.** No cross-scan asset caching (ETag / If-Modified-Since); re-scans refetch everything.
8. **ASM breadth.** SecretNode is the *secrets* slice. Cindrasec's brand promises broader ASM
   (subdomains, exposed panels, misconfig, dangling DNS). That's a larger, later expansion — keep the
   secrets core excellent first (scope discipline).

## Roadmap — sequenced, each a shippable, tested unit

### Tier 1 — correctness & brand value (do first)
- **R1 · Verification enrichment.** ✅ **DONE 18 Jul** — a verified credential now yields a short,
  non-sensitive identity/scope label (GitHub @acct+scopes, Stripe account+LIVE/charges, Slack
  workspace/user, OpenAI org, npm/GitLab/Telegram handle, SendGrid send-scope, Mailgun domain count),
  surfaced in HTML/CSV/SARIF as the concrete blast radius. Backward-compatible API; +7 tests.
- **R2 · FP/FN benchmark harness.** ✅ **DONE 18 Jul** — `backend/bench/` labelled corpus (12 synthetic
  positives + 15 placeholders/examples/noise), `make bench` reporting **precision/recall/F1**, and a
  pytest CI gate (`test_bench.py`) that fails the build on a precision/recall regression. Current:
  **precision 1.000 · recall 1.000 · F1 1.000 · 0 false positives.** The harness immediately caught a
  malformed test key, confirming the OpenAI detector correctly requires real key structure. +4 tests.
- **R3 · Regex safety.** ✅ **DONE 18 Jul** — a per-pattern match cap (defence-in-depth against
  match-flood blobs) plus an automated ReDoS gate: empirical wall-clock fuzz over all 54 detectors ×
  17 adversarial 50 KB inputs, a static nested-quantifier guard, and a cap-engagement test. Proves no
  catastrophic backtracking and gates future pattern additions. +3 tests.
- **R4 · SARIF full detector catalog.** ✅ **DONE 18 Jul** — the driver now advertises every detector as
  a SARIF rule (help text, CWE, severity), even on clean scans. +2 tests.

### Tier 2 — coverage
- **R5 · Surface expansion.** ✅ **DONE 18 Jul (source-map slice)** — decode a source map's embedded
  original source (`sourcesContent`) and scan it as real code, with precise per-file attribution
  (`app.js.map → src/config.js`). Replaces raw-`.map` scanning for maps that carry source, which also
  removes the high-entropy `mappings` VLQ as a false-positive source. Env-tunable
  (`SCAN_SOURCEMAP_CONTENT`, `MAX_SOURCEMAP_SOURCES`); fully defensive; +6 tests.
  *Note:* inline JSON (`__NEXT_DATA__`, `__INITIAL_STATE__`) and HTML comments are **already** covered —
  the scanner scans the full HTML body wholesale, so they are in scope today.
  *Remaining R5 follow-up:* opt-in authorized known-path probe (`.env`, `.git/config`, `config.js`) —
  the one genuinely new *network* surface; deferred as higher-risk (extra requests, needs SSRF/scope
  review). [MED]
- **R6 · Detector + verifier expansion.** ✅ **DONE 18 Jul (verifier slice)** — added 8 read-only
  whoami/validate verifiers for existing detectors that previously returned `unsupported`: Cloudflare,
  DigitalOcean, Datadog, Notion, Linear, Figma, Postman, Doppler. Live-verification coverage now spans
  **17 providers** (was 9); each extracts R1 identity where available, is read-only, and fails closed.
  Chosen deliberately over adding new *detectors* — this widens the verification-first differentiator
  with **zero new false-positive risk** (no new regexes). +6 tests. *Follow-up:* new detectors (Twilio
  SID-paired, GCP SA JSON, Supabase service_role) when each can ship with a corpus entry + verifier.
- **R7 · Composite/proximity rule engine.** ✅ **DONE (v2.13.0)** — `composite.py`.
  Framed here as an FP control for generic patterns; it shipped as a false-*negative*
  fix, which is the more valuable end. See the 21 Aug update at the top.

### Tier 3 — ASM breadth (fulfills the brand fully; larger)
- **R8 · Passive attack-surface map.** ✅ **DONE 18 Jul (security-posture slice)** — `posture.py`
  analyses the target root's own response for missing/weak security headers (HSTS, CSP, clickjacking,
  X-Content-Type-Options, Referrer/Permissions-Policy), version disclosure, and insecure cookies. Pure
  passive analysis (no exploitation, no third-party calls); each issue carries severity/CWE/evidence/
  remediation and renders in a dedicated report section + KPI tile — so even a clean *credential* scan
  now returns actionable ASM findings. Env-tunable (`SCAN_HTTP_POSTURE`); +11 tests. This is the first
  step from "secret scanner" toward the full attack-surface scanner the brand promises.
  *Remaining R8 follow-up (higher-risk / external network):* CT-log subdomain discovery (crt.sh),
  DNS resolution + dangling-CNAME takeover checks; posture in CSV/SARIF export. [HIGH]

### Tier 4 — polish
- **R9 · Executive-summary report page.** ✅ **DONE 18 Jul** — the HTML report now leads with a
  verification-evidence callout (each verified-active key + its R1 identity/scope as "confirmed live
  access"), a "Verified Active" KPI tile, and an honest measured-precision "Detection quality"
  statement (verification-first + CI-gated precision/recall). Turns the engine work into a
  client-ready deliverable. +4 tests.
- ~~**R10 · Asset caching**~~ ✅ **DONE (v2.7.7)** — conditional GET with a per-target validator
  cache; a 304 skips an unchanged *and previously clean* asset, but always refetches one that
  had a finding so nothing silently vanishes from a report. No response bodies cached, by
  design. *Follow-up (per-provider verify concurrency)* ✅ **DONE (v2.8.2)** — see the
  13 Aug update at the top of this document.
- **R11 · Distribution** — PyPI publish, tagged releases, docs. [LOW]

## Recommended next steps (highest ROI for Cindrasec's stage)
Pre-pilot, the biggest wins are **R1** (impact-rich verification — makes client reports sell),
**R2** (precision/recall harness — credibility + the explicit FP/FN ask), and **R5** (finds more real
leaks). **Chase impact + precision + surface — not a race to 700 detectors.** Keep the secrets core
excellent before broadening to full ASM (R8).

> Engineering honesty: "enhance every single aspect in one pass" is the wrong move on a working,
> 147-test tool — it trades reliability for the appearance of progress. The right path is incremental,
> measured, tested slices. R4 shipped today; R1 and R2 are the recommended next slices.
