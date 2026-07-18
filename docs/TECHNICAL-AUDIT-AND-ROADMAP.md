# SecretNode — Technical Audit & Enhancement Roadmap
*Prepared 18 Jul 2026 · baseline: v2.5.4 · grounded in 2026 secret-scanning SOTA (TruffleHog, Gitleaks, GitHub Secret Scanning).*

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
1. **Verification depth.** Verifiers return only `verified/unverified`. TruffleHog surfaces the
   *identity + scopes* a live key maps to (which account, what permissions). That detail is the
   strongest possible "impact" statement — and Cindrasec sells impact.
2. **No FP/FN measurement harness.** There's good FP *handling* but no labeled corpus + precision/recall
   report, so changes aren't measured. Industrial tools track precision/recall on a benchmark.
3. **Regex robustness.** No ReDoS/catastrophic-backtracking audit or regex timeout; a hostile minified
   bundle could stall a detector. No composite/proximity rules (a Gitleaks 2026 feature) for generic
   high-FP patterns.
4. **Surface coverage.** Mines JS + source maps well, but modern leaks also hide in inline JSON
   (`__NEXT_DATA__`, `window.__INITIAL_STATE__`), HTML comments, source-map `sourcesContent`, wasm
   strings, and common exposed paths (`.env`, `.git/config`, `config.js`, backups). All authorized-only.
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
- **R5 · Surface expansion.** Parse inline JSON blobs, HTML comments, source-map `sourcesContent`, wasm
  strings; opt-in known-path probe (`.env`, `.git/config`). Authorized-only. [MED–HIGH]
- **R6 · Detector + verifier expansion.** Prioritize high-impact providers, each paired with a safe
  read-only verifier. [MED, ongoing]
- **R7 · Composite/proximity rule engine** for generic high-FP patterns (Gitleaks-style). [MED]

### Tier 3 — ASM breadth (fulfills the brand fully; larger)
- **R8 · Passive attack-surface map** — CT-log subdomain discovery, security-header/misconfig checks,
  dangling-DNS detection. Moves SecretNode from "secret scanner" toward the full "attack-surface
  scanner" the brand promises. [HIGH]

### Tier 4 — polish
- **R9 · Executive-summary report page** + precision statement + verification-evidence block. [LOW–MED]
- **R10 · Asset caching** (ETag/If-Modified-Since) + per-provider verify concurrency. [LOW]
- **R11 · Distribution** — PyPI publish, tagged releases, docs. [LOW]

## Recommended next steps (highest ROI for Cindrasec's stage)
Pre-pilot, the biggest wins are **R1** (impact-rich verification — makes client reports sell),
**R2** (precision/recall harness — credibility + the explicit FP/FN ask), and **R5** (finds more real
leaks). **Chase impact + precision + surface — not a race to 700 detectors.** Keep the secrets core
excellent before broadening to full ASM (R8).

> Engineering honesty: "enhance every single aspect in one pass" is the wrong move on a working,
> 147-test tool — it trades reliability for the appearance of progress. The right path is incremental,
> measured, tested slices. R4 shipped today; R1 and R2 are the recommended next slices.
