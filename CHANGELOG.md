# Changelog

All notable changes to SecretNode are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

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
