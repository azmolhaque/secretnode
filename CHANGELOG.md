# Changelog

All notable changes to SecretNode are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [2.14.1] — Three limits that were documented, asserted, or implied

An audit for this codebase's recurring shape: a guarantee stated somewhere a
reader will believe it, with no mechanism behind it. Three found, all measured
before being fixed — and one proposal measured and then dropped.

### Fixed — the documented RAM bound was not one

The architecture table credited `asyncio.Semaphore(20)` with *"bounds RAM on Pi
5 during deep JS analysis"*. It bounds concurrent **fetches**, which is a
different thing: every fetched body was appended to one list held until the scan
ended, with no aggregate cap. `js_urls` had no cap at all — every `<script src>`
across every crawled page was gathered at once — so source maps alone could
reach 200 MB and archived seed assets 1 GB, on the 16 GB Pi this project targets.

- `MAX_TOTAL_ASSET_BYTES` (256 MB) bounds what a scan **keeps**, charged at every
  accumulation point: root, crawled pages, JS bundles, source maps, archive
  seeds and the deeper endpoint crawl. `MAX_JS_ASSETS` (400) bounds the count.
- Advisory, not fatal: a scan that stops collecting still reports everything it
  read, where one killed by the OOM killer reports nothing. Engaging the cap is
  a WARN **and** `assets_skipped_over_budget` on the result — reading less than
  the operator asked for is a coverage statement, and a coverage statement only
  in a log line nobody keeps is how a clean verdict comes to mean nothing.
- A crawled page is still parsed for links when the budget is spent; only its
  body is dropped. A page is a link graph as well as something to grep.
- Verified end to end: eight ~9 KB bundles against a 20 KB budget kept four,
  skipped ten, and completed cleanly with the count on the result.
- The README row now says what the semaphore actually does.

### Fixed — credentials were retained in memory indefinitely

`main._registry` was appended to and never pruned — no `del`, no `pop`, no
eviction anywhere — and each completed entry holds the full result, matched
values included. Measured at ~16 KB for a scan of ten findings, ~156 MB at
10,000 scans. The memory is the lesser problem: a long-running dashboard held
every credential it had ever found in process memory, indefinitely, long after
any use for them. That is the same argument the `asset_cache` schema already
makes about not keeping a client's secrets on disk, applied to RAM, where
nothing enforced it.

`MAX_REGISTRY_ENTRIES` (200) bounds it. Eviction is safe because `_resolve_scan`
already falls back to SQLite, so a report requested afterwards is served from
the durable store; running scans are never evicted, since they hold live state.

### Fixed — scan history grew without limit

Measured at ~16.7 KB per scan, which under continuous monitoring is on the order
of a gigabyte a year onto an SD card. `SCAN_HISTORY_LIMIT` (1000, `0` disables)
prunes at the point the table grows, so retention needs no separate schedule.
By count rather than age: an operator who scans monthly should not lose their
history to a 90-day rule, and one who scans hourly should not accumulate forever.

### Fixed — a credential could reach a log

`verifier.py` states it *"never reveals or transmits the secret anywhere except
to its own issuer"*, and nothing enforced it. Telegram's API requires the token
in the URL path, and `httpx.HTTPStatusError` renders the full URL into its
message, which `verify_finding_detailed` logged verbatim on any failure — a live
bot token in cleartext, reproduced with a synthetic one.

Latent rather than live: no verifier calls `raise_for_status()` today, so
nothing reaches that path. It is fixed anyway, because a docstring invariant with
no mechanism behind it is precisely how the authorization ledger came to be a
comment. The scrub covers the percent-encoded form too — a token containing `:`
or `/` arrives encoded, so matching only the literal would let exactly the
tokens that need encoding through.

### Measured and deliberately not shipped: WAL journaling

SQLite runs in `delete` journal mode with no explicit PRAGMAs, which looked like
an obvious win for an async app writing from concurrent host scans. Measured
first: 30 concurrent writes plus 30 concurrent reads ran in **0.28 s as shipped
and 0.77 s with WAL, with zero errors either way**. `busy_timeout` already
defaults to 5 s, and every call opens its own connection, so WAL's per-connection
cost lands without its cross-connection benefit. A 2.8x regression sold as a
performance improvement is worse than leaving it alone.

**787 tests, ruff clean.** Ground truth 71/71 offline and over HTTP, zero false
positives; external-validity recall unchanged at 80.6%.

## [2.14.0] — The recall number is now measured from outside

Asked to test against intentionally vulnerable targets. Two things made that
question worth reframing rather than answering literally: hosted targets are
unreachable from this environment, and Juice Shop / DVWA measure SQLi and XSS —
which this tool does not claim to find. The equivalent for a secrets scanner is
a labelled corpus of planted credentials that nobody here wrote.

### Added — `make bench-external`, and the number it produced

`bench/benchmark.py` has printed its own caveat on every run since it shipped:
*"a detector matching its own canonical example proves the detector is wired up,
not that it catches credentials in the wild."* Correct, and load-bearing — 71/71
was never a recall claim. `bench/external.py` measures against gitleaks' rule
definitions: literal specimens written by another project, for another scanner,
owing nothing to these patterns.

**80.6% of 108 specimens.** The report splits misses into the only two buckets
that matter — a provider SecretNode covers and missed (a defect) versus one it
never claimed (a roadmap fact, since gitleaks carries ~220 rules to this
scanner's 71 and breadth was never the differentiator).

The corpus is fetched on demand, never vendored: ~240 KB of third-party source
whose whole purpose is to contain credential-shaped strings would trip push
protection, which is the same trap `bench-corpus/` set two releases ago. With no
network the run skips and says so — *"this is a skip, not a pass: no number was
measured"* — and there is a test pinning that, because a benchmark that silently
reports success when it measured nothing is worse than one that fails.

### Fixed — the current OpenAI key formats were undetected

The pattern required exactly 20 characters before the `T3BlbkFJ` marker. That
was true of the original key format and is false of the `sk-proj-` (~164 char)
and `sk-admin-` (~133 char) keys OpenAI issues today — so the most commonly
leaked AI credential of 2026 was invisible. `T3BlbkFJ` is base64 "OpenAI" and is
the actual discriminator; the segments around it carry no length promise and no
longer pretend to.

Every internal specimen passed throughout, because each was built to satisfy the
pattern the code already had. This is precisely the failure an internally-derived
benchmark cannot report.

### Fixed — credential families the provider coverage implied but did not match

- **AWS: only `AKIA`.** `ASIA` is a temporary STS credential and is *more*
  likely to appear in shipped frontend code than a long-lived key — it is what a
  browser-side credential-vending flow hands out. `A3T*`, `ABIA` and `ACCA` now
  match too, and Amazon Bedrock keys (`ABSK`/`AXSK`) get their own detector.
- **Stripe: only `sk_live_`.** Restricted keys (`rk_`) and the `prod` label were
  missed. Test-mode keys now report at LOW — they cannot move money, but they
  are routinely committed beside the live key they were copied from.
- **GitLab: only `glpat-`.** Deploy, feed, runner, pipeline-trigger, OAuth-app,
  SCIM, agent, incoming-mail, feature-flag and CI job tokens each grant real
  repository or CI access and read as unrecognised strings.
- **Grafana: only `glsa_`.** Cloud access-policy tokens (`glc_`) and legacy API
  keys (`eyJrIjoi…`, JWT-shaped but without the dots the JWT detector needs).
- **Cloudflare Origin CA keys** (`v1.0-…`), which mint origin certificates.
- **Hugging Face organisation tokens** (`api_org_`), the wider-blast-radius
  sibling of the per-user `hf_` token that was already covered.

**64 → 71 detectors**, and the internal benchmarks held at **71/71 with zero
false positives** both offline and end-to-end over HTTP. None of it cost
precision.

### Fixed — a corpus specimen that could not survive its own detector

Adding a specimen shifted the shared RNG stream and the Terraform Cloud sample
generated a trailing `-`, which its detector's own `\b` boundary excludes: the
declared and captured values differed. The corpus self-validation caught it, as
designed. Latent, RNG-position-dependent, and dormant until something unrelated
was added — so the final character is now pinned to the word class rather than
left to chance.

### Fixed — a test that had become an accidental ceiling

`test_severity_lookup_covers_all_patterns` asserted every detector's severity
was CRITICAL, HIGH or MEDIUM. LOW was absent only because no detector had used
it yet, so a check meant to ask *"is this a recognised value?"* had quietly
become *"no detector may be low severity."* Aligned with the vocabulary
`report._SARIF_LEVEL` and `report._SEVERITY_RANK` actually understand.

### On the remaining 19.4%

Ten in-scope misses, each checked by hand, none a defect: two placeholders
(`XXXX…`), one degenerate all-ones value the entropy floor is right to reject,
and seven entries in gitleaks' JWT rule file that are not JWTs (a timestamp, two
DIDs, a Docker key fingerprint, a GitLab CI claim string). Eleven more are
providers with no detector — atlassian, facebook, flyio, freemius, intra42,
kubernetes, pulumi — which is a coverage decision, not a failure.

The honest reading of 80.6% is that the denominator contains items no scanner
should match. It is still the number to quote, because it is the only one
measured against data this project did not write.

**768 tests, ruff clean.** Ground truth 71/71 offline and over HTTP, zero false
positives; labelled corpus precision 1.000 / recall 1.000.

## [2.13.2] — The redirect guard changed what posture measures

A second live deep scan, of a domain whose apex and `www` both answer. Two
defects, both reproduced against the real pipeline in a local lab before a line
was changed — the lab reproduces the shapes the real reports exhibited, because
this environment cannot reach an external target.

### Fixed — posture was measuring the redirect, not the page

v2.13.0 set `follow_redirects=False` on the shared client so every hop could be
address-checked before a request went out. That was right, and it silently
changed what `posture.fetch_posture` sees: its single `client.get()` now
returned whatever answered *first*. On any host that redirects, that is the
**301**, not the page a browser ends up on.

A redirect hop is not the site. The first real target hid this — Cloudflare
applies header rules to redirects too, so the wrong measurement and the right
one agreed. Against a lab server whose landing page sets six security headers
and whose redirect hop sets none:

```
landing page (headers present) : 1 issue   (the Python Server: banner)
redirect hop (headers ABSENT)  : 6 issues  -> 5 of them fabricated
```

Five missing headers reported for a page that sets all five.

- `fetch_posture` takes a `get_final` callable and `scanner` passes it the same
  validated hop-walk the fetch path uses, so posture measures the landing page
  and a redirect into internal space is still refused rather than read for
  headers. Injected rather than imported: the only implementation lives in
  `scanner`, which imports `posture`, so a parameter keeps the dependency
  one-way and the function unit-testable with no network.
- The landing page's URL also decides the HTTPS-only checks, so an `http://`
  start that lands on `https://` is judged on where it ended.

### Fixed — one site was being scanned twice

`www.example.com` 301-ing to `example.com` looked like two independent live
hosts. `_probe_one` returned the URL it asked for on any HTTP response —
including a 301 — and never recorded where it pointed, so `run_deep_scan`
crawled both. In the lab: **eleven requests for four unique paths**, both
"hosts" reporting the same three assets. Against a real domain that is double
the traffic aimed at a target, and a client report claiming twice the coverage
it has.

- The probe now captures the redirect destination — it is the only place that
  sees it, since the client stopped following redirects in v2.13.0.
- `collapse_redirect_duplicates` drops a host only when its redirect lands on a
  host **already being scanned**. A redirect leaving that set is scanned
  normally: it may be the only route to content nothing else reaches, so
  dropping it would lose coverage rather than remove duplicate work. A mutual
  redirect loop falls back to scanning both — duplicate work beats a scan that
  reads nothing and still prints a verdict.
- Lab after the fix: **five requests, one duplicate** (posture's own root GET).

### Fixed — a collapsed host is not a failure

Found while wiring the above, and it would have been wrong twice over. The only
way to record a host that was not scanned was `HostScan.error`, which renders
red as **error** in the per-host table *and* is what the v2.13.1 coverage check
counts as unexamined — so de-duplicating a `www` alias would have hedged a
fully-covered domain to PARTIAL, the mirror image of the overstatement that
verdict exists to prevent.

`status` and `note` now carry that case without overloading a field that means
"this failed". The alias appears in the table, labelled `redirect`, with the
host it points to; a genuinely failed host still reads as an error.

**758 tests, ruff clean.** Labelled corpus precision 1.000 / recall 1.000;
ground truth 64/64 with zero false positives.

## [2.13.1] — Three defects a live scan found that the suite could not

A deep scan of a real company's domain produced an HTML report, a CSV and a
SARIF file. Reading the three next to each other took about ninety seconds and
turned up three defects, none of which any of the 708 tests could see, because
each one needs input messier than a test fixture usually is.

### Fixed — one regex literal disabled the whole comment stripper

v2.12.6 added `surface.strip_js_comments()` so that `//console.log(…)` and a
bundled library's documentation links would stop being reported as the client's
"third-party / connected infrastructure". The report from this scan listed
`i.test`, `.test`, `caniuse.com`, `stackoverflow.com` and
`raw.githubusercontent.com`. Four of those five are named in the v2.12.6 entry
as fixed.

The stripper tracked string literals but not regex literals. A regex may contain
a quote — `/['"]/g` is ordinary in any bundle that normalises quoting — and a
scanner that only knows about strings reads that apostrophe as the *start* of
one. From there the tracker is inverted for the rest of the file: real code
counts as string content, and every subsequent comment survives. It fails open,
silently, and only on input realistic enough that no unit test had used it. One
regex early in a bundle was enough to disable the pass for the whole file.

- Regex literals are now tracked. Telling one from division is the classic
  JavaScript lexing ambiguity and cannot be resolved without knowing whether the
  previous token ends an expression, so `_regex_may_follow` is that test, kept
  conservative: when the preceding token can end a value — identifier, number,
  `)`, `]`, `}`, or a closed string — the slash divides.
- Two bounds keep a misread cheap. A regex cannot span a line, so an unterminated
  one is re-read as division rather than swallowing the file; and guessing
  "regex" too eagerly is the more expensive error, because it blanks real code
  and drops hosts from the graph. The ambiguity resolves toward division.
- Verified by sweep as well as by example: across 400 randomised bundles mixing
  regex literals, division, template strings and comments, zero hosts inside
  string literals were lost and length was preserved every time.

### Fixed — `.test` is not a hostname

`_valid_host` rejected a trailing dot but not a leading one, so `.test` — a
by-product of the desync above — passed as a hostname and was printed in a
client's external-host list. A label may not be empty; that is now what the
check says.

### Fixed — 143 posture issues reached no deliverable

The scan found 143 security-header and misconfiguration issues. The HTML showed
the number in a KPI tile and a per-host column and itemised none of them; the
CSV was a bare header row; the SARIF was `"results": []`. Only
`generate_html_report` — the single-target renderer, which a deep scan never
calls — could itemise posture at all.

Two deliverables built from one scan disagreeing about whether anything was
found is worse than either being empty, because each looks authoritative on its
own. A consumer gating on the SARIF was told the target was clean.

- Posture issues are now written to CSV (`status=POSTURE`, so a reader sorting
  the column cannot mistake them for leaked credentials) and emitted as SARIF
  results under their own `secretnode/posture/*` rules, tagged `posture` rather
  than `secret`. Their rules are declared on demand rather than catalogued
  up-front: the detector registry is a fixed list, but posture checks are
  generated per response, so there is no complete set to advertise.
- The deep-scan HTML gains a section that names each issue, its evidence and its
  remediation, grouped by issue rather than by host — one missing CSP across
  twenty-six hosts is one fix, and a flat list reads as twenty-six problems.
- Closes the R8 follow-up ("posture in CSV/SARIF export") the roadmap had carried
  as open at [HIGH].

### Fixed — a CLEAN verdict over a domain the scan mostly did not read

`MAX_TARGETS` defaults to 25 and is applied as a prefix slice of an
alphabetically sorted host list. The scan read 26 of 83 live hosts; everything
after the letter "g" was never fetched. The banner said **"No confirmed
credential exposures across the domain."**

That claim is the product, and stating it from 31% of the surface is the same
error v2.12.3 fixed for resolved findings — asserting an absence the scan's
coverage does not support. It is worse here, because a domain verdict is the
line a client reads first.

- The verdict now reads PARTIAL when live hosts were discovered and not scanned,
  states both counts, and adds a coverage note explaining that the unscanned
  hosts are the tail of an alphabetical ordering rather than a random sample.
- A confirmed exposure still outranks coverage: partial reading never softens a
  credential that was actually found.
- The cap is unchanged. Raising it silently multiplies traffic against a third
  party; that is an operator's decision, not a reporting fix.

**739 tests, ruff clean.** Labelled corpus precision 1.000 / recall 1.000;
ground truth 64/64 with zero false positives.

## [2.13.0] — The SSRF guard ran once. Offline mode had no verdict.

Four defects found by auditing the code against what it claims to do, each with
its own root cause and its own regression net. Two are security-relevant, two
are about a report telling the truth.

### Fixed — the redirect chain was completely unguarded

`build_client()` set `follow_redirects=True`, so httpx resolved and connected on
its own for every hop. `assert_public_target` ran once, against the URL the
operator typed, and never again. A probe against the old code:

```
requested:    http://127.0.0.1:PORT/redirect
returned url: http://127.0.0.1:PORT/redirect   <- the URL asked for
body:         const k = "AKIA…"                <- served by /internal
```

Three consequences, one root cause.

- **SSRF.** A single 302 reaches loopback, RFC1918 and link-local space,
  including `169.254.169.254` — and the instance-metadata response is scanned
  for credentials and written into a client report. This needs no hostile
  target: an open redirect on a legitimate one is a sufficient trigger.
- **Scope.** `_accept_asset` refuses to *discover* a third-party host, then a
  redirect fetches one anyway. For a tool whose authorization ledger asserts
  that only authorized hosts were contacted, that traffic is the violation the
  ledger exists to prevent.
- **Attribution.** `fetch_url` returned the URL it asked for, never the one that
  answered, so a credential served by the redirect's destination was reported at
  the original location and the remediation pointed at the wrong system. The
  same bug resolved relative URLs against the pre-redirect base: an apex
  redirecting to `www`, or to a locale prefix, produced 404s for every relative
  asset and a quietly under-covered scan that still printed CLEAN.

`netguard.py` is now the single answer to "may this scanner request this?".
`main.py` and `cli.py` each carried a hand-rolled copy of the address rule and
the fetch path had none — the missing one is the one traffic went through.
`_get_following_redirects` walks the chain one validated hop at a time.

- Scope is judged against the URL originally requested, never the previous hop.
  Otherwise a chain walks anywhere one in-scope step at a time: A → B (in scope
  for A) → C (in scope for B, authorized by nobody).
- Scope is checked *before* resolution — no DNS lookup for a host already
  refused, and the refusal reason is the scope decision rather than a DNS
  failure.
- Refusal is loud. A silent skip trades an SSRF for a coverage loss that nothing
  reports, and a scan that quietly stopped reading still prints CLEAN.
- RFC6598 CGNAT (`100.64.0.0/10`) is refused. It is not `is_private`, so the
  previous rule let it through; a test documents the old blind spot.
- One test asserts `follow_redirects is False` on the built client. If that is
  ever re-enabled every other test still passes while the hole reopens, because
  httpx would resolve the chain internally and `fetch_url` would never see a 3xx.

Also: a duplicated `Content-Length` (`"512, 512"`, as some proxies emit) raised
`ValueError`, which the catch-all handler turned into a silent asset drop with
no retry. An unread asset is an unscanned asset.

### Added — a deterministic verdict that needs no API key (`triage.py`)

With no `GEMINI_API_KEY`, `_ai_skipped` returned `is_valid=True, confidence=50`
for everything. That is not a verdict, it is a placeholder standing in for one:
an AWS secret key, a Sentry DSN and a Stripe *publishable* key came back
byte-identical apart from the type name, none carrying a sentence about blast
radius. This is the **default** configuration — the README documents offline
operation on a Pi as first-class — so the most common way to run the tool was
also the way that produced the least usable output.

- Known-public values are dismissed at the same confidence the AI tier uses:
  Stripe `pk_`, Sentry DSN and PostHog `phc_` by type; a Firebase web `apiKey`
  or a Maps key by the config siblings beside it. A bare `AIza…` with neither
  context is retained, and the reason says it is ambiguous rather than
  manufacturing a call.
- Generic keyword=value matches inside evident test scaffolding are dismissed.
  Provider-shaped keys in the same file are **not** — developers hardcode real
  credentials into fixtures constantly and those fixtures ship in bundles.
  `staging` and `dev` are deliberately absent from the non-production markers:
  staging credentials are real credentials against real infrastructure.
- Everything retained carries a blast-radius sentence, so an offline report says
  what an attacker gets rather than listing types.
- Findings now report `validation_tier` (`ai` / `offline-triage` / `none`). A
  confidence number with no tier named invites the reader to assume the
  strongest tier ran, and for an offline scan that assumption is wrong.

Triage never confirms, by construction *and* by routing: its retain confidence
is capped below the threshold, and `classify_validated` refuses to confirm an
un-AI-judged finding regardless of the number attached to it.

The never-drop guarantee holds and is now explicit about why. Only a *confident*
offline dismissal discards; a hedged one goes to a human. Getting a confirmation
wrong wastes an afternoon; getting a dismissal wrong is the failure this whole
tool exists to prevent.

### Fixed — offline mode could not confirm anything, ever

Verification only ever ran on `confirmed`. Offline, everything routes to review,
and review was never verified — so the Confirmed table was structurally
guaranteed to be empty no matter how many live credentials the scan had actually
found. The strongest evidence this tool can obtain was withheld from exactly the
findings nobody could judge.

Verification now also runs on review findings that have a verifier, and promotes
any the provider confirms ACTIVE. A provider answering "yes, this key works" is
an observation, not an opinion; it does not additionally need a model to agree.
The scan-to-scan diff moved after verification so a promoted finding is counted
like any other confirmed one.

### Added — R7: credentials no single regex can find (`composite.py`)

Several registry detectors are keyword-anchored:

```
AWS Secret Access Key   (?i)aws.{0,20}secret.{0,20}['"]([A-Za-z0-9/+=]{40})['"]
```

The keyword is doing all the work, and a bundler deletes it. What ships is
`{a:"AKIA…",b:"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}` — the ID is found
because `AKIA…` is self-describing, the secret is not. The scan reported the half
that is a public identifier and missed the half that is the credential, and no
amount of tuning a single-value regex fixes it, because the information needed is
not inside the value. It is right next to it.

Two rules: `AKIA…` → the AWS secret beside it, Twilio Account SID → the auth
token beside it. Anchors are never reported on their own — a Twilio SID is a
public identifier, and adding it to the registry to enable the pairing would mean
reporting known-public information as an exposure.

The precision work is the substance, and the ground-truth benchmark drove it. The
unconstrained rule's first run produced a false positive: a 40-hex git commit SHA
is exactly as long as an AWS secret key and appears in essentially every build,
so proximity alone made every such build yield a CRITICAL finding on a value that
is public by definition. The fix is a character-class test — an AWS secret is 40
draws from a 64-symbol base64 alphabet, so P(no uppercase) is about 1 in 10⁹,
while a hex digest can never satisfy upper+lower+digit. The Twilio rule cannot
use that test (its token *is* 32 hex), so proximity carries the whole weight and
the window tightens to 120 characters.

Composite findings pass every existing gate and carry their rationale into the
context snippet: a shapeless 40-character string reported as CRITICAL has to be
able to show its reasoning, or an analyst is right to distrust it.

`_collapse_generic_duplicates` becomes `_collapse_duplicates` with a three-tier
rank — a registry detector outranks a composite inference, which outranks the
generic catch-all — because R7 creates the same collision from the other
direction. The old name is kept as an alias.

A test asserting that every composite rule names a registry type caught a defect
in this change itself: `OAuth Client Secret` had no registry entry, so its
severity and remediation would have silently degraded to the generic
MEDIUM/CWE-798 fallback. Investigating showed the rule was never a composite at
all — its companion requires the literal `client_secret` keyword, so it anchors
itself and never consults the `client_id`. It is now an ordinary detector in the
registry, which is where a keyword-anchored pattern belongs. **64 detectors.**

### Fixed — public-by-design findings were deleted, not reported

The ground-truth corpus declares three classes, and `public` has a two-part
contract: "must be detected AND classified public-by-design". Nothing enforced
the second half. `classify_validated` routed a confident dismissal to `drop`, and
a public-by-design verdict *is* a confident dismissal — so those findings were
deleted, and `effective_severity()`, whose sole purpose is to downgrade them to
INFO, was unreachable dead code.

Deleting them is also the worse client outcome. A reader who sees nothing about
their Stripe publishable key cannot tell whether the scanner examined it and
cleared it or never looked.

- New `informational` bucket, rendered as **"Examined and Cleared — Public by
  Design"**. This is not the same as reporting an exposure: informational
  findings raise no alert, are never live-verified, and carry INFO severity. In
  SARIF they are `note` level, because a pipeline that goes red on a publishable
  key is a pipeline someone disables — and then the AWS key goes unnoticed too.
- Carried through HTML, CSV, SARIF, JSON and the dashboard. No toast on the
  dashboard, deliberately: an alert that needs no action teaches an operator to
  ignore alerts.
- The benchmark harness now scores the bucket it was blind to. It had reported
  recall 0.953 for the pipeline doing exactly what the corpus asks — the
  measuring instrument being wrong about the tool.

**Found while wiring it up, and the more dangerous of the two:**
`generate_json_report` masked credentials in a hardcoded list of two bucket
names. Adding a third without extending that tuple would have shipped unmasked
live keys in the one deliverable a client is most likely to pipe into another
tool or commit to a triage repo — reintroducing exactly the bug that function's
docstring describes as fixed. A masking rule that depends on someone remembering
to update a list will eventually be wrong, so it now keys off the field that
actually matters: a dict carrying `raw_match` gets masked, wherever it lives.

### Measurements

- **708 tests passing** (was 631), ruff clean.
- Labelled corpus: **precision 1.000 · recall 1.000 · F1 1.000**, 0 false positives.
- Ground truth, offline: **64/64**, 0 false positives.
- Ground truth, full pipeline over HTTP: **64/64**, 0 false positives — restored
  from the 0.953 the informational bucket had exposed.

## [2.12.6] — The ledger existed. Nothing called it.

A whole-domain deep scan ran from the dashboard against a company with no Rules of
Engagement on file: 123 subdomains enumerated, 80 hosts probed for liveness, 25
crawled, 129 assets fetched, 383 seconds of traffic — and VERIFY was enabled, so a
confirmed credential would have been replayed against the provider's API.

`ops/ledger.py` had shipped in v2.12.0 to make exactly this impossible. It was never
wired into a scan path. An authorization check a caller has to remember to make is
not a control; it is a comment.

### Fixed — authorization is now in the request path

- **`ledger.enforce()` gates every scan entry point**: `POST /api/scans`,
  `POST /api/deep-scans`, and the CLI. No live authorization covering the target, no
  scan — HTTP 403 from the API, exit 2 from the CLI, before any traffic. Fails closed:
  `REQUIRE_AUTHORIZATION` defaults to true, and an empty ledger denies everything.
- Two deliberate escape hatches, both narrow. A loopback/private target is exempt when
  `ALLOW_PRIVATE_TARGETS=true`, so a local lab and `make bench-http` still run — it
  grants nothing on the public internet, and a test pins that. `REQUIRE_AUTHORIZATION=false`
  disables the gate entirely and logs a warning naming the target, because every finding
  from such a run is unattributable to an engagement.
- Every decision, allow or deny, is written to the ledger's audit trail. "We only
  scanned what was authorised" is a claim; the trail is the evidence.

### Fixed — comments in bundles were being reported as the client's infrastructure

The same report listed `console.log`, `i.test`, `stackoverflow.com`, `caniuse.com`,
`pastebin.com`, `raw.githubusercontent.com` and several developers' personal blogs
under the heading **"Associated hosts (third-party / connected infrastructure)"**.

`_ABS_URL` matches protocol-relative `//host`, and a minified bundle is full of
`//console.log(…)` and `//i.test(v)` — every commented-out line became a hostname.
Documentation URLs cited in library comments came through the same way. Handing a
client a "connected infrastructure" list containing `pastebin.com` is worse than
handing them nothing: the heading makes a claim the data does not support.

- `surface.strip_js_comments()` removes `//` line comments and `/* … */` blocks before
  host and endpoint extraction, correctly leaving string literals alone (`"https://…"`
  contains `//`) and preserving newlines so offsets still line up. A denylist cannot
  keep up with every blog a bundled library cites; removing comments addresses the cause.
- **Never applied on the secret-detection path.** Credentials hide in comments, and
  blanking them there would be a false negative — the failure this scanner treats as
  unacceptable. Surface intel only.
- The report section is retitled "External hosts referenced across the domain" and now
  states what it is: a reference graph extracted from code, not an assertion that every
  entry is a live dependency.

### Fixed — scope is not consent to a technique

`permit_deep_scan` and `permit_verification` were defined on `Authorization`,
stored in the schema, written by `save_authorization` and read back by
`_row_to_auth` — and consulted by nothing. The same defect as the ledger itself,
one level down. The run that prompted this release had *both* techniques on.

- `enforce(target, deep=…, verify=…)` now refuses a domain-wide enumeration, or a
  live credential replay, unless the engagement permits that specific technique.
  An authorization covering a host is not consent to enumerate every subdomain it
  has, and it is certainly not consent to authenticate to a provider with a
  credential found along the way.
- Both scan endpoints and the CLI pass the flags they were invoked with.

### Fixed — the deep-scan endpoint had no SSRF guard

`POST /api/scans` called `assert_public_target`; `POST /api/deep-scans` did not.
The larger of the two traffic generators was the unguarded one. It now resolves and
rejects private/internal addresses on the same terms.

### Added — the ledger has a write interface

It stayed empty partly because filling it meant writing Python. `python -m ops.ledger`
now offers `add`, `list`, `check`, `revoke` and `decisions`:

```
cd backend                      # `ops` is a package inside backend/
python -m ops.ledger add --id ENG-2026-014 --client "Acme Ltd" \
    --scope acme.com '*.acme.com' --starts 2026-08-01 --expires 2026-09-30 \
    --recipient security@acme.com --roe "Signed RoE 2026-07-28"
python -m ops.ledger check acme.com --deep
```

or from the repo root: `make auth-list`, `make auth-check TARGET=acme.com`,
`make auth-decisions`.

`check` answers the question the scanner will ask, before you start a scan and
discover the answer the hard way. `decisions` prints the audit trail.

### Tests

- `test_v2126.py`: 33 tests. The gate is asserted to deny an unauthorized company, an
  empty ledger, and both lookalike shapes (`notexample.com`, `example.com.evil.net`);
  to allow an authorized apex and subdomain; and to record denials. Three tests read
  the scan entry points and fail if the `enforce` call is removed. Comment stripping is
  pinned against every quote style, escaped quotes, unterminated blocks, and the obvious
  trap that `https://` contains `//`. Suite: 600 → 631.
- `test_deep_scan_api.py` now seeds a real authorization rather than stubbing the gate,
  so it would notice if the gate disappeared.

## [2.12.5] — Two ways a scan could report clean without having looked

The second deep scan of `cindrasec.com` from the Pi, read the same way: exported
HTML/CSV/SARIF against the dashboard against the source. The scan was clean again —
0 confirmed, 0 needs-review, 0 posture, 0 takeover, and the v2.12.3 fixes all held
(duration agreed across three surfaces, no font was fetched as JavaScript).

The tool did not come out as well. Two separate defects could each produce a CLEAN
verdict from a scan that had not actually examined anything: a scope rule that
discarded the target's own JavaScript before fetching it, and a routing rule that
threw away every generic credential finding when no AI key was configured. Neither
announced itself. A scanner that is wrong loudly costs an hour; one that is wrong
quietly gets written into a client report.

> **On 2.12.4.** There is no released 2.12.4. It existed only as an untagged state
> of `main` that self-reported that version, and this release absorbed it. A build
> reporting 2.12.4 predates the `ai_judged` fix below and should be updated — that
> is exactly the ambiguity a version number exists to prevent, and folding fixes
> into an unreleased version stopped being safe the moment a machine was running it.

### Fixed

- **The scope gate used `str.lstrip("www.")`, which is not prefix removal — every
  target domain beginning with `w` was scanned with no JavaScript coverage at all.**
  `lstrip` strips any leading character present in the *set* `{'w', '.'}`, so
  `"web3forms.com"` became `"eb3forms.com"`, `"walmart.com"` became `"almart.com"`,
  `"wwf.org"` became `"f.org"`. The mangled base then failed to match the target's
  **own hostname**: scanning `walmart.com` asked whether `walmart.com` was in scope
  for `almart.com`, got no, and discarded the asset. Because this gate runs before
  anything is fetched, `extract_js_urls` returned `[]` for such a target — the scan
  read the root HTML and nothing else, then reported CLEAN. A false clean in a paid
  deliverable is the worst failure mode this tool has. Affected: any hostname
  starting with `w` that is not itself `www.`-prefixed — `wix.com`, `wordpress.com`,
  `walmart.com`, `wise.com`, `webflow.com`, `w3.org` among them.

  The same bug fails the other way too: `eb3forms.com` was accepted as in scope for
  a scan of `web3forms.com`, and this gate decides whether a request leaves the
  machine, so anyone registering that domain would receive traffic from an
  authorized scan of someone else's. Both directions are one line.

  All four pre-existing scope tests used `example.com`, where the `lstrip` is a
  no-op; the fixture could not fail. Scope now lives in one place,
  `surface.same_scope`, so the fetch decision and the client report cannot disagree
  about what "in scope" means, and a regression test asserts the property that would
  have caught this immediately: a host is always in its own scope.
- **The robots.txt notice reported one blocked user-agent as a site-wide block.**
  The check was `re.search(r"^disallow:\s*/\s*$", body)` against the whole file, with
  no notion of RFC 9309 groups. A single `User-agent: GPTBot / Disallow: /` — exactly
  what a Cloudflare-managed robots.txt appends — made the scanner announce that the
  target "disallows all crawling" while every general-purpose crawler, Googlebot
  included, was free to fetch the entire site. robots.txt is now parsed into groups;
  only the wildcard group (SecretNode publishes no product token) can trigger the
  warning, path-scoped rules like `Disallow: /src/` correctly do not match the root,
  and `Allow: /` wins the length tie against `Disallow: /` as Google resolves it.
  Named-agent blocks are still reported — as what they are, with the agents named.
  Crawl-delay is now actually read, which the docstring had claimed for some time.
- **The scan ID on screen did not match the report just downloaded.** Every per-host
  sub-scan in a deep scan emits its own `scan_start`, and the dashboard adopted each
  one. The run behind this release displayed `7c19405d…` while all three exports were
  named `6ad578be` — the operator reading an ID aloud to a client would name a scan
  that produced no deliverable.
- **Per-host `scan_start` also cleared the discovered-asset panel mid-run**, throwing
  away assets already found on hosts that started earlier. It survived this run only
  because both hosts started in the same second; at concurrency 1, or with hosts of
  uneven speed, the earlier host's assets are lost. `startScan()` already clears both
  panels before queueing, so the sub-scan clear was never needed.
- **The client report filed the target's own domain under third-party
  infrastructure.** `classify_endpoints` compared hostnames with `host == base_host`,
  so during the `www.cindrasec.com` scan the apex counted as external and landed in
  "Associated hosts (third-party / connected infrastructure)" in the deliverable. The
  same root cause made two hosts serving byte-identical content report 24 endpoints /
  8 associated hosts against 19 / 9, because absolute apex URLs were dropped from the
  in-scope list. Classification is now scope-aware at both the per-host and the
  domain level, and accepts an explicit `scope_hosts` set for targets whose hosts do
  not share a registrable root.

### Found by the new benchmark, and the reason it exists

- **With no Gemini key, every generic `apiKey = "…"` finding was discarded in
  silence.** `validate_finding` returned `is_valid=True, confidence=50` when
  `GEMINI_API_KEY` was unset — a fabricated verdict standing in for one that never
  happened. `classify_validated` read that as an ordinary weak result: structural
  detectors still went to review, but the entropy-gated generic catch-all fell
  through to **drop**. Running without a Gemini key is the documented offline mode
  on the Pi, so the default configuration was losing the single most common shape
  a hardcoded credential takes in real client code — `password: "…"`,
  `token = "…"`, `api_key = "…"` — and reporting the scan clean.

  Fixed with an explicit `ai_judged` flag on `ValidatedFinding`. "The AI said this
  is fake" and "the AI never looked" are different states and must route
  differently; only the first justifies dropping anything. Both now reach a human.

### Added — measurement

- **`bench/groundtruth.py` + `bench/benchmark.py`**: a ground-truth corpus
  covering **all 63 detectors** (the existing `bench/corpus.py` covers 22 and
  stays as the fast `make bench` gate), rendered as a small site — inline script,
  external bundle, vendor bundle, source map, JSON config — so `--http` mode puts
  asset *discovery* in scope. A secret in a bundle the spider never fetched is
  missed exactly as completely as one the regex never matched, and only an
  end-to-end run tells them apart.

  Three ground-truth classes: `secret` (must be found), `public` (must be found
  *and* classified public-by-design), `decoy` (must not be found — git SHAs,
  UUIDs, SRI hashes, inline base64 images, webpack chunk manifests, a CSP nonce).

  The corpus self-validates before it will run, and that has already earned its
  keep twice: it caught a specimen whose declared and embedded values differed
  because the RNG was called twice, and the harness caught two bugs *in itself*
  before either could be reported as a scanner defect — a reimplemented dispatch
  that skipped source-map decoding, and a comparison against uncapped values that
  scored every credential over 80 characters as both a miss and a false positive.

  Every reported figure ships with its own caveat: recall against specimens built
  to satisfy SecretNode's own patterns is **internal validity only**. It proves a
  detector is wired up, not that it catches credentials in the wild. A defensible
  external recall number needs a corpus nobody derived from these regexes.

- **`scanner.scan_asset()`**: the per-asset dispatch (source map → decoded
  originals, anything else → itself) extracted from `run_scan` so the benchmark
  measures the path production takes instead of a copy that can drift from it.

- `make bench-full` and `make bench-http`.

### Added — the guard that would have caught all of this

- **A scan that cannot read the target now says so.** The scope bug above was
  survivable-looking for one reason: nothing announced it. The scanner discarded
  every script, found nothing, and reported CLEAN, and no surface disagreed. The
  spider now raises an ERROR when the scope check rejects a script served by the
  target's **own host** — a thing that cannot be correct under any scope policy, so
  it means the rule is broken and the run's verdict is worthless.

  Deliberately narrower than "every script was rejected": a page that loads only
  third-party analytics rejects all of them and is completely ordinary. Only
  self-rejection is unambiguous, and it is the exact signature the `lstrip` bug
  produced. Verified by restoring the broken rule against a live local target: the
  old rule trips the ERROR and discovers 0 JS assets, the fixed rule is silent and
  discovers 1.

### Also fixed

- **`Fetching [1/3]` was an attempt counter that read as a file counter.** Printed
  once per asset, three identical `[1/3]` lines directly above `3 file(s) to scan`
  look like a counter that is stuck. First attempts now read `Fetching: <url>` and
  only genuine retries carry `Retry 2/3: <url>`.
- **`f"{type(exc).__name__}: {exc}".strip(": ")` in the deep-scan host handler** —
  same family as the scope bug, `strip` taking a character set rather than a
  suffix, so a host error whose message ended in a colon silently lost it. An
  audit of the whole backend for this mistake found only this one other instance.

### Correcting the record

v2.12.3 noted the robots.txt warning under "Noted, not a code change" and said the
tool "was right to raise it". That was too generous to the tool. The served file does
differ from the committed one — that part stands, and the committed file still
produces no match for the old regex. But a file-wide grep cannot establish "disallows
all crawling", so the warning's *conclusion* was not supported by its evidence even on
the run where the observation was real. The finding was luck, not detection.

### Tests

- `test_v2124.py`: 53 tests, `test_groundtruth_bench.py`: 9 tests. The `lstrip` regression pinned with hosts that actually
  trip it, robots.txt group semantics including the exact cindrasec.com file plus
  Cloudflare-style AI blocks, a differential against `urllib.robotparser` over ten
  real-world robots shapes, a 441-pair scope matrix checked against an independently
  written reference, and apex/www classification symmetry asserted rather than
  described. One test guards the guard: it fails if the scope matrix ever stops
  covering the bug it was built for, and the self-rejection guard pinned in both
  directions — it fires when the broken rule is restored, and stays quiet on an
  analytics-only page that legitimately rejects every script it has.
  Suite: 538 → 600.
- `tests/qa_dashboard.py`: browser harness, not a pytest, since it needs Chromium.
  Loads the real dashboard with only `fetch` and `WebSocket` stubbed and replays a
  deep scan's event sequence. Run it when touching the WebSocket handling.

### QA

Each fix was checked against the pre-fix build, because a check that cannot fail on
the old code proves nothing:

- **Dashboard, in Chromium.** The real page, with only `fetch` and `WebSocket`
  stubbed, replaying the exact event sequence of the 2026-08-14 16:11 UTC scan. The
  pre-fix build reproduces `ID: 7c19405d…` — the value in the screenshot that started
  this release — while the fixed build shows the parent ID that names the exports.
  Run again at concurrency 1, the pre-fix build also loses the first host's assets
  (1 URL instead of 2); the live run had escaped that only because both hosts started
  inside the same second. Single-target scans are unaffected in both builds, which is
  the point of the guard.
- **robots.txt over real HTTP**, against a local server serving a Cloudflare-shaped
  file: three AI agents blocked, wildcard group free. Reported as
  "blocks 3 named user-agent(s) … general crawling is permitted", no warning.
- **Differential against `urllib.robotparser`** and the **441-pair scope matrix** are
  now part of the suite rather than a one-off script: ten agreements with the stdlib,
  zero divergences; the fixed scope check agrees with the reference on every pair
  while the pre-fix one disagrees on 11, in both directions.
- **End-to-end scan** of a local target: SSRF guard refused the private address until
  explicitly overridden for lab use, the planted AWS key was detected and correctly
  routed to needs-review with "AI validation skipped — GEMINI_API_KEY not
  configured", the preloaded font was not fetched as JavaScript (v2.12.3 holding),
  and `associated_hosts` listed the two genuine third parties and nothing else.

## [2.12.3] — Three bugs found by scanning our own site from the Pi

A real deep scan of `cindrasec.com` from the Raspberry Pi, with the dashboard read
side-by-side against the downloaded HTML report. The scan itself was clean; the tool
was not.

### Fixed

- **Every preloaded font was downloaded as a candidate JavaScript asset.**
  `_LINK_IS_SCRIPT_RE` treated a bare `rel="preload"` as script-ish, so
  `<link rel="preload" href="inter-var.woff2" as="font">` matched. The scan reported
  "Discovered 4 JS asset(s)" when three of the four were binary font files that cannot
  contain a credential, and fetched them anyway — six wasted downloads across two hosts
  on this run alone. Font preloading is close to universal on modern sites, so this was
  a bandwidth and latency tax on essentially every client scan, paid on a Pi over a
  domestic connection. A `<link>` now counts as a script only when it says so:
  `rel=modulepreload`, or `rel=preload` *with* `as=script`, or an `href` ending `.js`.
- **The dashboard and the report disagreed about the same deep scan.** The report
  correctly said 6 assets analysed over ~14 seconds; the dashboard's tiles said
  "Assets Fetched: 1" and "Last Duration: 0s". `deep_scan_complete` never called
  `updateStats`, so the tiles kept whatever a per-host event had last set. This is the
  same class of defect as the v2.8.0 severity mismatch — two surfaces describing one
  scan and not agreeing — and it is corrosive in a client demo, where the operator is
  reading one number aloud while the deliverable states another.
- **`duration_seconds` and `raw_findings` were missing from the deep-scan event.**
  `totals` is the entire payload of `deep_scan_complete`, so a field absent from it is a
  field the dashboard cannot display, whatever the frontend does. Both are now included,
  and a test asserts the duration in `totals` matches the top-level duration the report
  reads — the two surfaces are no longer *able* to disagree.

### Noted, not a code change

The same scan warned that `cindrasec.com`'s robots.txt disallows all crawling. The
repository's `robots.txt` contains no such directive — verified by running the scanner's
own regex against the committed file — which means the file served at the edge differs
from the one in the repository. Recorded here because the tool was right to raise it and
the discrepancy is real; the cause is for the site's operator to establish, not this
changelog to guess at.

### Tests

- `test_v2123.py`: 9 tests. Font/JSON/CSS/image preloads excluded, every genuine script
  form still collected, and the deep-scan totals contract pinned including the
  cross-surface duration agreement. Suite: 529 → 538.

## [2.12.2] — The self-check reported one timing figure that hid which problem you had

The first real Pi run reported "33.4s per call" and flagged it as too slow to loop over.
A second run moments later, with the model still resident, took 4.8s. The single figure
was conflating two costs with opposite remedies, and the conclusion drawn from it was
wrong.

### Fixed

- **Step 3 now makes two calls and reports both.** The first may include loading the
  model from disk — on a Pi that is tens of seconds and dominates everything. The second
  runs inside the `keep_alive` window with weights already resident, so it measures
  inference alone.

  The distinction decides the architecture. A slow *cold start* is fixed by batching work
  into one session and keeping the model warm. Slow *warm inference* means the model is
  simply too slow for per-item work and the design must avoid it. Measured on a Pi 5 with
  `llama3.2:3b`: ~28.6s load, 4.8s warm, ≈5.2 tokens/sec — the first problem, not the
  second, and the "too slow to loop" warning the original figure produced was a false
  alarm.
- The load cost is now reported explicitly as paid once per idle window, and the
  slow-inference warning is assessed against the warm figure rather than a number that
  includes a one-off cost.

## [2.12.1] — The self-check could not diagnose its own most likely failure

Found on the first real run on the Pi. `python3 -m ops.selfcheck` was invoked with the
system interpreter rather than the project virtualenv, and a tool whose entire purpose is
answering "does this work on this machine" answered with a bare `ModuleNotFoundError`
traceback.

### Fixed

- **A dependency preflight runs before anything third-party is imported.** It names the
  missing module, prints which interpreter is actually running, detects whether a
  virtualenv exists alongside, and prints the exact command to fix it. Wrong-interpreter
  is far and away the most likely failure for this script, since the correct invocation
  requires activating a venv two directories up from where the command is run — so it is
  the one failure it must handle well.
- **Exit code 2 now distinguishes "cannot run" from "ran and failed" (1).** A scheduler
  or a cron wrapper needs to tell a broken environment apart from a failing check; both
  collapsing to non-zero would have hidden a misconfigured deployment behind what looked
  like a service outage.

## [2.12.0] — Verified contact lookup

Built for a specific, expensive failure: an outreach email to
`now@intelligentmachin.es` hard-bounced because the address came from a repeated search
snippet rather than the company's own page. The correct address was sitting in a
`mailto:` link on their website the whole time. That cost a full outreach cycle, and it
is a mechanical failure with a mechanical fix — never accept an address that cannot be
pointed at on a page that was actually fetched.

`python3 -m ops.contacts acme.com` resolves a contact address and cites the page it came
from.

### The division of labour is the design

- **A regex extracts; the model only ranks.** A regex finds every address in a document
  with perfect recall and — the point — *cannot invent one*. Asking a language model to
  "find the contact email" invites it to produce `contact@` + domain: plausible,
  frequently wrong, and it does not look wrong in review.
- **The model is consulted only to break a close tie**, and picks from an enum of
  addresses that were actually found, so an invented address is not expressible. A clear
  winner is never sent to the model — spending 15 seconds of Pi inference to confirm the
  obvious is how an agent becomes slower than doing the job by hand.
- **It works with Ollama switched off.** The model improves a ranking; it is never
  load-bearing for correctness. A model failure falls back to deterministic ranking and
  says so in the result.
- **Every result is grounded anyway.** Extraction came from the fetched documents, so
  `guards.assert_grounded` cannot fail — which is precisely why it is checked rather
  than assumed. "Impossible by construction" is a claim that survives right up until
  someone edits the constructor.

### Ranking

RFC 9116 `security.txt` outranks everything — a published, machine-readable declaration
of where security correspondence goes. Below that: `mailto:` links (someone deliberately
made it clickable), role priority tuned for this use (`security` > `hello`/`contact` >
`support` > `sales` > `marketing`), the company's own domain over freemail, and
`noreply@`/`postmaster@` rejected outright regardless of score. Ties break on the address
itself, so the same input always yields the same recommendation.

### This is browsing, not scanning — and it is enforced

The company's own registrable domain only, a hard page cap, sequential with a delay
between requests, GET only, and links are *followed* rather than guessed — except a short
allowlist of conventional public paths and `/.well-known/security.txt`, which exists to
be read. Deliberately **not** routed through `ops.ledger`: the ledger authorises
*scanning*, and treating "read a company's public contact page" as a scan would make the
signed-RoE gate meaningless by inflating it to cover ordinary browsing. If this module
ever grows a capability that probes rather than reads, that decision must be revisited
first.

### Verified over real HTTP, not only mocked

The unit tests use a mock transport; a live local server was also used to exercise the
real path — content-type handling, encoding, redirects. `security.txt` correctly
outranked the page-level addresses, `noreply@` was dropped, and the chosen address
grounded to the exact page it came from.

### Tests

- `test_ops_contacts.py`: 28 tests, passing first run. Includes the motivating case
  encoded directly — an address present only in a search snippet and absent from the
  company's own site must never be returned, however confident the upstream source was.
  Suite: 501 → 529.

## [2.11.0] — The authorization ledger: turning a promise into a check

"No scan without a signed Rules of Engagement" appears on the website, in the FAQ, in
the process diagram and in every client report. Until now it was enforced by one
careful person remembering. That is adequate for one client and untenable for ten, and
the failure mode is not a bug — it is scanning an organisation that never agreed.

`ops/ledger.py` makes it a check. Nothing in the operations layer may initiate a request
against a target without `assert_authorized` returning cleanly first.

### Added

- **Authorization records** — scope, exclusions, testing window, permitted techniques
  (passive-only / verification / deep scan), the named recipient findings go to, and the
  RoE reference. Stored in a separate `ops.db`, deliberately: scan data is purged 30 days
  after delivery, but the authorization that permitted it is the evidence the scan was
  lawful and must outlive it.
- **Scope matching, written strict and dumb on purpose.** This is the one place in the
  codebase where a subtle bug has legal consequences:
  - *Nothing is inferred.* `acme.test` authorises exactly that host — not `www.acme.test`,
    not subdomains. If the RoE meant subdomains it says `*.acme.test` and so does the
    ledger. Inference is how scope creep happens quietly.
  - *Substring matching is never used.* `notacme.test` ends with `acme.test`;
    `acme.test.evil.net` contains it. Both are denied, and a matcher built on `in` or a
    bare `endswith` allows one or both.
  - *A wildcard does not include the apex.* A host is not a subdomain of itself.
  - *Exclusions beat inclusions, always* — including across engagements, so a host one
    client carved out is not made scannable by another client's scope covering the same
    shared infrastructure.
  - IP and CIDR scopes are supported via `ipaddress`; a hostname is never inside a CIDR.
- **Immediate revocation.** The privacy notice promises a client may withdraw in writing
  at any moment and testing "stops immediately", so status is checked on every decision
  rather than at scan start — an in-flight campaign stops at the next target, not at the
  end of the run.
- **An append-only audit trail.** Every decision, allow or deny, with its reason and the
  rule that matched. "We only scanned what was authorised" is a claim; this is the
  evidence for it.
- **Fails closed everywhere.** Absent database, empty ledger, unparseable target, expired
  window, revoked engagement, no matching rule — all deny. There is no configuration in
  which an unknown host is allowed, and an empty scope list is rejected at construction
  because it is one keystroke from being read as "everything".

### Fixed during development

Two defects the tests surfaced before this shipped, both in how a denial explains itself:

- **A revoked engagement claimed every host in the world.** `evaluate` checked status
  before scope, so a revoked authorization answered "revoked" for hosts it had never
  covered. Wrong, and actively misleading in an audit trail, where it reads as a client
  withdrawing consent for infrastructure that was never theirs. Evaluation is now
  *relevance first*: parse, exclusions, scope membership, and only then status and
  window. An engagement gets to explain a denial only for hosts it actually covers.
- **`evaluate_all` discarded the specific reason.** With several authorizations on
  record, a denial reported "not covered by any of the 3 authorization(s)" even when one
  of them said "revoked" or "expired on 2026-01-31". The specific reason now wins, and
  with several engagements that do not cover the host at all the summary stays generic
  rather than naming one arbitrarily and implying a relationship that does not exist.

### Tests

- `test_ops_ledger.py`: 49 tests. The scope-confusion cases are pinned explicitly —
  `notacme.test`, `acme.test.evil.net`, `evil-acme.test`, apex-vs-wildcard in both
  directions — rather than left to confidence in `endswith`. Suite: 452 → 501.

## [2.10.0] — An operations layer built for a 3B model on a Raspberry Pi

First slice of the agent runtime that will carry Cindrasec's business operations. This
release is the foundation only: the model adapter and the guards that make a small
model's output safe to act on. No business agents yet — those sit on top of this.

The design constraint is the whole story. The target is `llama3.2:3b` on Ollama on a
Pi 5. A 3B model cannot be trusted to reason; it can classify into a few options and
extract a value it can see. So the deterministic Python does the logic and the model
does narrow, bounded, schema-constrained tasks — never the reverse.

"Error-free" is not achieved by making a small model reliable. It is achieved by never
trusting it.

### Added

- **`ops/llm.py` — Ollama adapter.** Uses Ollama's JSON-Schema `format` parameter, so
  generation is grammar-constrained and structurally invalid output cannot be produced
  rather than merely being rejected. The response is nevertheless re-parsed and
  re-validated locally, because a schema can be satisfied by a stream truncated at
  `num_predict`, and because relying on a remote guarantee for a local invariant is how
  silent breakage happens. Pi-tuned throughout: `keep_alive=10m` (loading a 3B model on
  a Pi costs seconds and would otherwise dominate inference), bounded `num_ctx`,
  generous timeouts, `temperature=0` with a fixed seed for reproducibility. Retries vary
  the seed — retrying a deterministic failure with identical inputs reproduces it
  exactly, which on a Pi is an expensively slower way to fail.
- **`ops/guards.py` — grounding.** The layer that matters. A schema constrains shape,
  not truth: `{"email": "contact@acme.com"}` is schema-perfect and may be pure
  invention — and a *plausible* invention, which is worse, because it will not look
  wrong in review. `assert_grounded` inverts the trust: the model does not assert a
  fact, it points at one, and the value must literally appear in a source document that
  was actually fetched. Hallucination becomes structurally unable to pass through rather
  than something a reviewer is asked to catch. Common obfuscations (`[at]`, HTML
  entities, zero-width spaces) are folded so a genuine address written defensively is
  not rejected; nothing requiring a guess about intent is folded, because a false accept
  means outreach to an address nobody reads.
- **`ops/guards.py` — prompt hygiene.** This layer sits next to a scanner whose job is
  finding live credentials. Prompts are scanned before transmission using SecretNode's
  own 63 detectors, and credential-bearing text is refused. Locally that is merely
  correct; the day any of this points at a hosted model it is the difference between
  a working guard and a client-credential disclosure by the security vendor. The
  exception names the credential *types* found and never the values — the message goes
  to logs, and logging a secret to explain that it must not be transmitted would defeat
  the guard.
- **`ops/selfcheck.py` — Pi verification.** The unit tests mock Ollama so they run
  anywhere, which means a green suite says nothing about whether a Pi can actually serve
  this model at a workable speed. `python3 -m ops.selfcheck` talks to the real daemon,
  runs real inference, grounds the result, and reports honest timings. A call slower
  than 20s is flagged: usable one-at-a-time, too slow to loop over a large list, and
  better learned here than from an overnight run.

### Failure philosophy

This layer raises. It never returns a plausible default, never retries into a
fabrication, and never degrades quietly. A caller that cannot reach the model must find
out and decide — queue, fall back to deterministic logic, or stop. A business process
that continues on an invented value is worse than one that halts.

### Verified end to end, not only unit-tested

Run against a stand-in Ollama implementing the real API contract, in three states:

- **Daemon absent** — fails with the actionable message and a non-zero exit.
- **Well-behaved model** — all four stages pass.
- **Hallucinating model** — stage 3 passes (the response *is* schema-valid) and stage 4
  catches it, because the invented address appears nowhere in the source. That single
  run is the entire design argument: schema-validity is not truth.

### Tests

- `test_ops_llm.py` (15) and `test_ops_guards.py` (17). Suite: 420 → 452.
- One bad fixture found and corrected during the run: `AKIAIOSFODNN7EXAMPLE` is AWS's
  own documentation key and is correctly filtered by the placeholder allowlist, so a
  test using it would have exercised the allowlist rather than the guard. A regression
  test now pins that behaviour deliberately — if published example keys ever raised,
  every prompt quoting AWS docs would be refused.

## [2.9.0] — Watch: continuous-monitoring delivery, and the resolution trap

A scan answers "what is exposed right now?". A monitoring subscription has to answer a
different question — **what changed since last time, and does any of it need a human
today?** `backend/watch.py` adds that layer. Pure functions, no network, no database:
`compute_delta` → `classify` → `render_digest`.

### Added

- **Resolved-finding tracking.** SecretNode has always counted `new_findings_count` and
  `recurring_findings_count`; nothing tracked the opposite direction — findings present
  last period and gone now. That omission matters commercially as much as technically,
  because a monitoring subscription proves its worth by showing what got fixed, and the
  data to say so was being discarded.
- **A guard against the resolution trap.** A finding disappears from a scan for two
  reasons that look *identical* in the findings list: someone fixed it, or this run
  simply saw less than the last one (asset 404'd, WAF blocked the fetch, crawl budget
  ran out, scan errored halfway). Only the first is "fixed". Reporting the second to a
  paying client as resolved is a false statement in a deliverable, so resolution is now
  asserted only when the current scan completed *and* its coverage is comparable to the
  previous run (≥50%). Otherwise the disappearances surface as
  `unverified_disappearances` and the digest says plainly that it could not tell. Older
  scan rows predating v2.8.0's `assets_scanned` fall back to `assets_fetched` rather
  than being read as zero coverage, which would have flagged every such comparison as
  an anomaly.
- **Triage that treats a verified credential as urgent regardless of severity.** A
  MEDIUM secret *proven to be an active credential* is a working way in; waiting a month
  to mention it is indefensible. `classify()` returns URGENT / REVIEW / ROUTINE, and a
  coverage anomaly forces REVIEW even when nothing new was found.
- **A client-facing monthly digest** (`render_digest`), deterministic by design — the
  numbers in a paid deliverable come from the data, not from a model's paraphrase of it.
  A clean period is stated plainly rather than left as silence, and every digest carries
  an explicit scope-and-limits section naming what was *not* covered.
- **Persistent high-severity findings get their own section.** A CRITICAL key that has
  survived several monitoring periods is the most important fact in the report and the
  one a client is most likely to have stopped noticing. Rendering it inside a "still
  present: N" count is how it gets ignored for another month.
- **`watch-roster.json`** (gitignored; `watch-roster.example.json` is the committed
  template) lists monitored targets. A missing roster raises rather than running zero
  targets — "monitoring completed, zero targets" is the most dangerous silent failure a
  paid subscription can have. Roster membership is scheduling, not authorization: every
  target still requires a signed RoE.

### Deliberately not done

- **Nothing is sent to a client automatically.** `render_digest` produces a draft for
  human review. Two checkpoints are never automated in this business — the authorization
  to scan at all, and the final severity call on anything critical — and a monitoring
  loop that emailed clients on its own would quietly erase the second one.
- **No LLM in the delta path.** A model may later improve the prose *around* these facts;
  it will not produce the facts.

### Fixed during review

Two defects caught by rendering a realistic digest and reading it as a client would,
which the substring assertions had not caught:

- **Internal triage leaked into the client-facing body.** The header printed
  `**Internal triage:** URGENT` as visible markdown while the triage *reasons* sat in an
  HTML comment marked "remove before sending" — so a reviewer who removed the comment
  still shipped the studio's internal vocabulary to a client. All internal content now
  lives in exactly one block, making its deletion the complete and only step.
- **A persistent CRITICAL finding was rendered as the number `1`.** See above.

### Tests

- `test_watch.py`: 23 tests. The coverage-anomaly cases are the ones that matter — they
  pin the behaviour that stops a false "resolved" claim reaching a deliverable. Also
  covers rotated credentials reading as resolved+new, findings without fingerprints,
  pre-v2.8.0 scan rows, and that internal triage never appears in the visible body.
  Suite: 397 → 420.

## [2.8.3] — A UI/UX and industrial-grade audit

A deliberate broadening of the v2.8.2 audit to the dashboard itself: is it usable on a phone
or tablet (already largely yes — verified, not just assumed), is it usable without a mouse or
with a screen reader (no, in several concrete ways), and does anything else in the served
frontend or its serving path quietly disagree with the truth. Every fix below was verified
against the actual rendered markup / a real HTTP response, not inferred from reading code.

### Fixed

- **The finding-detail modal had no focus management.** Opening it left keyboard focus on
  whatever button triggered it, now hidden behind the overlay; nothing moved focus into the
  dialog, Tab could leave it entirely into background content still notionally covered by the
  overlay, and closing it (Escape, click-outside, or the ✕ button) never returned focus
  anywhere. A keyboard-only user lost their place in the findings table every time they
  inspected a finding. Implemented the WAI-ARIA "Dialog (Modal)" pattern: `role="dialog"`,
  `aria-modal="true"`, `aria-labelledby` pointing at the visible "FINDING DETAIL" heading,
  `aria-label="Close"` on the icon-only ✕ button, focus moved to the dialog on open, a Tab trap
  that cycles between the dialog's first and last focusable elements, and focus restored to
  the original trigger element on close.
- **Toasts, the live scan terminal, and the type filter were invisible to a screen reader or a
  keyboard user.** `#toast-container` had no live region (`role="status" aria-live="polite"`
  added — a scan's success/error toasts previously vanished silently for anyone not looking at
  the screen at that exact moment); `#console-output` had no indication it was a live-updating
  log (`role="log" aria-live="polite"` added); `#target-input`, `#crawl-pages-input`, and
  `#filter-type` had no accessible name beyond a placeholder or adjacent visual text, which is
  not reliably exposed to assistive tech (`aria-label` added to each). `#filter-type` also set
  `outline:none` inline with nothing replacing it, so tabbing to it showed no focus indicator
  at all — a hard WCAG 2.4.7 failure, not a judgment call. Added a global
  `:focus-visible { outline: 2px solid #00ff88 !important }` rule (keyboard-only, not
  mouse-click, and `!important` specifically because inline `outline:none` otherwise wins
  regardless of any external stylesheet's specificity) as a safety net for this element and any
  other interactive control that isn't already handling its own focus state.
- **Eighteen places rendered real information at roughly 2:1 contrast against the background** —
  `#2d4a35`, used as `color` (never as `border-color`, which was left alone — that's a
  decorative button gradient, not text) for the clock, the pipeline-stage label, the
  `ARM64 / RPI5` badge, table row numbers, the "TIME" column, empty-state copy ("No assets
  discovered yet," "No confirmed secrets detected yet"), and four toolbar buttons' resting
  state (COPY / CLR / EXPORT JSON / CLEAR — including their `onmouseout` handlers, which
  reverted to the same broken color after a hover). WCAG AA's floor for this size of text is
  4.5:1; measured contrast against both backgrounds this color appears on was 1.91:1 and
  2.01:1 — not a borderline case. Replaced with `#5a9470` (same muted-green hue, 5.25:1 /
  5.53:1) everywhere it was used as text color.
- **`viewport-fit=cover` was missing from the viewport meta tag**, which is the one thing that
  makes the `env(safe-area-inset-*)` rules already written for `.app-header` and `.app-main`
  do anything — without it, those variables resolve to `0` on iOS Safari and the dashboard's
  dark background stopped short of the notch/home-indicator safe area instead of bleeding
  edge-to-edge under it. The CSS was correct; the one line that activates it was absent.
- **`index.html` hardcodes "2.7.1" in three places** (`<title>`, `#version-line`,
  `#footer-version`) as a static fallback that client-side JS corrects after fetching
  `/api/health` — but that leaves a real, stale version visible in view-source, to crawlers,
  and as a flash on every load until the fetch resolves, five releases after the same class of
  bug was fixed for the footer and boot log in v2.7.9. `main.py` now patches all three at
  import time (the version is fixed for the process's lifetime, so this isn't done per-request)
  before serving `index.html`, on both the `/` route and the SPA-fallback route — the fallback
  was the one place a `FileResponse` was still serving the raw, unpatched file.

### Tests

- `test_frontend_serving.py`: 5 tests covering the version-patching fix at both routes, that a
  real static asset (a font) is still served as itself and not swallowed by the SPA fallback,
  and the response content-type. Suite: 392 → 397. The accessibility, contrast, and
  `viewport-fit` fixes are frontend-only (HTML/CSS/inline JS) — this project has no frontend
  test harness, consistent with how the rest of `frontend/index.html` has always been verified
  (manual QA against a running instance, per the v2.7.9 entry below), not a gap introduced here.

## [2.8.2] — The STOP button did nothing during validation or verification

Found during a general audit: the live-verification stage ran its provider checks
one finding at a time, and while making it concurrent, a test written to prove the
new code still honoured a cancelled scan failed — which led to finding the same,
older bug already sitting in the Gemini-validation stage it was modelled on.

### Fixed
- **Cancelling a scan mid-validation or mid-verification did not stop it.** Both
  stages run each finding's work inside `asyncio.gather(..., return_exceptions=True)`,
  and `state.check()` inside each task raises `asyncio.CancelledError` when the
  user has hit STOP. `return_exceptions=True` does not propagate that
  `CancelledError` out of `gather()` the way it would for `await` used directly —
  it is captured as an ordinary per-task result, same as any other exception.
  Both call sites had a comment naming "cancellation" as a case the fallback
  branch expected to handle, but that branch only checked `isinstance(v,
  ValidatedFinding)` / built a "manual review" placeholder — it could not
  distinguish a cancellation from a real per-item bug, so a STOP request during
  either stage was silently absorbed: the scan kept validating or verifying every
  remaining finding at full cost (Gemini calls, provider API calls) and returned
  a normal result with no indication the user had asked it to stop. Both sites
  now scan their gathered results for `CancelledError` and re-raise it before the
  ordinary per-item fallback logic runs.
- **Live verification of confirmed findings was sequential — one provider API
  round-trip at a time.** A deep scan can confirm findings across dozens of
  hosts; each `--verify` check is an independent network call to that secret's
  own provider (GitHub, Stripe, Slack, …), so there was no reason for the second
  one to wait on the first. Extracted into `verify_confirmed_findings()`,
  concurrent and bounded by the same `semaphore` (`CONCURRENCY_LIMIT`, default
  20) already used for fetches and Gemini validation — the identical pattern
  `_validate_one`/`validation_tasks` already used, which is what surfaced the
  cancellation bug above in the first place.

### Changed
- README's architecture diagram and "Key Design Decisions" table disagreed with
  each other and with the code in four places: the diagram said 54 secret
  patterns, the table implied Gemini 3.1-flash-lite → 3.5-flash, both said the
  frontend used a Tailwind CDN, and the file-structure table said "82-test
  pytest suite." The code says 63 patterns, `gemini-3.5-flash-lite` →
  `gemini-3.6-flash`, no Tailwind (removed — self-hosted CSS, see
  `frontend/index.html`'s own comment), and the test count is now whatever the
  badge at the top of this file says — worded that way specifically so this
  number can't go stale the same way again.

### Tests
- `test_verify_concurrency.py`: 4 tests — concurrent execution actually happens
  (wall-clock bound, not just "doesn't crash"), concurrency is bounded by the
  semaphore, one finding's unexpected verify failure doesn't affect the others,
  and cancellation propagates correctly. The last of these is what caught the
  bug above; it failed against the first implementation. Suite: 388 → 392.

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
