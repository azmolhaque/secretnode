#!/usr/bin/env python3
"""The detector registry: what SecretNode looks for, and nothing about how.

WHY THIS IS ITS OWN MODULE
--------------------------
`scanner.py` reached 5,208 lines, and ~2,000 of them were this: 111 detectors,
their per-provider remediation, and the helpers that build them. That is a
registry — a long, flat, frequently-edited table — sharing a file with HTTP
fetching, an adaptive throttle, an asset cache, AI validation and the scan
orchestrator. Every release touched the table, so every release touched the
file that also owns the network path.

Splitting it is not tidiness. v2.21.0 found six detectors that disagreed with
their issuers, and one of them (the Discord bot token) was wrong *because* the
same calendar fact had been fixed in a sibling detector forty lines away and
not carried across. A registry you can read end to end is a registry where that
kind of inconsistency is visible.

WHAT BELONGS HERE
-----------------
Declarations and the functions that construct them: the `SecretPattern` model,
`_contextual` for keyword-anchored providers, the prefilter derivation, the
patterns themselves and the remediation table. Everything here is pure — no I/O,
no environment reads, no async — and imports only `re` and `dataclasses`.

WHAT DOES NOT
-------------
Entropy scoring, degeneracy tests, redaction, fetching, validation and
orchestration stay in `scanner.py`, which re-exports every public name from
here so `scanner.SECRET_PATTERNS` and friends keep working untouched. Callers
were not asked to care that this moved.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace

_DEFAULT_REMEDIATION = (
    "Treat as compromised: revoke/rotate the credential at the provider "
    "immediately, purge it from the asset and version-control history, and "
    "serve it from a server-side secret manager or environment variable "
    "instead of shipping it in client-side code."
)


@dataclass
class SecretPattern:
    name: str
    regex: re.Pattern[str]
    description: str
    severity: str = "HIGH"
    cwe: str = "CWE-798"                       # Use of Hard-coded Credentials
    remediation: str = _DEFAULT_REMEDIATION
    # Entropy handling differs by detector class:
    #   • Structural/provider detectors (AKIA…, ghp_…, sk_live_…, PEM blocks,
    #     fixed-format hex/UUID tokens) are high-precision by shape. They are
    #     asked only whether the value is degenerate filler — see
    #     looks_degenerate() — which rejects "AKIAAAAAAAAAAAAAAAAA" while still
    #     catching genuinely modest-entropy live keys, because gating these on
    #     the full generic bar silently drops real credentials (a false negative,
    #     the worst failure). That test replaced an absolute 2.5-bit floor, which
    #     did the same job for alphanumerics and dropped 2-5% of real NUMERIC ids
    #     for no reason but the base they are written in.
    #   • The generic keyword=value catch-all matches loosely and needs the full
    #     MIN_ENTROPY_THRESHOLD randomness signal to stay quiet; it opts in below.
    #   • The provider keyword-anchored detectors (`_contextual`) deliberately do
    #     NOT opt in, and the reason is worth recording. They have the same
    #     looseness, so the entropy gate was the obvious answer — and it is the
    #     wrong one. MIN_ENTROPY_THRESHOLD is 3.5 bits, which silently assumes a
    #     ~62-character alphabet: an 18-digit Discord client ID tops out at
    #     log2(10) = 3.32 and can never pass, however random it is. Gating them
    #     dropped four external specimens, every one of them digit- or hex-only.
    #     An absolute bit floor is a category error on a restricted alphabet.
    #     `_contextual` refuses identifiers by shape instead — see its docstring.
    entropy_gated: bool = False
    # Literal substrings, lowercased, of which AT LEAST ONE must appear in an
    # asset for this pattern to have any chance of matching. A necessary
    # condition, never a sufficient one: it decides whether to RUN the regex,
    # never whether a match counts.
    #
    # 108 patterns each make a full pass over every asset, which measured at
    # ~11 ms per pattern per megabyte — and on a real bundle almost none of the
    # provider names are present, so almost every one of those passes is a scan
    # of a megabyte to find nothing. gitleaks carries the same idea in its
    # `Keywords` field for the same reason.
    #
    # Soundness is not taken on trust: `test_prefilters_are_necessary_conditions`
    # asserts that every ground-truth specimen for a prefiltered detector
    # contains one of its literals. An unsound prefilter is a silent false
    # negative, which is the worst failure this scanner has, so the mechanism
    # only earns its place with that check attached.
    prefilter: tuple[str, ...] = ()


# ─────────────────────────────────────────────────────────────────────────────
# Secret Pattern Registry
# ─────────────────────────────────────────────────────────────────────────────

# The loose keyword=value catch-all. Named here because the de-duplication pass
# needs to know which detector is the fallback: when a provider-specific detector
# has already typed a credential, the generic claim on the same value is dropped.
GENERIC_SECRET_TYPE = "Generic High-Entropy Secret"

def _contextual(keyword: str, value: str) -> "re.Pattern[str]":
    """`keyword … = value`, for providers whose value carries no shape at all.

    Asana, Confluent, KuCoin and the rest issue plain runs of alphanumerics.
    Nothing about `a7Fk…` says "Asana", so the provider name within thirty
    characters is the entire discriminator — the same construction as the
    Datadog and Heroku patterns above, factored out because this batch needed
    it eleven times.

    The separator class accepts the quoted form a JS bundle uses AND the bare
    `KEY=value` of a `.env` file or a shell export. Both reach this scanner: an
    exposed `.env` is one of the things it looks for, and gitleaks' own sample
    for Cohere is `export CO_API_KEY=…` with no quotes anywhere. A quote-only
    separator matched the bundle case and silently missed the file case.

    The lookahead refuses a value that CONTAINS the provider keyword, because
    that is a variable name and not a credential. Scanning this release's own
    diff with this scanner reported `linkedInClientId` as a LinkedIn client
    secret: sixteen alphanumerics, sitting exactly where a value goes, and in
    real code an assignment reads `linkedin_secret: linkedInSecret` far more
    often than it holds a literal. Nothing about the length or the alphabet
    separates the two — but a credential that spells its own provider's name
    does not exist, so the name is the discriminator.

    The trailing class also refuses a value that CONTINUES through `.`, `_` or
    `-`. Capturing the front of a longer credential is always wrong, and it
    happened: an Airtable personal access token is `pat` + 14 characters + `.` +
    64 hex, whose first segment is exactly the 17 alphanumerics the legacy
    Airtable key pattern wants. One credential produced two findings, and
    `_collapse_duplicates` could not merge them because the matched substrings
    differ — which is precisely the double-count it exists to prevent.
    """
    return re.compile(
        rf"(?i)(?:{keyword}).{{0,30}}?['\"=:\s](?!\w{{0,40}}?(?:{keyword}))"
        rf"({value})(?![A-Za-z0-9]|[._-][A-Za-z0-9])"
    )


_REGEX_META = set(".^$*+?{}[]\\|()")


def _literal_prefix(alternative: str) -> str:
    """The leading run of ordinary characters in one regex alternative.

    `linked[_-]?in` -> `linked`. Everything from the first metacharacter on is
    dropped, because only the plain prefix is guaranteed to appear verbatim in
    any string the alternative can match.
    """
    out: list[str] = []
    i = 0
    for i, ch in enumerate(alternative):
        if ch in _REGEX_META:
            break
        out.append(ch)
    else:
        i = len(alternative)
    # The last literal character may be the target of the quantifier that
    # stopped the walk, in which case it is optional and must not be required.
    # `https?://` yields `http`, not `https` — the soundness check caught this
    # by finding that the Basic-Auth URL detector would have skipped every
    # `http://user:pass@host`, which is precisely the credential it exists for.
    # `+` is left alone: one-or-more still requires the character once.
    if out and i < len(alternative) and alternative[i] in "?*{":
        out.pop()
    return "".join(out).lower()


def _keyword_prefilter(keyword: str) -> tuple[str, ...]:
    """Literals for a `_contextual` keyword, or () when none is safe.

    The keyword may be an alternation (`cohere|co_api_key`). EVERY branch has to
    yield a literal, because a single branch without one means the pattern can
    match text containing none of the others — and skipping that text would be a
    false negative. All or nothing is the only safe rule here.
    """
    parts = [_literal_prefix(a) for a in keyword.split("|")]
    return tuple(parts) if all(len(part) >= 3 for part in parts) else ()


SECRET_PATTERNS: list[SecretPattern] = [
    SecretPattern(
        name="AWS Access Key",
        # AKIA is only one of the prefixes AWS issues. ASIA is a temporary STS
        # credential and is *more* common in shipped frontend code than a
        # long-lived key, because that is exactly what a browser-side
        # credential-vending flow hands out — so matching only AKIA missed the
        # case most likely to appear on the surface this scanner reads.
        # Measured against gitleaks' corpus, which is where the gap showed up.
        regex=re.compile(r"\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"),
        description="AWS IAM Access Key ID (long-lived, temporary/STS, or service-specific)",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="AWS Bedrock API Key",
        # A 2025 credential type: a long base64 blob prefixed ABSK. Nothing in
        # the AKIA-shaped detectors comes close to matching it.
        regex=re.compile(r"\b((?:ABSK|AXSK)[A-Za-z0-9+/]{109,269}={0,2})"),
        description="Amazon Bedrock long-lived API key",
        severity="CRITICAL",
        remediation=(
            "Delete this Bedrock API key in the AWS console and issue a "
            "replacement held server-side. A leaked key bills model inference to "
            "your account and reaches every foundation model the associated "
            "identity may invoke; never ship one to a browser."
        ),
    ),
    SecretPattern(
        name="AWS Secret Access Key",
        regex=re.compile(
            r"(?i)aws.{0,20}secret.{0,20}['\"]([A-Za-z0-9/+=]{40})['\"]"
        ),
        description="AWS IAM Secret Access Key",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="Google Cloud API Key",
        regex=re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        description="Google Cloud / Firebase API Key",
        severity="HIGH",
    ),
    # Google's CURRENT key format, and the one that actually matters.
    #
    # AI Studio now issues `AQ.`-prefixed keys instead of `AIzaSy…`, and the
    # legacy format is being retired. That inverted this scanner's value on
    # Google: the `AIza` keys it reliably catches are, in real web bundles,
    # overwhelmingly Firebase *web config* keys — public by design, correctly
    # downgraded to INFO — while the `AQ.` keys it could not see at all are live
    # credentials with billing attached. It found the harmless ones and was blind
    # to the dangerous ones.
    #
    # Kept separate from the `AIza` detector rather than folded into it, because
    # the two differ in the way that decides a report: an `AIza` value may be
    # public by design and routinely is, an `AQ.` key never is. One severity and
    # one remediation cannot serve both.
    #
    # SIZING, honestly: Google has published no specification for this format.
    # The bound comes from an observed key — `AQ.` plus 50 base64url characters,
    # mixed case and digits — widened deliberately rather than pinned to that
    # length. Pinning an observed length is exactly what left the OpenAI pattern
    # demanding twenty characters before `T3BlbkFJ` and blind to every `sk-proj-`
    # key Google's counterpart issues today. The 30-character floor is what keeps
    # the short `AQ.` prefix from matching ordinary text; the ceiling is slack.
    #
    # `\b` before `AQ` is load-bearing, not decoration. It is what stops a JWT
    # whose segment happens to end in `AQ` from reading as a key: in
    # `…HUzI1NiAQ.eyJzdWI…` the `A` follows a word character, so no boundary
    # exists and no match is attempted. A real JWT can never open with `AQ.`
    # either — its first segment is base64 of `{"`, always `eyJ`.
    SecretPattern(
        name="Google AI Studio API Key",
        regex=re.compile(r"\b(AQ\.[A-Za-z0-9_-]{30,200})\b"),
        description="Google AI Studio / Gemini API key (AQ. format)",
        severity="CRITICAL",
        remediation=(
            "Delete this key at https://aistudio.google.com/apikey and issue a "
            "replacement held server-side. Unlike a Firebase web apiKey, an AI "
            "Studio key is never public by design: it bills model inference to "
            "the owning project and reaches every model the project can call. "
            "Proxy Gemini calls through your own backend so the key never enters "
            "a browser bundle."
        ),
    ),
    SecretPattern(
        name="Slack Webhook",
        regex=re.compile(
            r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+)"
        ),
        description="Slack Incoming Webhook URL",
        severity="HIGH",
    ),
    SecretPattern(
        name="JWT Token",
        regex=re.compile(
            r"\b(eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=+/]*)\b"
        ),
        description="JSON Web Token",
        severity="HIGH",
    ),
    SecretPattern(
        name="GitHub Personal Access Token",
        regex=re.compile(r"\b(ghp_[A-Za-z0-9]{36})\b"),
        description="GitHub PAT (classic)",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="GitHub OAuth Token",
        regex=re.compile(r"\b(gho_[A-Za-z0-9]{36})\b"),
        description="GitHub OAuth Access Token",
        severity="HIGH",
    ),
    SecretPattern(
        name="Stripe Secret Key",
        # Stripe issues restricted keys (rk_) alongside secret keys, and labels
        # the live environment both `live` and `prod`. Matching only sk_live_
        # missed a restricted key, which is a real credential with a real scope.
        regex=re.compile(r"\b((?:sk|rk)_(?:live|prod)_[0-9a-zA-Z]{24,})\b"),
        description="Stripe Live Secret Key",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="Stripe Test Key",
        regex=re.compile(r"\b((?:sk|rk)_test_[0-9a-zA-Z]{24,})\b"),
        description="Stripe test-mode secret/restricted key",
        severity="LOW",
        remediation=(
            "Roll this test key in the Stripe dashboard and keep it server-side. "
            "It cannot move real money, so this is not an emergency — but it "
            "reveals account structure and is often committed beside the live "
            "key it was copied from, which is the reason to look."
        ),
    ),
    SecretPattern(
        name="Stripe Publishable Key",
        regex=re.compile(r"\b(pk_live_[0-9a-zA-Z]{24,})\b"),
        description="Stripe Live Publishable Key",
        severity="MEDIUM",
    ),
    SecretPattern(
        name="SendGrid API Key",
        regex=re.compile(r"\b(SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43})\b"),
        description="SendGrid API Key",
        severity="HIGH",
    ),
    SecretPattern(
        name="Twilio API Key SID",
        # Twilio's only detector here was the contextual auth token, so an API
        # Key SID — the `SK`-prefixed half of an API key pair — reached nothing.
        # Found by the vendor-shape corpus: a credential built from Twilio's own
        # documented SID layout was reported by no detector at all.
        #
        # HIGH rather than CRITICAL, deliberately. The SID identifies a key; the
        # Key Secret beside it is what authenticates. Reporting it still matters:
        # it names a key that exists, and in a shipped bundle the secret is
        # usually a few characters away.
        regex=re.compile(r"\b(SK[0-9a-fA-F]{32})\b"),
        description="Twilio API Key SID",
        severity="HIGH",
        remediation=(
            "Delete this API key in the Twilio console (Account -> API keys). The "
            "SID alone cannot authenticate, so check the bundle for the Key "
            "Secret that pairs with it before deciding the exposure is limited — "
            "if the secret shipped too, treat the account as compromised and "
            "review message and call logs for traffic you did not send."
        ),
    ),
    SecretPattern(
        name="Twilio Auth Token",
        regex=re.compile(r"(?i)twilio.{0,20}['\"]([0-9a-f]{32})['\"]"),
        description="Twilio Account Auth Token",
        severity="HIGH",
    ),
    SecretPattern(
        name="Private Key Block",
        regex=re.compile(
            r"(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)"
            # A header with nothing behind it is not a key. Empty PEM blocks ship
            # for real — templates that never rendered, fixtures, configs stripped
            # before publication — and each one was reported CRITICAL, because the
            # pattern asked only for the marker. Found by measuring this scanner
            # against gitleaks' declared non-secrets, where the empty OPENSSH block
            # is listed for exactly this reason.
            #
            # The lookahead demands real key material without capturing it: the
            # reported value stays the header alone, so masking, fingerprints and
            # memory are unchanged. The window is 300 characters rather than zero
            # because an encrypted key puts `Proc-Type:` and `DEK-Info:` between
            # the header and its base64, and those must still be found.
            r"(?=[\s\S]{0,300}?[A-Za-z0-9+/]{32})"
        ),
        description="PEM Private Key Block",
        severity="CRITICAL",
        cwe="CWE-321",   # Use of Hard-coded Cryptographic Key
    ),
    SecretPattern(
        name="Heroku API Key",
        regex=re.compile(
            r"(?i)heroku.{0,30}['\"]([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})['\"]"
        ),
        description="Heroku API Key",
        severity="HIGH",
    ),
    SecretPattern(
        name=GENERIC_SECRET_TYPE,
        regex=re.compile(
            r"(?i)(?:api[_-]?key|secret|token|password|passwd|auth)\s*[=:]\s*['\"]([A-Za-z0-9\-_.~+/]{20,80})['\"]"
        ),
        description="Generic credential assignment",
        severity="MEDIUM",
        entropy_gated=True,   # loose keyword=value match — entropy keeps it quiet
    ),
    # A secret hiding behind a build-time "public" prefix.
    #
    # Every SPA bundler inlines a whitelisted env prefix into the shipped bundle:
    # NEXT_PUBLIC_ (Next.js), REACT_APP_ (CRA), VITE_ (Vite), VUE_APP_ (Vue CLI),
    # NUXT_PUBLIC_, GATSBY_, EXPO_PUBLIC_, PUBLIC_ (SvelteKit). The prefix IS the
    # opt-in — it means "ship this to every browser" — and the failure this
    # catches is a developer reading it as a naming convention and putting a real
    # secret behind it. `NEXT_PUBLIC_STRIPE_SECRET_KEY` is not a hypothetical
    # shape; it is the single most common way a live key reaches a bundle today.
    #
    # The name is the whole signal, so this is keyword-anchored and lives here
    # rather than in composite.py — per that module's own rule, a companion
    # carrying its own keyword is an ordinary detector wearing a composite's
    # clothes.
    #
    # WHERE IT IS ACTUALLY FINDABLE, honestly: a fully minified Next.js bundle
    # has already substituted the literal for `process.env.NEXT_PUBLIC_…`, so the
    # name is gone and only the value ships. This detector fires on the forms
    # where the name survives — Angular `environment.ts` object literals compiled
    # verbatim, source maps' `sourcesContent`, unminified and dev builds, served
    # `.env` files, and any config object that enumerates the vars rather than
    # dereferencing them one by one. That is a real and large share of what a
    # crawler meets, but it is not all of it, and claiming otherwise would be the
    # kind of overstatement the benchmark caveat exists to prevent.
    #
    # Only names that DECLARE a secret qualify. `NEXT_PUBLIC_MAPBOX_TOKEN` and
    # `NEXT_PUBLIC_POSTHOG_KEY` are public by design and correctly ignored —
    # matching on "TOKEN" or "KEY" alone would turn this into a false-positive
    # engine on exactly the values the informational bucket exists to clear.
    SecretPattern(
        name="Framework Public Env Secret",
        regex=re.compile(
            r"(?:NEXT_PUBLIC|REACT_APP|VUE_APP|VITE|NUXT_PUBLIC|GATSBY|EXPO_PUBLIC|PUBLIC)"
            r"_[A-Z0-9_]{0,40}"
            r"(?:SECRET|PRIVATE|PASSWORD|PASSWD|SERVICE_ROLE|CLIENT_SECRET)"
            r"[A-Z0-9_]{0,40}"
            # Value charset excludes only quotes, whitespace and angle brackets
            # rather than allowlisting base64: a `_PASSWORD` is routinely full of
            # punctuation, and `hunter2Correct!Horse9Battery` was invisible while
            # this allowlisted `[A-Za-z0-9-_.~+/=]`. The name anchor is strong
            # enough to carry a permissive value — a bundle does not casually
            # contain `REACT_APP_..._SECRET=` beside something harmless.
            r"['\"]?\s*[=:]\s*['\"]([^'\"\s<>]{12,200})['\"]"
        ),
        description="Secret-named value behind a framework's public env prefix",
        severity="HIGH",
        remediation=(
            "This value is inlined into the browser bundle by the build — the "
            "NEXT_PUBLIC_/REACT_APP_/VITE_ prefix is precisely the instruction to "
            "publish it, so every visitor already has it. Treat it as compromised: "
            "rotate it at the provider, then move the call server-side (an API "
            "route or backend-for-frontend) and re-introduce the value WITHOUT the "
            "public prefix so the bundler cannot inline it again."
        ),
    ),
    SecretPattern(
        name="OAuth Client Secret",
        regex=re.compile(
            r"(?i)client[_-]?secret['\"]?\s*[=:]\s*['\"]([A-Za-z0-9\-_.~+/]{16,80})['\"]"
        ),
        description="OAuth 2.0 client secret",
        severity="HIGH",
        remediation=(
            "An OAuth client secret in browser-delivered code lets anyone "
            "impersonate the application to the identity provider and complete "
            "the authorization-code exchange. Rotate the secret at the provider, "
            "and move the exchange server-side — a public SPA client should use "
            "PKCE with no secret at all."
        ),
    ),
    SecretPattern(
        name="Mailgun API Key",
        regex=re.compile(r"\b(key-[0-9a-zA-Z]{32})\b"),
        description="Mailgun API Key",
        severity="HIGH",
    ),
    SecretPattern(
        name="Shopify Access Token",
        regex=re.compile(r"\b(shpat_[A-Za-z0-9]{32})\b"),
        description="Shopify Private App Access Token",
        severity="HIGH",
    ),
    # ── v2.2.0: expanded modern-provider coverage ──────────────────────────
    SecretPattern(
        name="GitHub Fine-Grained PAT",
        regex=re.compile(r"\b(github_pat_[0-9A-Za-z_]{82})\b"),
        description="GitHub fine-grained personal access token",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="GitLab Token (non-PAT)",
        # GitLab issues a whole family beyond glpat-: deploy, feed, runner,
        # pipeline-trigger, OAuth-app, SCIM, agent, incoming-mail, feature-flag,
        # CI job and runner-registration tokens. Only glpat- was matched, so a
        # runner or deploy token — each of which grants real repository or CI
        # access — read as an unrecognised string.
        regex=re.compile(
            r"\b((?:gldt|glft|glrt|glptt|gloas|glsoat|glagent|glimt|glffct|glcbt)"
            r"-[0-9A-Za-z_\-]{20,64}|GR1348941[0-9A-Za-z_\-]{20})\b"
        ),
        description="GitLab deploy / feed / runner / trigger / OAuth / SCIM token",
        severity="HIGH",
        remediation=(
            "Revoke this token in GitLab (Settings → Access Tokens, or the "
            "project's CI/CD settings for runner and deploy tokens) and issue a "
            "replacement stored in a masked CI variable. Depending on type it "
            "grants repository read/write, runner registration, or CI pipeline "
            "execution — none of which belongs in browser-delivered code."
        ),
    ),
    SecretPattern(
        name="GitLab Personal Access Token",
        regex=re.compile(r"\b(glpat-[0-9A-Za-z_\-]{20})\b"),
        description="GitLab personal access token",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="OpenAI API Key",
        # `T3BlbkFJ` is base64 "OpenAI" and sits inside every issued key — it is
        # the discriminator, so the segments around it carry no length promise.
        # Pinning them to exactly 20 was true of the original key format and is
        # not true of the current ones: an `sk-proj-` key runs to ~164
        # characters and an `sk-admin-` key to ~133, so both — the formats
        # OpenAI issues today, and the most commonly leaked AI credential —
        # went undetected. Found by measuring against gitleaks' corpus, whose
        # specimens carry the real marker.
        #
        # The lookahead keeps service-account keys with the detector that names
        # them; without it both would fire on one value and the report would
        # double-count a single credential.
        regex=re.compile(
            r"\b(sk-(?!svcacct-)(?:proj-|admin-)?[A-Za-z0-9_\-]{20,}"
            r"T3BlbkFJ[A-Za-z0-9_\-]{20,})\b"
        ),
        description="OpenAI API key (project or user)",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="Anthropic API Key",
        regex=re.compile(r"\b(sk-ant-[A-Za-z0-9_\-]{20,})\b"),
        description="Anthropic (Claude) API key",
        severity="CRITICAL",
    ),
    # ── AI / ML provider keys ────────────────────────────────────────────────
    # Modern AI stacks leak these constantly: the key is shipped to the browser
    # because a frontend calls the provider directly instead of proxying through
    # a backend. Each pattern below is structural (distinctive prefix + fixed
    # length), so it stays high-precision without the generic entropy gate.
    SecretPattern(
        name="ElevenLabs API Key",
        regex=re.compile(r"\b(sk_[a-f0-9]{48})\b"),
        description="ElevenLabs text-to-speech API key",
        severity="HIGH",
        remediation=(
            "Revoke this key in the ElevenLabs dashboard and issue a replacement. A leaked key "
            "lets anyone consume the account's character quota and credits, generate audio, and "
            "reach private/cloned voice models. Never ship it to the browser: proxy "
            "text-to-speech calls through your own backend so the key stays server-side."
        ),
    ),
    SecretPattern(
        name="Groq API Key",
        regex=re.compile(r"\b(gsk_[A-Za-z0-9]{52})\b"),
        description="Groq inference API key",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="Hugging Face Organization Token",
        # api_org_ is an organisation-wide token; hf_ (below) is per-user. The
        # organisation one has the wider blast radius and was the uncovered one.
        # `[A-Za-z0-9]`, matching the `hf_` detector below. The two were written
        # with different alphabets for the same vendor, which is a defect
        # whichever one is right — and this one is the expensive direction: a
        # random 34-character alphanumeric token contains no digit at all only
        # 0.25% of the time, so a letters-only class misses 99.75% of real org
        # tokens if digits occur.
        #
        # Widened rather than narrowed, deliberately. gitleaks also writes
        # letters-only here, so the evidence is not one-sided and neither source
        # is the issuer. Accepting both costs nothing — letters-only values are a
        # subset — while the `api_org_` prefix keeps precision intact.
        regex=re.compile(r"\b(api_org_[A-Za-z0-9]{34})\b"),
        description="Hugging Face organization API token",
        severity="HIGH",
        remediation=(
            "Revoke this organization token in the Hugging Face settings and "
            "issue a replacement held server-side. It reaches every private "
            "model, dataset and Space the organization owns."
        ),
    ),
    SecretPattern(
        name="Hugging Face Access Token",
        regex=re.compile(r"\b(hf_[A-Za-z0-9]{34,40})\b"),
        description="Hugging Face user access token",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="Replicate API Token",
        regex=re.compile(r"\b(r8_[A-Za-z0-9]{37,45})\b"),
        description="Replicate model-inference API token",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="Perplexity API Key",
        regex=re.compile(r"\b(pplx-[A-Za-z0-9]{32,64})\b"),
        description="Perplexity AI API key",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="xAI API Key",
        regex=re.compile(r"\b(xai-[A-Za-z0-9]{64,100})\b"),
        description="xAI (Grok) API key",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="OpenRouter API Key",
        regex=re.compile(r"\b(sk-or-v1-[a-f0-9]{64})\b"),
        description="OpenRouter aggregated-inference API key",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="LangSmith API Key",
        regex=re.compile(r"\b(lsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10})\b"),
        description="LangSmith / LangChain tracing API key",
        severity="HIGH",
    ),
    SecretPattern(
        name="Pinecone API Key",
        # Pinecone's Admin API reference states "New keys will have the format
        # pckey_<public-label>_<unique-key>" and that the whole string is the
        # credential. Only `pcsk_` was matched here, and that prefix appears in
        # secret-scanning rules rather than in anything Pinecone publishes — so
        # the documented form was the one we could not see. Both are kept: the
        # older prefix is still plausibly live, and dropping it to chase the new
        # one would trade a silent miss for a different silent miss.
        regex=re.compile(r"\b((?:pcsk_|pckey_)[A-Za-z0-9_]{40,90})\b"),
        description="Pinecone vector-database API key",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="Slack Token",
        regex=re.compile(r"\b(xox[baprs]-[0-9A-Za-z\-]{12,72})\b"),
        description="Slack API token (bot/user/app/refresh)",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="npm Access Token",
        regex=re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"),
        description="npm registry access token",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="PyPI Upload Token",
        # `pypi-` + base64url of a PyMacaroon v2 (PyPI's own documented
        # structure). The anchor is the macaroon HEADER — bytes 0x02 0x01,
        # "version 2, location field", which base64 always renders as "AgE".
        #
        # It used to be `AgEIcHlwaS`, which is the base64 of {v2, length 8,
        # "pypi.org"} — one deployment's hostname baked into the pattern. A
        # TestPyPI token encodes "test.pypi.org" instead and begins
        # `AgENdGVzdC5weXBpLm9yZ`, so every one of them was missed. Verified by
        # serializing real macaroons for each location with the library PyPI
        # documents (see bench/vendorshapes.py).
        regex=re.compile(r"\b(pypi-AgE[A-Za-z0-9_\-]{50,})\b"),
        description="PyPI API upload token",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="DigitalOcean PAT",
        regex=re.compile(r"\b(dop_v1_[a-f0-9]{64})\b"),
        description="DigitalOcean personal access token",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="HashiCorp Vault Token",
        regex=re.compile(r"\b(hvs\.[A-Za-z0-9_\-]{24,})\b"),
        description="HashiCorp Vault service token",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="Google OAuth Client Secret",
        # Google states the `GOCSPX-` prefix and nothing about length. The
        # exact `{28}` here came from scanner samples, not from Google, and an
        # unpublished fixed width is precisely how the Mapbox detector came to
        # match zero real tokens. The prefix carries the precision; the width
        # only carried risk, so it is now a range wide enough to be wrong-proof.
        regex=re.compile(r"\b(GOCSPX-[A-Za-z0-9_\-]{20,45})\b"),
        description="Google OAuth 2.0 client secret",
        severity="HIGH",
    ),
    SecretPattern(
        name="Square Access Token",
        regex=re.compile(r"\b(sq0atp-[A-Za-z0-9_\-]{22}|EAAA[A-Za-z0-9_\-]{60})\b"),
        description="Square API access token",
        severity="HIGH",
    ),
    SecretPattern(
        name="Postman API Key",
        regex=re.compile(r"\b(PMAK-[a-f0-9]{24}-[a-f0-9]{34})\b"),
        description="Postman API key",
        severity="HIGH",
    ),
    SecretPattern(
        name="Databricks Token",
        regex=re.compile(r"\b(dapi[a-f0-9]{32})\b"),
        description="Databricks personal access token",
        severity="HIGH",
    ),
    SecretPattern(
        name="Telegram Bot Token",
        # `<bot id>:<secret>`, and BOTH halves were wrong.
        #
        # The bot id is a Telegram USER id, and Telegram documents those as
        # "at most 52 significant bits" while its own changelog warns that
        # ids will grow past 2^31-1. 52 bits is 16 decimal digits; the cap
        # here was 10, which real ids already reach. Same defect family as
        # the Discord snowflake, except Telegram published the fuse.
        #
        # The secret half was pinned to 35. The example token on Telegram's
        # own Bot API page has 34 characters after the colon, so the
        # issuer's published token did not match us — and neither endpoint
        # of a range is something Telegram states, so both are observations:
        # 34 from that example, the ceiling for headroom. The precision
        # comes from the structure (a digit run, a colon, a urlsafe run, all
        # word-boundary delimited), which is where it should come from when
        # the issuer publishes no width.
        regex=re.compile(r"\b([0-9]{8,16}:[A-Za-z0-9_\-]{34,46})\b"),
        description="Telegram Bot API token",
        severity="HIGH",
    ),
    SecretPattern(
        name="Discord Bot Token",
        # `base64url(bot user id).base64url(timestamp).hmac`. The first segment
        # is the bot's SNOWFLAKE, so its width is a function of the calendar —
        # the same fact the Discord Client ID detector was already corrected
        # for, and which was never carried across to the token that embeds it.
        #
        # A 17-digit id base64s to 23 chars, 18 digits to 24, 19 to 26 and 20
        # to 27 (25 is unreachable — 19 bytes is 6 full triples plus one).
        # Hard-coding 24 meant every bot created since ids crossed 19 digits in
        # 2022 — effectively every bot alive — was invisible to this pattern.
        regex=re.compile(
            r"\b([MNO][A-Za-z0-9_\-]{22,26}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,38})\b"),
        description="Discord bot token",
        severity="HIGH",
    ),
    SecretPattern(
        name="Datadog API Key",
        regex=re.compile(r"(?i)datadog.{0,20}['\"]([a-f0-9]{32})['\"]"),
        description="Datadog API key (contextual)",
        severity="HIGH",
    ),
    SecretPattern(
        name="Azure Storage Account Key",
        regex=re.compile(r"AccountKey=([A-Za-z0-9+/=]{88})"),
        description="Azure Storage account key (connection string)",
        severity="CRITICAL",
        cwe="CWE-798",
    ),
    SecretPattern(
        name="Database Connection URI",
        regex=re.compile(
            r"\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://"
            r"[^:@/\s]+:[^@/\s]{3,}@[^\s'\"<>]+)"
        ),
        description="Database URI with embedded username:password",
        severity="CRITICAL",
        cwe="CWE-522",   # Insufficiently Protected Credentials
    ),
    SecretPattern(
        name="Basic-Auth URL Credentials",
        # The character classes exclude JS/JSON string boundaries, not just
        # whitespace. Excluding only `/` and space let a match start inside one
        # string literal and finish inside another:
        #
        #   {"homepage":"https://acme.com","author":"dev@acme.com"}
        #    -> https://acme.com","author":"dev@acme.com   [HIGH, fabricated]
        #
        # That is the shape of every package.json, and any path-less base URL in
        # a config object followed by a support email does the same. A `/` in the
        # URL's path happened to break the run, which is why this survived — the
        # false positive needs a base URL with no path, which is the commonest
        # form a config object holds.
        #
        # RFC 3986 userinfo is unreserved / pct-encoded / sub-delims / ":", so
        # quotes, angle brackets, braces and backslash are excluded by the spec
        # anyway. Comma and semicolon are sub-delims in principle; in shipped
        # JavaScript they mean "the string ended" far more often than they mean
        # "part of a password", and that trade buys back the whole false positive.
        regex=re.compile(
            r"\b(https?://[^:@/\s'\"<>{},;\\]+:[^@/\s'\"<>{},;\\]{3,}@[^\s'\"<>{},;\\]+)"
        ),
        description="Credentials embedded in an HTTP(S) URL",
        severity="HIGH",
        cwe="CWE-522",
    ),
    SecretPattern(
        name="Firebase Cloud Messaging Key",
        regex=re.compile(r"\b(AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140})\b"),
        description="Firebase Cloud Messaging server key",
        severity="HIGH",
    ),
    SecretPattern(
        name="Bearer Token",
        regex=re.compile(r"(?i)bearer\s+([A-Za-z0-9_\-\.=]{24,})"),
        description="HTTP Authorization bearer token (contextual)",
        severity="MEDIUM",
    ),
    SecretPattern(
        name="PGP Private Key Block",
        regex=re.compile(
            r"(-----BEGIN PGP PRIVATE KEY BLOCK-----)"
            # Same empty-block guard as the PEM detector above. A PGP armor
            # header may be followed by `Version:`/`Comment:` lines before the
            # base64 begins, which the 300-character window accommodates.
            r"(?=[\s\S]{0,300}?[A-Za-z0-9+/]{32})"
        ),
        description="PGP private key block",
        severity="CRITICAL",
        cwe="CWE-321",   # Use of Hard-coded Cryptographic Key
        remediation=(
            "Revoke this PGP key, generate a new keypair, and never commit "
            "private key material to a public asset or repository."
        ),
    ),
    # ── v2.3.0: additional modern detectors ────────────────────────────────
    SecretPattern(
        name="Slack App-Level Token",
        regex=re.compile(r"\b(xapp-[0-9]-[A-Z0-9]+-[0-9]+-[a-f0-9]{32,})\b"),
        description="Slack app-level token",
        severity="HIGH",
    ),
    SecretPattern(
        name="GitHub Server/Refresh Token",
        regex=re.compile(r"\b((?:ghs|ghr|ghu)_[A-Za-z0-9]{36})\b"),
        description="GitHub server-to-server / refresh / user-to-server token",
        severity="HIGH",
    ),
    SecretPattern(
        name="OpenAI Service Account Key",
        regex=re.compile(r"\b(sk-svcacct-[A-Za-z0-9_\-]{20,})\b"),
        description="OpenAI service-account API key",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="New Relic API Key",
        regex=re.compile(r"\b(NRAK-[A-Z0-9]{27}|NRAA-[a-f0-9]{27})\b"),
        description="New Relic user / admin API key",
        severity="HIGH",
    ),
    SecretPattern(
        name="Grafana Cloud Access Token",
        # glc_ is Grafana Cloud's access-policy token; glsa_ (below) is a
        # self-hosted service account. Different products, different prefixes —
        # matching only glsa_ left the hosted product uncovered.
        regex=re.compile(r"\b(glc_[A-Za-z0-9+/]{32,400}={0,3})"),
        description="Grafana Cloud access-policy token",
        severity="HIGH",
        remediation=(
            "Revoke this access policy token in Grafana Cloud and issue a "
            "replacement held server-side. It can read and write metrics, logs "
            "and traces for the stacks its policy covers."
        ),
    ),
    SecretPattern(
        name="Grafana Legacy API Key",
        # Base64 of {"k":"… — a JWT-shaped token with no dots, so the JWT
        # detector (which requires the header.payload.signature form) cannot see
        # it. Still issued by older self-hosted installations.
        regex=re.compile(r"\b(eyJrIjoi[A-Za-z0-9+/]{60,400}={0,3})"),
        description="Grafana legacy API key",
        severity="HIGH",
        remediation=(
            "Delete this API key in Grafana and replace it with a service "
            "account token held server-side. Legacy keys carry a fixed role "
            "(Viewer/Editor/Admin) over the whole organisation."
        ),
    ),
    SecretPattern(
        name="Grafana Service Account Token",
        regex=re.compile(r"\b(glsa_[A-Za-z0-9]{32}_[a-f0-9]{8})\b"),
        description="Grafana service-account token",
        severity="HIGH",
    ),
    SecretPattern(
        name="Terraform Cloud Token",
        # The 14-character prefix is MIXED case. HashiCorp's own user-tokens
        # API reference shows `6tL24nM38M7XWQ.atlasv1.…`, which a lowercase-only
        # class rejects — the issuer's published example did not match us.
        regex=re.compile(r"\b([A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_\-]{60,})\b"),
        description="HCP Terraform (Terraform Cloud) API token",
        severity="CRITICAL",
    ),
    # ── v2.4.0: current-generation providers (GitHub/GitGuardian 2026 patterns) ──
    SecretPattern(
        name="Supabase Access Token",
        regex=re.compile(r"\b(sbp_[a-f0-9]{40})\b"),
        description="Supabase personal/management access token",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="Supabase Secret Key",
        regex=re.compile(r"\b(sb_secret_[A-Za-z0-9_\-]{24,})\b"),
        description="Supabase service-role secret key (service_role replacement)",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="Sentry DSN",
        regex=re.compile(
            r"(https://[0-9a-f]{32}@(?:o\d+\.ingest\.)?[a-z0-9.\-]*sentry\.io/\d+)"
        ),
        description="Sentry DSN (allows event/error injection into the project)",
        severity="MEDIUM",
    ),
    SecretPattern(
        name="Linear API Key",
        regex=re.compile(r"\b(lin_api_[A-Za-z0-9]{40})\b"),
        description="Linear API key",
        severity="HIGH",
    ),
    SecretPattern(
        name="Notion Integration Token",
        regex=re.compile(r"\b((?:ntn_|secret_)[A-Za-z0-9]{43,50})\b"),
        description="Notion internal integration token",
        severity="HIGH",
    ),
    SecretPattern(
        name="Doppler Token",
        # Doppler publishes a format per token type. Two things were missing.
        #
        # A SERVICE token carries an optional label (in practice the config
        # name) between the prefix and the random part: `dp.st.prd.<40-44>`,
        # which is the form the docs themselves use. Requiring the random part
        # to follow `dp.st.` directly missed it — and a service token in a CI
        # config is the Doppler credential most likely to leak.
        #
        # `dp.said.` (short-lived service-account identity) was absent. Note it
        # must precede `sa` in the alternation: regex alternation is
        # leftmost-first, so `sa` would match, then demand a `.` it cannot find
        # before the `id`, and the whole match would fail.
        regex=re.compile(
            r"\b(dp\.(?:pt|said|sa|st|ct|scim|audit)\."
            r"(?:[a-z0-9_\-]{2,35}\.)?[A-Za-z0-9]{40,44})\b"),
        description="Doppler service/personal/CLI token",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="PostHog Project API Key",
        regex=re.compile(r"\b(ph[cx]_[A-Za-z0-9]{43})\b"),
        description="PostHog project API key",
        severity="MEDIUM",
    ),
    SecretPattern(
        name="Figma Personal Access Token",
        regex=re.compile(r"\b(figd_[A-Za-z0-9_\-]{40,})\b"),
        description="Figma personal access token",
        severity="HIGH",
    ),
    SecretPattern(
        name="Cloudflare Origin CA Key",
        # A distinct credential from the cfat/cfut/cfk API tokens: it issues
        # origin certificates for any zone on the account.
        regex=re.compile(r"\b(v1\.0-[0-9a-f]{24}-[0-9a-f]{146})\b"),
        description="Cloudflare Origin CA key",
        severity="CRITICAL",
        remediation=(
            "Revoke this Origin CA key in the Cloudflare dashboard and issue a "
            "replacement server-side. It can mint origin certificates for zones "
            "on the account, which enables impersonating your origin."
        ),
    ),
    SecretPattern(
        name="Cloudflare API Token",
        # Split for the same reason as Sourcegraph: the prefixed forms carry
        # their own discriminator, and the common form does not. A Cloudflare API
        # token is 40 characters with no prefix at all, so a pattern demanding
        # `cfat_`/`cfut_`/`cfk_` sees only a minority of them — the vendor-shape
        # corpus reported a plain 40-character token reaching nothing but the
        # generic catch-all. The unprefixed half is below, keyword-anchored,
        # because 40 alphanumerics alone would match half a bundle.
        regex=re.compile(r"\b((?:cfat|cfut|cfk)_[A-Za-z0-9_\-]{32,})\b"),
        description="Cloudflare API token (2026 prefixed format)",
        severity="HIGH",
    ),
    SecretPattern(
        name="Cloudflare API Token (unprefixed)",
        regex=_contextual("cloudflare", r"[A-Za-z0-9_]{40}"),
        prefilter=_keyword_prefilter("cloudflare"),
        description="Cloudflare API token, classic 40-character form (contextual)",
        severity="HIGH",
        remediation=(
            "Roll this token in the Cloudflare dashboard under My Profile -> API "
            "Tokens. Check its permissions while you are there: a token scoped to "
            "Zone:Edit on every zone is the common case and is far broader than "
            "whatever the page needed it for."
        ),
    ),
    SecretPattern(
        name="Cloudflare Global API Key",
        # A different and worse credential from the token above: the global key
        # authenticates as the account itself, cannot be scoped, and is paired
        # with the account email. gitleaks carries it; this registry did not.
        regex=_contextual("cloudflare", r"[a-f0-9]{37}"),
        prefilter=_keyword_prefilter("cloudflare"),
        description="Cloudflare global API key (contextual)",
        severity="CRITICAL",
        remediation=(
            "The global API key authenticates as the whole account and cannot be "
            "scoped — rotate it in the Cloudflare dashboard immediately, then "
            "replace its use with a scoped API token rather than reissuing a "
            "second global key."
        ),
    ),
    SecretPattern(
        name="GCP Service Account Key (JSON)",
        regex=re.compile(
            r'"private_key_id"\s*:\s*"([0-9a-f]{40})"'
        ),
        description="Google Cloud service-account JSON key (private_key_id)",
        severity="CRITICAL",
        cwe="CWE-798",
        remediation=(
            "A leaked service-account JSON key grants API access as that "
            "service account. Disable/delete the key in the GCP console "
            "immediately, rotate to a new key stored server-side, and audit "
            "the account's IAM roles for least privilege."
        ),
    ),

    # ── Providers added from gitleaks' rule definitions (v2.15.0) ────────────
    #
    # Every pattern below is transcribed from gitleaks' own published regex for
    # that provider, not inferred from a single observed sample. That distinction
    # is the whole reason these are safe to add in a batch: the shape is
    # documented by a second project that maintains it, so none of them encodes a
    # length this repository guessed at.
    #
    # They close the largest part of the "provider never claimed" bucket in
    # `make bench-external` — a bucket that is a coverage decision rather than a
    # defect, and was simply never decided.
    SecretPattern(
        name="Adobe Client Secret",
        regex=re.compile(r"\b(p8e-[A-Za-z0-9]{32})\b"),
        description="Adobe OAuth client secret",
        severity="HIGH",
    ),
    SecretPattern(
        name="Alibaba Access Key ID",
        regex=re.compile(r"\b(LTAI[A-Za-z0-9]{20})\b"),
        description="Alibaba Cloud access key ID",
        severity="HIGH",
    ),
    SecretPattern(
        name="Artifactory API Key",
        regex=re.compile(r"\b(AKCp[A-Za-z0-9]{69})\b"),
        description="JFrog Artifactory API key",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="Atlassian API Token",
        regex=re.compile(r"\b(ATATT3xFfGF0[A-Za-z0-9_\-=]{100,250})\b"),
        description="Atlassian (Jira/Confluence) API token",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="Defined Networking API Token",
        regex=re.compile(r"\b(dnkey-[A-Za-z0-9=_\-]{26}-[A-Za-z0-9=_\-]{52})\b"),
        description="Defined Networking API token",
        severity="HIGH",
    ),
    SecretPattern(
        name="Dynatrace API Token",
        regex=re.compile(r"\b(dt0c01\.[A-Za-z0-9]{24}\.[A-Za-z0-9]{64})\b"),
        description="Dynatrace API token",
        severity="HIGH",
    ),
    SecretPattern(
        name="Intra42 Client Secret",
        regex=re.compile(r"\b(s-s4t2(?:ud|af)-[A-Fa-f0-9]{64})\b"),
        description="42 Intra OAuth client secret",
        severity="HIGH",
    ),
    SecretPattern(
        name="PlanetScale API Token",
        regex=re.compile(r"\b(pscale_tkn_[A-Za-z0-9=\.\-_]{32,64})\b"),
        description="PlanetScale API token",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="PlanetScale OAuth Token",
        regex=re.compile(r"\b(pscale_oauth_[A-Za-z0-9=\.\-_]{32,64})\b"),
        description="PlanetScale OAuth token",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="PlanetScale Password",
        regex=re.compile(r"\b(pscale_pw_[A-Za-z0-9=\.\-_]{32,64})\b"),
        description="PlanetScale database password",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="RubyGems API Token",
        regex=re.compile(r"\b(rubygems_[a-f0-9]{48})\b"),
        description="RubyGems push/API token",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="Brevo (Sendinblue) API Token",
        regex=re.compile(r"\b(xkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16})\b"),
        description="Brevo / Sendinblue transactional-email API key",
        severity="HIGH",
    ),

    # ── Providers added from gitleaks' rule definitions (v2.16.0) ────────────
    #
    # The remainder of the "provider never claimed" bucket, plus the four rules
    # this scanner claimed a provider for and still missed. Same rule as the
    # v2.15.0 batch: every shape below is transcribed from gitleaks' published
    # regex rather than inferred from one observed sample.
    #
    # Two deliberate departures from the reference are marked at their pattern.
    # A transcription is not an obligation to copy a pattern this scanner would
    # not otherwise accept.

    # Structure-anchored: a distinctive prefix carries the whole match, so these
    # need no neighbouring keyword and stay high-precision on minified bundles.
    SecretPattern(
        name="Artifactory Reference Token",
        # `cmVmd` is base64 for `refe…` — the token's own prefix, encoded.
        # Separate from the AKCp API key above because Artifactory issues both
        # and they share no shape.
        regex=re.compile(r"\b(cmVmd[A-Za-z0-9]{59})\b"),
        description="JFrog Artifactory reference token",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="GitLab Session Cookie",
        # Not an API token: a live browser session. Anyone holding it acts as
        # the signed-in user until it expires, with no key to revoke.
        regex=re.compile(r"(?i)(_gitlab_session=[0-9a-z]{32})"),
        description="GitLab session cookie",
        severity="CRITICAL",
        cwe="CWE-539",   # Use of Persistent Cookies Containing Sensitive Information
        remediation=(
            "Terminate the session in GitLab (Settings -> Active Sessions) "
            "rather than rotating a key — there is no key. Then find why a "
            "session cookie reached a public asset; it is usually a captured "
            "request pasted into a fixture or a debug log."
        ),
    ),
    SecretPattern(
        name="age Secret Key",
        # Bech32 charset, so the body excludes 1/b/i/o by construction.
        regex=re.compile(r"\b(AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58})\b"),
        description="age file-encryption private key",
        severity="CRITICAL",
        cwe="CWE-321",
        remediation=(
            # The default advice — revoke at the provider — has no meaning here.
            # There is no provider and no revocation: an age key is a local
            # asymmetric key, so exposure is permanent for everything it has
            # already encrypted.
            "There is nothing to revoke: age keys are local, so every file this "
            "key can decrypt must be treated as readable by anyone who saw it. "
            "Generate a new keypair, re-encrypt that data to it, and rotate any "
            "secrets the old ciphertext contained."
        ),
    ),
    SecretPattern(
        name="1Password Service Account Token",
        # `-_` as well as `+/`: gitleaks' class is base64 only, and the same blob
        # travels base64url-encoded wherever it passes through a URL or an env
        # file. A token holding one `-` would otherwise be truncated at it, or
        # dropped outright if the truncation fell short of 250 characters. The
        # `ops_eyJ` prefix is the discriminator, so widening the body costs
        # nothing in precision.
        regex=re.compile(r"\b(ops_eyJ[A-Za-z0-9+/_-]{250,}={0,3})"),
        description="1Password service-account token",
        severity="CRITICAL",
        remediation=(
            "Revoke the service account in 1Password. This token reads every "
            "vault the account was granted, so treat all secrets in those "
            "vaults as exposed and rotate them too."
        ),
    ),
    SecretPattern(
        name="1Password Secret Key",
        # The hyphens are readability only and 1Password strips them at login,
        # but every exported or copied key carries one of these two groupings.
        regex=re.compile(
            r"\b(A3-[A-Z0-9]{6}-(?:[A-Z0-9]{11}|[A-Z0-9]{6}-[A-Z0-9]{5})"
            r"-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5})\b"
        ),
        description="1Password account secret key",
        severity="CRITICAL",
        remediation=(
            "The Secret Key is one of the two factors that derive the account's "
            "encryption key; it cannot be rotated on its own. Change the account "
            "password, which reissues the Secret Key, then re-download the "
            "Emergency Kit. Until that is done, treat every item in the account's "
            "vaults as exposed to anyone who also has the password."
        ),
    ),
    SecretPattern(
        name="Airtable Personal Access Token",
        regex=re.compile(r"\b(pat[A-Za-z0-9]{14}\.[a-f0-9]{64})\b"),
        description="Airtable personal access token",
        severity="CRITICAL",
    ),
    SecretPattern(
        name="Sourcegraph Access Token",
        # DEPARTURE 1, and it is a split rather than a refusal. gitleaks' rule
        # offers three alternatives in one pattern, the third being a bare
        # 40-character hex string. Transcribed as written it would match every
        # Git SHA-1, every sha1 digest and every 40-hex id in a bundle — a rule
        # that fires on every commit hash in a source map costs more trust than
        # the tokens it recovers.
        #
        # But gitleaks does not apply that alternative bare either: its rule
        # carries a `sourcegraph`/`sgp_` keyword precondition and an entropy
        # floor, and this registry has no keyword mechanism of its own. So the
        # two halves are separated instead — the sgp_ forms here, unconditional
        # because the prefix is the discriminator, and the legacy bare-hex form
        # below with the keyword written into the pattern. Same coverage as the
        # reference, same precondition, expressed where this scanner can see it.
        regex=re.compile(
            r"\b(sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}|sgp_[a-fA-F0-9]{40})\b"
        ),
        description="Sourcegraph access token",
        severity="HIGH",
    ),
    SecretPattern(
        name="Sourcegraph Access Token (legacy)",
        regex=_contextual("sourcegraph", r"[a-fA-F0-9]{40}"),
        description="Sourcegraph legacy access token (contextual)",
        severity="HIGH",
        prefilter=_keyword_prefilter("sourcegraph"),
    ),
    # DEPARTURE 2, in the other direction: matched WITHOUT the `mapbox` keyword
    # gitleaks requires, because the `pk.eyJ` / `sk.eyJ` prefix is unambiguous on
    # its own and a bundled map widget rarely names its vendor nearby.
    #
    # The LENGTHS here are this project's, not gitleaks'. Transcribing its
    # `pk\.[a-z0-9]{60}\.[a-z0-9]{22}` literally produced a detector that matched
    # gitleaks' generated samples, scored 100% on both benchmarks, and matched
    # ZERO real tokens — including the one Mapbox publishes in its own
    # documentation, whose payload is 62 characters rather than 60.
    #
    # A Mapbox token is a JWT: `pk.<base64url payload>.<base64url signature>`,
    # and the payload encodes the account name, so its length varies with the
    # account — 59 to 92 across ordinary usernames. A fixed 60 is a snapshot of
    # one generator's output, not a format. Ranges here, with `eyJ` (base64 for
    # `{"`) carrying the precision the fixed length was only pretending to.
    SecretPattern(
        name="Mapbox Public Token",
        regex=re.compile(r"\b(pk\.eyJ[A-Za-z0-9_-]{20,400}\.[A-Za-z0-9_-]{20,86})\b"),
        description="Mapbox public access token (client-side by design)",
        severity="LOW",
        remediation=(
            "A pk. token is Mapbox's client-side token and has to ship in the "
            "browser for a map to render — rotating it is not the fix. Check its "
            "URL restrictions and scopes in the Mapbox account settings so it "
            "cannot be lifted and billed against another site."
        ),
    ),
    SecretPattern(
        name="Mapbox Secret Token",
        # The half gitleaks' rule does not cover, and the one that matters. An
        # sk. token carries account-management scopes — it can read, create and
        # DELETE other tokens — and must never leave a server.
        regex=re.compile(r"\b(sk\.eyJ[A-Za-z0-9_-]{20,400}\.[A-Za-z0-9_-]{20,86})\b"),
        description="Mapbox secret access token",
        severity="CRITICAL",
        remediation=(
            "Delete this token in the Mapbox account settings immediately — a "
            "secret token can enumerate and revoke your other tokens and bills "
            "usage to the account. Issue a replacement held server-side, and "
            "ship a URL-restricted pk. token to the browser instead."
        ),
    ),
    SecretPattern(
        name="GCP Service Account JSON",
        # The `private_key_id` detector above needs that field to be present.
        # This marker survives a JSON that was trimmed to its useful fields, and
        # a service-account document in a shipped bundle is the finding whether
        # or not the key id came with it. HIGH rather than CRITICAL: the marker
        # proves the document, the private_key detector proves the key.
        # Only when the document does NOT also carry a private_key_id. Google's
        # generated JSON opens with `"type"` and reaches `private_key_id` a
        # couple of fields later, so on a complete file the key-id detector
        # above claims it and this one stays silent — one document, one finding.
        # `_collapse_duplicates` cannot do that job here: the two detectors match
        # different substrings, so they are not duplicates by its definition
        # (same URL, same matched value) even though they describe one exposure.
        # The lookahead is what keeps a trimmed document covered without
        # double-reporting a whole one.
        regex=re.compile(
            r'("type"\s*:\s*"service_account")(?![\s\S]{0,600}?"private_key_id")'
        ),
        description="Google Cloud service-account JSON document",
        severity="HIGH",
        cwe="CWE-798",
        remediation=(
            "This marker says a service-account key document is present, whether "
            "or not its private_key survived the trim. Find the account in the "
            "GCP console, delete every key issued to it, and audit its IAM roles "
            "— a service account in a browser bundle usually has far broader "
            "scope than the one call the frontend needed."
        ),
    ),

    # Keyword-anchored. These providers issue values with no distinguishing
    # shape — 16 to 64 alphanumerics — so the provider name within 30 characters
    # is what separates a credential from any other string of that length. Same
    # construction as the Datadog and Heroku patterns above.
    SecretPattern(
        name="Discord Client Secret",
        regex=_contextual("discord", r"[A-Za-z0-9_\-]{32}"),
        description="Discord OAuth client secret (contextual)",
        severity="HIGH",
        prefilter=_keyword_prefilter("discord"),
    ),
    SecretPattern(
        name="Discord Client ID",
        # 17-20, not 18. A Discord ID is a snowflake — `(ms since 2015) << 22` —
        # so its width grows with the calendar and is not a property of the
        # format. gitleaks' 18 held from roughly 2016 to 2021; IDs minted since
        # 2022 are 19 digits, so the transcribed pattern missed every Discord
        # application created in the last four years. Found by computing
        # snowflakes for known dates, not by stumbling on one.
        regex=_contextual("discord", r"[0-9]{17,20}"),
        description="Discord OAuth client ID (public identifier)",
        severity="LOW",
        remediation=(
            # The default text — "treat as compromised, revoke immediately" — is
            # not merely unhelpful here, it is wrong, and wrong advice on a LOW
            # finding is how a reader learns to skim the CRITICAL ones.
            "An OAuth client ID is published in every authorization URL the "
            "application builds — it is not a leak and there is nothing to "
            "revoke. Treat it as a pointer: confirm the matching client SECRET "
            "is not in the same bundle, and that the redirect URIs registered "
            "for this client are restricted to hosts you control."
        ),
        prefilter=_keyword_prefilter("discord"),
    ),
    SecretPattern(
        name="Asana Client Secret",
        regex=_contextual("asana", r"[A-Za-z0-9]{32}"),
        description="Asana OAuth client secret (contextual)",
        severity="HIGH",
        prefilter=_keyword_prefilter("asana"),
    ),
    SecretPattern(
        name="Asana Client ID",
        # A range for the same reason as Discord above: an Asana gid is an
        # allocated numeric id that has been getting longer, so a fixed width is
        # a snapshot of when the reference rule was written. Kept narrower than
        # Discord's, because the growth here is observed rather than derivable
        # from a documented formula.
        regex=_contextual("asana", r"[0-9]{15,19}"),
        description="Asana OAuth client ID (public identifier)",
        severity="LOW",
        remediation=(
            # The default text — "treat as compromised, revoke immediately" — is
            # not merely unhelpful here, it is wrong, and wrong advice on a LOW
            # finding is how a reader learns to skim the CRITICAL ones.
            "An OAuth client ID is published in every authorization URL the "
            "application builds — it is not a leak and there is nothing to "
            "revoke. Treat it as a pointer: confirm the matching client SECRET "
            "is not in the same bundle, and that the redirect URIs registered "
            "for this client are restricted to hosts you control."
        ),
        prefilter=_keyword_prefilter("asana"),
    ),
    SecretPattern(
        name="LinkedIn Client Secret",
        regex=_contextual("linked[_-]?in", r"[A-Za-z0-9]{16}"),
        description="LinkedIn OAuth client secret (contextual)",
        severity="HIGH",
        prefilter=_keyword_prefilter("linked[_-]?in"),
    ),
    SecretPattern(
        name="LinkedIn Client ID",
        regex=_contextual("linked[_-]?in", r"[A-Za-z0-9]{14}"),
        description="LinkedIn OAuth client ID (public identifier)",
        severity="LOW",
        remediation=(
            # The default text — "treat as compromised, revoke immediately" — is
            # not merely unhelpful here, it is wrong, and wrong advice on a LOW
            # finding is how a reader learns to skim the CRITICAL ones.
            "An OAuth client ID is published in every authorization URL the "
            "application builds — it is not a leak and there is nothing to "
            "revoke. Treat it as a pointer: confirm the matching client SECRET "
            "is not in the same bundle, and that the redirect URIs registered "
            "for this client are restricted to hosts you control."
        ),
        prefilter=_keyword_prefilter("linked[_-]?in"),
    ),
    SecretPattern(
        name="Cohere API Token",
        regex=_contextual("cohere|co_api_key", r"[A-Za-z0-9]{40}"),
        description="Cohere API token (contextual)",
        severity="CRITICAL",
        prefilter=_keyword_prefilter("cohere|co_api_key"),
    ),
    SecretPattern(
        name="Confluent Secret Key",
        regex=_contextual("confluent", r"[A-Za-z0-9]{64}"),
        description="Confluent Cloud secret key (contextual)",
        severity="CRITICAL",
        prefilter=_keyword_prefilter("confluent"),
    ),
    SecretPattern(
        name="Confluent Access Token",
        regex=_contextual("confluent", r"[A-Za-z0-9]{16}"),
        description="Confluent Cloud access token (contextual)",
        severity="HIGH",
        prefilter=_keyword_prefilter("confluent"),
    ),
    SecretPattern(
        name="KuCoin Secret Key",
        regex=_contextual(
            "kucoin",
            r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
        ),
        description="KuCoin API secret key (contextual)",
        severity="CRITICAL",
        remediation=(
            "Delete this API key in the KuCoin account settings now, then review "
            "trade and withdrawal history for activity you did not initiate — an "
            "exchange credential can move funds, so rotation alone is not the end "
            "of the incident. Reissue with the narrowest permissions and an IP "
            "allowlist, and never ship one to a browser."
        ),
        prefilter=_keyword_prefilter("kucoin"),
    ),
    SecretPattern(
        name="KuCoin Access Token",
        regex=_contextual("kucoin", r"[a-f0-9]{24}"),
        description="KuCoin API access token (contextual)",
        severity="CRITICAL",
        prefilter=_keyword_prefilter("kucoin"),
    ),
    SecretPattern(
        name="Airtable API Key",
        regex=_contextual("airtable", r"[A-Za-z0-9]{17}"),
        description="Airtable legacy API key (contextual)",
        severity="HIGH",
        prefilter=_keyword_prefilter("airtable"),
    ),
]

# ─────────────────────────────────────────────────────────────────────────────
# Per-provider remediation
# ─────────────────────────────────────────────────────────────────────────────
#
# `_DEFAULT_REMEDIATION` says: revoke at the provider, purge from history, serve
# it from a secret manager. That is sound and it is the advice a reader would
# have given themselves. 79 of 111 detectors shipped it on CRITICAL and HIGH
# findings, which is the difference between a report that names a problem and
# one a person can act on before lunch.
#
# Each entry answers the three questions the default cannot:
#
#   where     the specific console page that revokes this credential
#   reach     what the holder of it can do, so severity is arguable rather
#             than asserted
#   after     what to check for abuse, because rotating a key that was used
#             closes the hole and leaves the damage
#
# Kept as a table rather than inline on each pattern: 79 remediation strings
# spread through a 4,000-line registry cannot be reviewed as a body of writing,
# and consistency of voice across them is the thing a reader notices.
_REMEDIATION: dict[str, str] = {
    # ── Cloud platforms ───────────────────────────────────────────────────
    "AWS Access Key": (
        "Deactivate then delete this key in IAM -> Users -> Security credentials, "
        "and issue a replacement only if nothing can use a role instead. Review "
        "CloudTrail for the key's access-key ID over the whole exposure window — "
        "an AWS key reaches every service its IAM policy allows, and the common "
        "case is far broader than whatever the page needed."
    ),
    "AWS Secret Access Key": (
        "This is the half that authenticates. Deactivate the key pair in IAM "
        "immediately, then read CloudTrail for the matching access-key ID before "
        "assuming it went unused. Prefer a role with a short-lived session over "
        "reissuing a long-lived pair."
    ),
    "Azure Storage Account Key": (
        "Rotate key1/key2 under the storage account's Access keys blade — rotate "
        "one, move clients over, then rotate the other. An account key grants "
        "full control of every container and blob in the account, so check the "
        "storage analytics logs for reads you did not make. A scoped SAS token, "
        "or Entra ID, is what should ship instead."
    ),
    "Google Cloud API Key": (
        "Restrict or regenerate it under APIs & Services -> Credentials. A key "
        "with no application restriction can be called by anyone against the "
        "APIs it enables, billed to your project — check the API quota and "
        "billing report for the exposure period. If it is a browser key, an HTTP "
        "referrer restriction is the fix rather than hiding it."
    ),
    "Google OAuth Client Secret": (
        "Reset it under APIs & Services -> Credentials -> OAuth 2.0 Client IDs. "
        "With the client ID beside it, this secret completes the authorization-"
        "code exchange, so anyone holding both can impersonate your application "
        "to Google and to your own users. A browser-delivered app should be a "
        "public client using PKCE, which has no secret to leak."
    ),
    "Alibaba Access Key ID": (
        "Disable the key pair in the RAM console and check ActionTrail for calls "
        "made with it. The ID alone cannot authenticate, so look for its secret "
        "in the same bundle before deciding the exposure is limited."
    ),
    "DigitalOcean PAT": (
        "Revoke it under API -> Tokens in the DigitalOcean control panel. A "
        "read/write token can create, resize and destroy Droplets, databases and "
        "Spaces across the whole team, so review the account's activity log "
        "before reissuing — and issue the replacement read-only if it only reads."
    ),

    # ── Source control and packages ───────────────────────────────────────
    "GitHub Personal Access Token": (
        "Revoke it under Settings -> Developer settings -> Personal access tokens. "
        "A classic PAT carries its scopes across EVERY repository and "
        "organisation you can reach, so check the account's security log for "
        "clones and pushes in the exposure window. Replace it with a "
        "fine-grained token scoped to the one repository that needed it."
    ),
    "GitHub Fine-Grained PAT": (
        "Revoke it under Settings -> Developer settings -> Personal access tokens "
        "-> Fine-grained. Narrower than a classic PAT, but still check the "
        "security log for the repositories it was granted, and confirm no "
        "workflow or deploy depends on it before deleting."
    ),
    "GitHub OAuth Token": (
        "Revoke the authorisation under Settings -> Applications, which "
        "invalidates the token for that app. Then audit what the app did on your "
        "behalf: an OAuth token acts as you, within the scopes you approved."
    ),
    "GitHub Server/Refresh Token": (
        "Rotate the GitHub App's credentials in its settings page — a "
        "server-to-server token is minted from the app's private key, so "
        "rotating the token alone is not enough if the key also leaked. Review "
        "the installation's audit log for the exposure window."
    ),
    "GitLab Personal Access Token": (
        "Revoke it under Preferences -> Access tokens. Its scopes apply to every "
        "project and group your account can reach, including CI variables, so "
        "check the audit events before reissuing — and prefer a project access "
        "token scoped to one project."
    ),
    "npm Access Token": (
        "Revoke it at npmjs.com under Access Tokens. A publish token can push a "
        "new version of every package you maintain, which is a supply-chain "
        "exposure rather than an account one: check the publish history of each "
        "package for versions you did not release, and enable 2FA for publishing."
    ),
    "PyPI Upload Token": (
        "Revoke it in your PyPI account settings under API tokens. The same "
        "supply-chain reasoning as npm applies — check each project's release "
        "history for files you did not upload, and scope the replacement to a "
        "single project rather than the whole account."
    ),
    "RubyGems API Token": (
        "Revoke it in your RubyGems profile under API keys, then check the "
        "versions page of every gem you own for a release you did not push. "
        "Scope the replacement to the one permission it needs."
    ),
    "Artifactory API Key": (
        "Revoke it in the JFrog platform under your profile's authentication "
        "settings. An Artifactory key reaches every repository your user can "
        "read or deploy to, so review the access log for downloads and uploads "
        "before reissuing as a scoped access token."
    ),
    "Artifactory Reference Token": (
        "Revoke it alongside any API key for the same identity in the JFrog "
        "platform. A reference token is exchanged for a full access token, so "
        "treat it as equivalent to the credential it stands in for."
    ),
    "PlanetScale API Token": (
        "Delete it under Settings -> Service tokens in the PlanetScale "
        "organisation. It can read and modify database branches and deploy "
        "requests, so check the organisation's audit log before issuing a "
        "replacement with narrower accesses."
    ),
    "PlanetScale OAuth Token": (
        "Revoke the OAuth application's grant in the PlanetScale organisation "
        "settings. It acts on behalf of the authorising user, so audit the "
        "branches and deploy requests touched during the exposure window."
    ),
    "PlanetScale Password": (
        "Delete this database password in the branch's Passwords tab and create "
        "a new one. It is a live database credential — check the query insights "
        "and connection history for sessions you did not open, and scope the "
        "replacement to the branch and role that actually needs it."
    ),
    "Sourcegraph Access Token": (
        "Revoke it under User settings -> Access tokens. It reads every "
        "repository the instance has indexed and that your user can see, which "
        "on a company instance is usually all of them — treat exposed source as "
        "the finding, not just the token."
    ),
    "Sourcegraph Access Token (legacy)": (
        "Revoke it under User settings -> Access tokens and reissue in the "
        "current `sgp_` format. The legacy form is a bare hex string, so it is "
        "easy to paste into a config and miss on review."
    ),
    "Intra42 Client Secret": (
        "Regenerate the application's secret in the 42 intranet API settings. "
        "With the client ID it completes the OAuth exchange, so any application "
        "built on it should be treated as impersonable until rotated."
    ),

    # ── Payments and commerce ─────────────────────────────────────────────
    "Stripe Secret Key": (
        "Roll it immediately in the Stripe dashboard under Developers -> API "
        "keys. A live secret key can create charges, issue refunds and read "
        "every customer record — review the Events and Logs pages for API calls "
        "you did not make, and treat the customer data it could read as "
        "disclosed. Restricted keys exist for exactly the narrow jobs a page "
        "usually needs."
    ),
    "Square Access Token": (
        "Revoke it in the Square Developer dashboard for the matching "
        "application, then review the transaction and refund history for the "
        "exposure window. A production token moves real money."
    ),
    "Shopify Access Token": (
        "Uninstall or rotate the app's credentials in the store's Apps and sales "
        "channels settings. The token reads and writes whatever scopes the app "
        "requested — commonly orders and customers — so treat that data as "
        "disclosed and check the store's events log."
    ),
    "KuCoin Access Token": (
        "Delete this API key in the KuCoin account settings now, then review "
        "trade and withdrawal history for activity you did not initiate. An "
        "exchange credential can move funds, so rotation alone is not the end of "
        "the incident — reissue with the narrowest permissions and an IP "
        "allowlist."
    ),
    "Adobe Client Secret": (
        "Rotate it in the Adobe Developer Console for the matching project. With "
        "the client ID it authenticates your integration to Adobe's APIs, so "
        "check the project's usage before reissuing."
    ),

    # ── Messaging and communications ──────────────────────────────────────
    "Slack Token": (
        "Revoke it in the Slack app's OAuth & Permissions page, which "
        "invalidates it workspace-wide. Its scopes decide the reach — a bot "
        "token commonly reads channel history and posts as the app — so review "
        "the workspace's audit log and treat any private channel it could read "
        "as disclosed."
    ),
    "Slack App-Level Token": (
        "Revoke it under Basic Information -> App-Level Tokens. It authorises "
        "Socket Mode connections for the whole app rather than one workspace, so "
        "rotate it before the next deploy and check for connections you did not "
        "open."
    ),
    "Slack Webhook": (
        "Delete the webhook in the Slack app's Incoming Webhooks page and create "
        "a new one. It cannot read anything, but anyone holding it can post into "
        "that channel as your app — which is a convincing phishing primitive "
        "inside a workspace people trust."
    ),
    "SendGrid API Key": (
        "Delete it under Settings -> API Keys and check the Activity feed and "
        "suppression lists for mail you did not send. A full-access key can send "
        "as any verified sender you own, so treat domain reputation as part of "
        "the damage, and scope the replacement to Mail Send only."
    ),
    "Mailgun API Key": (
        "Rotate it in the Mailgun dashboard under API Security, then check the "
        "Logs for messages you did not send. Sending as your own verified domain "
        "is what makes this worse than the quota: a phish from your domain "
        "passes SPF and DKIM."
    ),
    "Brevo (Sendinblue) API Token": (
        "Revoke it under SMTP & API -> API keys, then review the email and SMS "
        "logs for traffic you did not send. The key also reads your contact "
        "lists, so treat that data as disclosed."
    ),
    "Twilio Auth Token": (
        "Rotate the auth token in the Twilio console's account settings. With the "
        "Account SID it can send SMS and place calls billed to you, and read "
        "message bodies and call logs — check the Monitor logs for traffic you "
        "did not originate, and use an API Key pair instead of the account token."
    ),
    "Telegram Bot Token": (
        "Revoke it by sending /revoke to BotFather and issuing a new token. "
        "Anyone holding it controls the bot completely: reading every message "
        "sent to it and posting as it in every chat it has joined."
    ),
    "Discord Bot Token": (
        "Reset it in the Discord Developer Portal under the application's Bot "
        "page. The token controls the bot in every guild it has joined, with "
        "whatever intents and permissions were granted — check the audit logs of "
        "those guilds before reissuing."
    ),
    "Discord Client Secret": (
        "Reset it under the application's OAuth2 page. With the client ID it "
        "completes the OAuth exchange, so anyone with both can impersonate your "
        "application to Discord users."
    ),
    "Asana Client Secret": (
        "Reset it in the Asana developer console for the matching app. With the "
        "client ID it completes the OAuth exchange and can act for any user who "
        "authorised the app."
    ),
    "LinkedIn Client Secret": (
        "Regenerate it in the LinkedIn developer portal under the app's Auth "
        "tab. With the client ID it completes the OAuth exchange and can act for "
        "every member who authorised the app."
    ),

    # ── AI and ML providers ───────────────────────────────────────────────
    "OpenAI API Key": (
        "Revoke it at platform.openai.com under API keys and check the Usage "
        "page for spend you did not incur — this is the most commonly abused "
        "class of leaked key, because it is immediately resellable. A browser "
        "that calls OpenAI directly needs a backend proxy instead, since any key "
        "it holds is public by construction."
    ),
    "OpenAI Service Account Key": (
        "Delete the service account's key in the project's settings at "
        "platform.openai.com. A service-account key is not tied to a person, so "
        "nobody notices it being used — check project usage over the whole "
        "exposure window rather than recent days."
    ),
    "Anthropic API Key": (
        "Revoke it in the Anthropic Console under API keys and check Usage for "
        "spend you did not incur. Keys are billed per token and are resold, so "
        "assume it was used if it was public for any length of time; a browser "
        "calling the API directly needs a server-side proxy."
    ),
    "Groq API Key": (
        "Revoke it in the GroqCloud console under API Keys and review usage for "
        "the exposure window. Inference keys are billed and resold."
    ),
    "Hugging Face Access Token": (
        "Revoke it at huggingface.co under Settings -> Access Tokens. A write "
        "token can push to every model, dataset and Space you can write to, "
        "which is a supply-chain exposure — check the commit history of each "
        "before reissuing a read-only token."
    ),
    "Replicate API Token": (
        "Revoke it in your Replicate account settings and check billing for "
        "predictions you did not run. GPU inference is expensive enough that "
        "abuse shows up quickly on the invoice."
    ),
    "Perplexity API Key": (
        "Revoke it in the Perplexity API settings and review usage for the "
        "exposure window. Billed per request and resold like any inference key."
    ),
    "xAI API Key": (
        "Revoke it in the xAI console under API keys and check usage for calls "
        "you did not make."
    ),
    "OpenRouter API Key": (
        "Revoke it at openrouter.ai under Keys. An OpenRouter key spends real "
        "credit across every model it can route to, so check the activity page "
        "and set a credit limit on the replacement."
    ),
    "Cohere API Token": (
        "Revoke it in the Cohere dashboard under API Keys and review usage. "
        "Billed per token like any inference credential."
    ),
    "LangSmith API Key": (
        "Revoke it in LangSmith under Settings -> API Keys. It reads your traces, "
        "which routinely contain the prompts and responses of real users — treat "
        "that as a data disclosure, not only an access one."
    ),
    "Pinecone API Key": (
        "Rotate it in the Pinecone console for the matching project. It reads and "
        "deletes every vector index in that project, and the vectors themselves "
        "are derived from your source data — treat the embedded content as "
        "disclosed."
    ),

    # ── Data, infrastructure and observability ────────────────────────────
    "Database Connection URI": (
        "Change the database password now and check the server's connection and "
        "query logs for sessions you did not open. A connection string in "
        "client-side code is a direct path to the data, so treat every table the "
        "user can read as disclosed until the logs say otherwise — and put the "
        "database behind an API rather than reissuing a reachable credential."
    ),
    "Basic-Auth URL Credentials": (
        "Change the password on the named account and check that service's access "
        "log. Credentials in a URL leak further than most: they appear in browser "
        "history, proxy logs and Referer headers, so assume wider exposure than "
        "the bundle alone."
    ),
    "Private Key Block": (
        "Treat every system trusting this key as compromised. Generate a new "
        "keypair, replace the public half everywhere it is authorised, then "
        "revoke the old one — in that order, so nothing locks out. Check the "
        "authentication logs of each system for sessions you did not open; a "
        "private key gives access without any further secret."
    ),
    "HashiCorp Vault Token": (
        "Revoke it with `vault token revoke` and check the audit device for "
        "paths it read. A Vault token is a key to other keys: every secret its "
        "policies allow must be treated as disclosed and rotated too, which is "
        "usually the larger job."
    ),
    "Terraform Cloud Token": (
        "Revoke it in HCP Terraform under the user or team's Tokens page. It can "
        "read state files — which routinely contain the credentials Terraform "
        "provisioned — and queue applies against real infrastructure. Audit the "
        "workspace run history, and rotate anything the state exposed."
    ),
    "Doppler Token": (
        "Revoke it in the Doppler dashboard under the project's Access tab. A "
        "service token reads every secret in its config, so the exposure is the "
        "whole config rather than this one value — rotate those secrets too."
    ),
    "Supabase Access Token": (
        "Revoke it in the Supabase dashboard under Account -> Access Tokens. It "
        "manages every project in your organisation through the Management API, "
        "including database settings and other keys."
    ),
    "Supabase Secret Key": (
        "Rotate it in the project's API settings. A service-role key bypasses "
        "Row Level Security entirely — it reads and writes every row in every "
        "table regardless of policy — so treat the whole database as disclosed "
        "and check the logs. The anon key is what belongs in a browser."
    ),
    "Confluent Secret Key": (
        "Delete the API key pair in the Confluent Cloud console and check the "
        "audit log for consumer groups and produce requests you did not create. "
        "It reads and writes the topics its ACLs allow, which means the message "
        "stream itself is the exposure."
    ),
    "Confluent Access Token": (
        "Delete the API key pair in the Confluent Cloud console. The key alone "
        "cannot authenticate, so look for its secret in the same bundle before "
        "deciding the exposure is limited."
    ),
    "Datadog API Key": (
        "Revoke it under Organization Settings -> API Keys. It submits metrics, "
        "logs and events as your organisation, so the risk is poisoned telemetry "
        "and hidden alerts as much as data — check for series you did not send."
    ),
    "New Relic API Key": (
        "Revoke it under API keys in the New Relic account settings. A user key "
        "reads your telemetry and can change alert policies, so check the audit "
        "events for configuration changes as well as reads."
    ),
    "Grafana Service Account Token": (
        "Revoke it under Administration -> Service accounts. Its role decides the "
        "reach: an Editor can change dashboards and alert rules, which is a way "
        "to hide an incident rather than merely observe one."
    ),
    "Dynatrace API Token": (
        "Revoke it in Dynatrace under Access tokens. Its scopes decide the reach, "
        "and token scopes there are commonly far broader than the one endpoint a "
        "page calls — reissue with only the scopes actually used."
    ),
    "Databricks Token": (
        "Revoke it under User Settings -> Developer -> Access tokens. It can run "
        "notebooks and jobs against your clusters and read every table the user "
        "can — treat the data in that workspace as disclosed and check the audit "
        "logs."
    ),
    "Defined Networking API Token": (
        "Revoke it in the Defined Networking admin panel. It manages hosts and "
        "their certificates on your overlay network, so an attacker holding it "
        "can enrol a host of their own — review the host list for enrolments you "
        "did not make."
    ),
    "Cloudflare API Token": (
        "Roll it in the Cloudflare dashboard under My Profile -> API Tokens, and "
        "check the account audit log. Check its permissions while you are there: "
        "a token scoped to Zone:Edit on every zone is the common case and is far "
        "broader than whatever the page needed."
    ),

    # ── Developer tools and SaaS ──────────────────────────────────────────
    "Atlassian API Token": (
        "Revoke it at id.atlassian.com under Security -> API tokens. It acts as "
        "your user across Jira and Confluence, so every issue and page you can "
        "read should be treated as disclosed — check the Atlassian audit log."
    ),
    "Postman API Key": (
        "Revoke it in Postman under Settings -> API keys. It reads your "
        "collections and environments, and environments are where people keep "
        "the credentials for the APIs they are testing — treat those as exposed "
        "too."
    ),
    "Linear API Key": (
        "Revoke it in Linear under Settings -> API. It reads and writes every "
        "issue and comment in the workspaces your account can reach."
    ),
    "Notion Integration Token": (
        "Revoke it in the Notion integration's settings. It reaches every page "
        "and database the integration was shared with, so review what is shared "
        "with it before reissuing — that list usually grows without anyone "
        "noticing."
    ),
    "Figma Personal Access Token": (
        "Revoke it in Figma under Settings -> Security -> Personal access tokens. "
        "It reads every file your account can open, and design files routinely "
        "contain unreleased product and real customer data."
    ),
    "Airtable Personal Access Token": (
        "Revoke it at airtable.com/create/tokens. Its scopes and base list decide "
        "the reach, and a token granted to all current and future bases is the "
        "common mistake — treat the records in those bases as disclosed."
    ),
    "Airtable API Key": (
        "Legacy Airtable API keys reach every base your account can see, with no "
        "scoping at all. Delete it in your account settings and replace it with a "
        "personal access token scoped to the one base that needed it."
    ),
    "Heroku API Key": (
        "Regenerate it with `heroku authorizations:rotate` or in Account "
        "Settings. It controls every app in your account — config vars included, "
        "which is where the rest of your secrets live — so rotate those too and "
        "check the app activity feed."
    ),
    "Firebase Cloud Messaging Key": (
        "Revoke it in the Firebase console under Project settings -> Cloud "
        "Messaging. Anyone holding it can send push notifications to every "
        "installed app, which is a phishing channel straight onto your users' "
        "lock screens."
    ),

    # ── Public by design ──────────────────────────────────────────────────
    #
    # These three are classed public-by-design by the triage tier and reported
    # at INFO, and they were still carrying "treat as compromised: revoke the
    # credential immediately". That is the same defect v2.16.1 fixed for OAuth
    # client IDs — advice that is wrong rather than merely unhelpful, on the
    # findings a reader is most likely to skim. Wrong advice on a low-severity
    # line teaches a reader to discount the CRITICAL ones.
    "Stripe Publishable Key": (
        "No action needed: a pk_ key is designed to ship in client code and can "
        "only create payment tokens. Worth one check — confirm the secret half "
        "(sk_) is not in the same bundle, which is the mistake this finding is "
        "usually sitting next to."
    ),
    "Sentry DSN": (
        "No action needed: a DSN is an ingest endpoint meant to be embedded in "
        "the client, and it permits sending events rather than reading them. If "
        "the volume matters, enable rate limiting and spike protection for the "
        "project — a public DSN can be used to flood your quota."
    ),
    "PostHog Project API Key": (
        "No action needed: a phc_ project key is a write-only ingest identifier "
        "intended for browser use and grants no read access to captured data. "
        "Check that it is the project key rather than a personal API key, which "
        "is a different credential and does read."
    ),

    # ── Structural ────────────────────────────────────────────────────────
    "JWT Token": (
        "Revoke the session or key at the issuer named in the token's `iss` "
        "claim — a JWT cannot be invalidated by deleting it from the bundle, "
        "because verification is offline. If it has no expiry it stays valid "
        "until the signing key rotates, which makes rotating that key the real "
        "fix. Check the issuer's logs for use of this subject in the window."
    ),
}


def _alternation_is_nested_below(src: str, depth: int, start: int) -> bool:
    """True if every `|` from `start` onward sits deeper than `depth`.

    This is the whole question a literal prefix turns on, and getting it wrong
    in either direction costs something:

        abcd(?:x|y)   the `|` is inside a group opened AFTER the literal, so
                      every match contains "abcd" — requiring it is sound
        abcd|efgh     the `|` is at the literal's OWN level, so "efgh" matches
                      with no "abcd" in sight — requiring it drops that branch

    "The literal comes before the first `|`" is true of both and therefore
    cannot separate them. Depth can.
    """
    i = start
    while i < len(src):
        ch = src[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "[":                      # a class may contain | harmlessly
            i += 1
            while i < len(src) and src[i] != "]":
                i += 2 if src[i] == "\\" else 1
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "|" and depth <= 0:
            return False
        i += 1
    return True


def _derive_prefilter(pattern: re.Pattern[str]) -> tuple[str, ...]:
    """A mandatory literal read off a prefix-anchored pattern, or ().

    Deliberately timid, because an unsound prefilter is a silent false negative
    and this runs over the whole registry. Conditions, all required:

      * the pattern opens with the usual `(?i)? \b? (` scaffolding and then at
        least four ordinary characters;
      * those characters are not themselves a character class or quantifier;
      * any `|` that follows is NESTED strictly deeper than the literal, so the
        literal is still mandatory. A top-level alternation offers a branch the
        literal never reaches, and skipping text for a literal only SOME
        branches need is exactly the mistake worth being afraid of here.

    That last condition used to be "no `|` anywhere", which was sound but
    refused eleven patterns whose alternation is nested — `sgp_(?:…|…)`,
    `(?:pcsk_|pckey_)…`, `-----BEGIN (?:RSA |EC )?PRIVATE KEY-----` — and a
    prefilter is the difference between running one regex over every asset and
    running it over the few that could possibly match.

    Everything else keeps an empty prefilter and is scanned as before. A
    detector losing a speed-up costs milliseconds; a detector losing a match
    costs the entire point of the tool.
    """
    src = pattern.pattern
    i = 0
    if src.startswith("(?i)"):
        i = 4
    while i < len(src) and src[i] in "(^":
        if src.startswith("(?:", i) or src.startswith("(?=", i) or src.startswith("(?!", i):
            return ()
        i += 1
    if src.startswith("\\b", i):
        i += 2
    while i < len(src) and src[i] in "(":
        i += 1
    # The literal's own level is zero by definition — the groups opened above it
    # are the scaffolding it lives inside, not nesting it is protected by. A `|`
    # at level 0 is a sibling alternative that bypasses the literal entirely,
    # and a `)` dropping below 0 means we have left the literal's group, where
    # an outer `|` can bypass it just as well. Passing the ABSOLUTE depth here
    # instead of 0 is the first thing I got wrong, and it declared `nrak-` a
    # mandatory literal for a pattern whose other branch is `NRAA-…`. Both the
    # `aaaa_x|bbbb_y` counterexample and a ground-truth specimen caught it.
    # A leading alternation of pure literals — `(?:pcsk_|pckey_)`, `(?:ABSK|AXSK)`
    # — is sound when EVERY branch yields one, the same all-or-nothing rule
    # `_keyword_prefilter` uses: one branch without a literal means the pattern
    # can match text containing none of the others.
    if src.startswith("(?:", i) or src.startswith("(", i):
        head = i + (3 if src.startswith("(?:", i) else 1)
        close = src.find(")", head)
        inner = src[head:close] if close != -1 else ""
        if close != -1 and "|" in inner and not any(c in inner for c in "()[]{}"):
            branches = [_literal_prefix(a) for a in inner.split("|")]
            if all(len(b) >= 4 for b in branches) and \
                    _alternation_is_nested_below(src, 0, close + 1):
                return tuple(dict.fromkeys(branches))
        return ()

    literal = _literal_prefix(src[i:])
    if len(literal) < 4:
        return ()
    if not _alternation_is_nested_below(src, 0, i + len(literal)):
        return ()
    return (literal,)


# Fill in prefilters for the prefix-anchored patterns that did not declare one.
# Keyword-anchored detectors set theirs explicitly via `_keyword_prefilter`.
SECRET_PATTERNS = [
    p if (p.prefilter or p.name == GENERIC_SECRET_TYPE)
    else replace(p, prefilter=_derive_prefilter(p.regex))
    for p in SECRET_PATTERNS
]

# Per-provider remediation, applied only where a pattern still carries the
# default. A pattern that defines its own text always wins: the table is a
# backstop for the 79 detectors that had none, not an override of considered
# wording already written beside a detector.
SECRET_PATTERNS = [
    replace(p, remediation=_REMEDIATION[p.name])
    if p.remediation == _DEFAULT_REMEDIATION and p.name in _REMEDIATION
    else p
    for p in SECRET_PATTERNS
]

# Fast name -> pattern lookup (severity / CWE / remediation metadata).
PATTERN_BY_NAME: dict[str, SecretPattern] = {p.name: p for p in SECRET_PATTERNS}
