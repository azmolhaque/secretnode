#!/usr/bin/env python3
"""
Vendor-shape benchmark — the blind spot the other three share.

WHY THIS EXISTS
---------------
`bench/groundtruth.py` builds one specimen per detector and scores 108/108. The
external benchmark scores 99.1% against gitleaks. Both were green while the
Mapbox detector matched **zero real Mapbox tokens**, including the one Mapbox
publishes in its own documentation.

Neither could have caught it, and the reason is structural rather than an
oversight in either:

    ground truth   specimens are generated FROM the registry's own regexes, so a
                   pattern that says 60 characters gets a 60-character specimen
                   and matches it. The corpus cannot disagree with the pattern.

    external       gitleaks' samples come from ITS regex — and this project
                   transcribed that same regex. Two copies of one claim agreeing
                   with each other is not corroboration.

So a detector whose length is simply wrong scores 1.000 on one and 100% on the
other, and finds nothing in the field. That is the worst failure this project
can have: a scan that returns CLEAN because the pattern never could have matched.

WHAT THIS DOES DIFFERENTLY
--------------------------
Every value below is constructed from the ISSUER's documented structure, written
out as an algorithm, with the registry's pattern deliberately not consulted:

    a Discord id is `(milliseconds since 2015-01-01) << 22`  — so its width is a
    function of the calendar, and IDs minted today are 19 digits, not the 18 the
    reference rule hard-codes

    a Mapbox token is a JWT whose payload encodes the ACCOUNT NAME — so its
    length varies per customer, and no fixed width is correct

When a construction and a pattern disagree, the pattern is wrong until someone
shows otherwise. That is the whole point: this corpus owes nothing to the
regexes it tests.

NOTHING HERE IS A CREDENTIAL. Every value is assembled at runtime from a seeded
RNG over the documented alphabet. Nothing authenticates to anything, and no
literal that could trip push protection is committed.
"""

from __future__ import annotations

import base64
import json
import os
import random
import string
import sys
from dataclasses import dataclass

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "bench")

import scanner  # noqa: E402

SEED = 20260905
LOWER = string.ascii_lowercase
UPPER = string.ascii_uppercase
DIGITS = string.digits
ALNUM = string.ascii_letters + string.digits
HEX = "0123456789abcdef"
B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
URLSAFE = ALNUM + "_-"
B64 = ALNUM + "+/"
BECH32 = "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L"

# Discord's epoch, from its own developer documentation.
DISCORD_EPOCH_MS = 1_420_070_400_000


@dataclass(frozen=True)
class Shape:
    """One credential built from its issuer's documented format."""

    expect: str          # the detector that must claim it
    value: str           # constructed here, never copied from a pattern
    source: str          # where the format comes from
    context: str = ""    # keyword-anchored detectors need their keyword


def _snowflake(rng: random.Random, year_ms: int) -> str:
    """Discord/Twitter snowflake: (ms since epoch) << 22, plus worker bits."""
    return str(((year_ms - DISCORD_EPOCH_MS) << 22) | rng.randrange(1 << 22))


def _jwt_token(rng: random.Random, prefix: str, account: str) -> str:
    """Mapbox: `<prefix>.<base64url claims>.<base64url signature>`.

    The claims object carries the account name, which is why the middle segment
    has no fixed length — the property the transcribed pattern got wrong.
    """
    claims = base64.urlsafe_b64encode(
        json.dumps({"u": account, "a": "".join(rng.choice(LOWER + DIGITS) for _ in range(25))})
        .encode()).decode().rstrip("=")
    sig = "".join(rng.choice(URLSAFE) for _ in range(22))
    return f"{prefix}.{claims}.{sig}"


def shapes() -> list[Shape]:
    rng = random.Random(SEED)

    def r(alphabet: str, n: int) -> str:
        return "".join(rng.choice(alphabet) for _ in range(n))

    out: list[Shape] = [
        # ── formats derivable from a published algorithm ──────────────────
        Shape("Discord Client ID", _snowflake(rng, 1_451_606_400_000),
              "snowflake: (ms since 2015-01-01) << 22 — a 2016 application",
              context="discordClientId"),
        Shape("Discord Client ID", _snowflake(rng, 1_756_944_000_000),
              "same formula, an application created today — 19 digits",
              context="discordClientId"),
        Shape("Discord Client ID", _snowflake(rng, 1_893_456_000_000),
              "same formula, 2030 — the width keeps growing",
              context="discordClientId"),
        Shape("Mapbox Public Token", _jwt_token(rng, "pk", "a"),
              "Mapbox JWT, one-character account name (shortest payload)"),
        Shape("Mapbox Public Token", _jwt_token(rng, "pk", "mapbox"),
              "Mapbox JWT, the account name from Mapbox's own doc token"),
        Shape("Mapbox Public Token", _jwt_token(rng, "pk", "acme-corporation-maps-team"),
              "Mapbox JWT, a long account name (longest payload)"),
        Shape("Mapbox Secret Token", _jwt_token(rng, "sk", "acme-maps"),
              "Mapbox secret token — same structure, sk. prefix"),

        # ── formats documented as a fixed layout ─────────────────────────
        Shape("AWS Access Key", "AKIA" + r(B32, 16),
              "AWS: AKIA + 16 base32 characters"),
        Shape("GitHub Personal Access Token", "ghp_" + r(ALNUM, 36),
              "GitHub: ghp_ + 36 alphanumerics"),
        Shape("Stripe Secret Key", "sk_live_" + r(ALNUM, 24),
              "Stripe: sk_live_ + 24 alphanumerics"),
        Shape("Stripe Publishable Key", "pk_live_" + r(ALNUM, 24),
              "Stripe: pk_live_ + 24 alphanumerics"),
        Shape("Google Cloud API Key", "AIza" + r(URLSAFE, 35),
              "Google: AIza + 35 URL-safe characters"),
        Shape("Airtable Personal Access Token", "pat" + r(ALNUM, 14) + "." + r(HEX, 64),
              "Airtable: pat + 14 + '.' + 64 hex"),
        Shape("age Secret Key", "AGE-SECRET-KEY-1" + r(BECH32, 58),
              "age: bech32 of a 32-byte key — 52 data + 6 checksum characters"),
        Shape("1Password Secret Key",
              "A3-" + r(UPPER + DIGITS, 6) + "-" + r(UPPER + DIGITS, 11) + "-"
              + r(UPPER + DIGITS, 5) + "-" + r(UPPER + DIGITS, 5) + "-" + r(UPPER + DIGITS, 5),
              "1Password whitepaper grouping: A3-<6>-<11>-<5>-<5>-<5>"),
        Shape("Sourcegraph Access Token", "sgp_" + r(HEX, 40),
              "Sourcegraph: sgp_ + 40 hex"),
        Shape("Sourcegraph Access Token", "sgp_" + r(HEX, 16) + "_" + r(HEX, 40),
              "Sourcegraph instance-scoped: sgp_<16 hex>_<40 hex>"),
        Shape("Slack Token", "xoxb-" + r(DIGITS, 13) + "-" + r(DIGITS, 13) + "-" + r(ALNUM, 24),
              "Slack: xoxb- + numeric team/bot ids + 24-character secret"),
        Shape("GCP Service Account JSON", '"type": "service_account"',
              "Google's generated service-account JSON opens with this field"),
        Shape("Private Key Block",
              "-----BEGIN RSA PRIVATE KEY-----\n" + r(B64, 64) + "\n"
              + r(B64, 64) + "\n-----END RSA PRIVATE KEY-----",
              "RFC 7468 PEM: armour header, base64 body, armour footer"),
        Shape("GitLab Session Cookie", "_gitlab_session=" + r(HEX, 32),
              "GitLab session cookie: name=value, 32-character value"),
    ]

    # ── Batch added when the corpus went from 16 detectors to most of the
    # registry. Each `source` names where the format comes from. Nothing here is
    # read off this project's own regexes: where a format could not be stated
    # from the issuer's own documentation or specification, the detector is
    # listed in UNDOCUMENTED below instead of being given a guessed shape.
    # A corpus that invents a shape to reach full coverage is the ground-truth
    # corpus again, one indirection further out.

    out += [
        # Git forges — all four prefixes and their lengths are in GitHub's and
        # GitLab's own token documentation.
        Shape("GitHub OAuth Token", "gho_" + r(ALNUM, 36),
              "GitHub: gho_ + 36 alphanumerics"),
        Shape("GitHub Server/Refresh Token", "ghs_" + r(ALNUM, 36),
              "GitHub: ghs_ (server-to-server) + 36"),
        Shape("GitHub Fine-Grained PAT",
              "github_pat_" + r(ALNUM, 22) + "_" + r(ALNUM, 59),
              "GitHub fine-grained PAT: github_pat_ + 22 + '_' + 59"),
        Shape("GitLab Personal Access Token", "glpat-" + r(URLSAFE, 20),
              "GitLab: glpat- + 20"),
        Shape("GitLab Token (non-PAT)", "glrt-" + r(URLSAFE, 20),
              "GitLab runner token: glrt- + 20"),

        # Payments and messaging.
        Shape("Stripe Test Key", "sk_test_" + r(ALNUM, 24),
              "Stripe: sk_test_ + 24"),
        Shape("Slack Webhook",
              "https://hooks.slack.com/services/T" + r(UPPER + DIGITS, 8)
              + "/B" + r(UPPER + DIGITS, 10) + "/" + r(ALNUM, 24),
              "Slack incoming webhook URL layout"),
        Shape("Slack App-Level Token",
              "xapp-1-A" + r(UPPER + DIGITS, 10) + "-" + r(DIGITS, 13) + "-" + r(HEX, 64),
              "Slack app-level token: xapp-1-<app id>-<ts>-<hex>"),
        Shape("SendGrid API Key",
              "SG." + r(URLSAFE, 22) + "." + r(URLSAFE, 43),
              "SendGrid: SG.<22>.<43>"),
        Shape("Telegram Bot Token", r(DIGITS, 10) + ":" + r(URLSAFE, 35),
              "Telegram: <bot id>:<35-character secret>"),

        # AI and ML providers.
        Shape("OpenAI API Key",
              "sk-proj-" + r(URLSAFE, 74) + "T3BlbkFJ" + r(URLSAFE, 74),
              "OpenAI project key: sk-proj- with the T3BlbkFJ marker inside"),
        Shape("OpenAI Service Account Key",
              "sk-svcacct-" + r(URLSAFE, 74) + "T3BlbkFJ" + r(URLSAFE, 74),
              "OpenAI service-account key: sk-svcacct- with the same marker"),
        Shape("Anthropic API Key",
              "sk-ant-api03-" + r(URLSAFE, 93) + "AA",
              "Anthropic: sk-ant-api03- + 93 + AA"),
        Shape("Hugging Face Access Token", "hf_" + r(ALNUM, 34),
              "Hugging Face user token: hf_ + 34"),
        Shape("Hugging Face Organization Token", "api_org_" + r(ALNUM, 34),
              "Hugging Face org token: api_org_ + 34"),
        Shape("Replicate API Token", "r8_" + r(ALNUM, 37),
              "Replicate: r8_ + 37"),
        Shape("Groq API Key", "gsk_" + r(ALNUM, 52),
              "Groq: gsk_ + 52"),
        Shape("xAI API Key", "xai-" + r(ALNUM, 80),
              "xAI: xai- + 80"),
        Shape("OpenRouter API Key", "sk-or-v1-" + r(HEX, 64),
              "OpenRouter: sk-or-v1- + 64 hex"),
        Shape("ElevenLabs API Key", "sk_" + r(HEX, 48),
              "ElevenLabs: sk_ + 48 hex"),
        Shape("Google AI Studio API Key", "AQ." + r(URLSAFE, 50),
              "Google AI Studio: AQ. + base64url body"),

        # Package registries and developer platforms.
        Shape("npm Access Token", "npm_" + r(ALNUM, 36),
              "npm: npm_ + 36"),
        Shape("RubyGems API Token", "rubygems_" + r(HEX, 48),
              "RubyGems: rubygems_ + 48 hex"),
        Shape("DigitalOcean PAT", "dop_v1_" + r(HEX, 64),
              "DigitalOcean: dop_v1_ + 64 hex"),
        Shape("Figma Personal Access Token",
              "figd_" + r(URLSAFE, 40),
              "Figma: figd_ + token body"),
        Shape("Linear API Key", "lin_api_" + r(ALNUM, 40),
              "Linear: lin_api_ + 40"),
        Shape("Notion Integration Token", "secret_" + r(ALNUM, 43),
              "Notion internal integration token: secret_ + 43"),
        Shape("Postman API Key",
              "PMAK-" + r(HEX, 24) + "-" + r(HEX, 34),
              "Postman: PMAK-<24 hex>-<34 hex>"),
        Shape("Databricks Token", "dapi" + r(HEX, 32),
              "Databricks: dapi + 32 hex"),
        Shape("Square Access Token", "sq0atp-" + r(URLSAFE, 22),
              "Square: sq0atp- + 22"),
        Shape("Shopify Access Token", "shpat_" + r(HEX, 32),
              "Shopify: shpat_ + 32 hex"),
        Shape("Mailgun API Key", "key-" + r(HEX, 32),
              "Mailgun: key- + 32 hex"),
        Shape("New Relic API Key", "NRAK-" + r(UPPER + DIGITS, 27),
              "New Relic user key: NRAK- + 27"),
        Shape("Supabase Access Token", "sbp_" + r(HEX, 40),
              "Supabase personal access token: sbp_ + 40 hex"),
        Shape("HashiCorp Vault Token", "hvs." + r(URLSAFE, 90),
              "Vault service token: hvs. + body"),
        Shape("PostHog Project API Key", "phc_" + r(ALNUM, 43),
              "PostHog project key: phc_ + 43"),

        # Observability and infrastructure.
        Shape("Grafana Service Account Token",
              "glsa_" + r(ALNUM, 32) + "_" + r(HEX, 8),
              "Grafana service account: glsa_<32>_<8 hex>"),
        Shape("Grafana Cloud Access Token",
              "glc_" + r(B64, 80) + "=",
              "Grafana Cloud access policy token: glc_ + base64"),
        Shape("Cloudflare API Token (unprefixed)", r(ALNUM + "_", 40),
              "Cloudflare API token: 40 characters, no prefix",
              context="cloudflareApiToken"),
        Shape("Cloudflare Global API Key", r(HEX, 37),
              "Cloudflare global API key: 37 hex",
              context="cloudflareGlobalKey"),
        Shape("Cloudflare Origin CA Key",
              "v1.0-" + r(HEX, 24) + "-" + r(HEX, 146),
              "Cloudflare origin CA key: v1.0-<24 hex>-<146 hex>"),
        Shape("Dynatrace API Token",
              "dt0c01." + r(UPPER + DIGITS, 24) + "." + r(UPPER + DIGITS, 64),
              "Dynatrace: dt0c01.<24>.<64>"),

        # Providers transcribed in v2.15.0, now checked against their issuers.
        Shape("Adobe Client Secret", "p8e-" + r(ALNUM, 32),
              "Adobe: p8e- + 32"),
        Shape("Alibaba Access Key ID", "LTAI" + r(ALNUM, 20),
              "Alibaba Cloud: LTAI + 20"),
        Shape("Artifactory API Key", "AKCp" + r(ALNUM, 69),
              "JFrog Artifactory API key: AKCp + 69"),
        Shape("Artifactory Reference Token", "cmVmd" + r(ALNUM, 59),
              "JFrog reference token: cmVmd (base64 'refe') + 59"),
        Shape("Atlassian API Token", "ATATT3xFfGF0" + r(URLSAFE, 180),
              "Atlassian: ATATT3xFfGF0 + body"),
        Shape("Defined Networking API Token",
              "dnkey-" + r(ALNUM, 26) + "-" + r(ALNUM, 52),
              "Defined Networking: dnkey-<26>-<52>"),
        Shape("Intra42 Client Secret", "s-s4t2ud-" + r(HEX, 64),
              "Intra42: s-s4t2ud- + 64 hex"),
        Shape("PlanetScale API Token", "pscale_tkn_" + r(URLSAFE, 40),
              "PlanetScale service token: pscale_tkn_ + body"),
        Shape("PlanetScale OAuth Token", "pscale_oauth_" + r(URLSAFE, 40),
              "PlanetScale OAuth token: pscale_oauth_ + body"),
        Shape("PlanetScale Password", "pscale_pw_" + r(URLSAFE, 40),
              "PlanetScale database password: pscale_pw_ + body"),
        Shape("Brevo (Sendinblue) API Token",
              "xkeysib-" + r(HEX, 64) + "-" + r(ALNUM, 16),
              "Brevo: xkeysib-<64 hex>-<16>"),
        Shape("1Password Service Account Token", "ops_eyJ" + r(B64, 300),
              "1Password service account: ops_ + base64 of a JSON document"),
        Shape("AWS Bedrock API Key", "ABSK" + r(B64, 150),
              "Amazon Bedrock long-lived API key: ABSK + base64"),

        # Specifications rather than vendor docs — equally independent of this
        # project's regexes, and the right source for a format nobody issues.
        Shape("JWT Token",
              "eyJ" + r(URLSAFE, 30) + "." + "eyJ" + r(URLSAFE, 60) + "." + r(URLSAFE, 43),
              "RFC 7519: three base64url segments, header starting eyJ"),
        Shape("PGP Private Key Block",
              "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG v2\n\n"
              + r(B64, 64) + "\n" + r(B64, 64) + "\n-----END PGP PRIVATE KEY BLOCK-----",
              "RFC 4880 armor: header, optional Version line, base64 body"),
        Shape("Basic-Auth URL Credentials",
              "https://svcacct:" + r(ALNUM, 18) + "@internal.acme-corp.test/v1/ingest",
              "RFC 3986 userinfo: scheme://user:password@host/path"),
        Shape("Database Connection URI",
              "postgresql://appuser:" + r(ALNUM, 20) + "@db.acme-corp.test:5432/production",
              "PostgreSQL libpq connection URI layout"),
        Shape("Bearer Token", "Bearer " + r(URLSAFE, 48),
              "RFC 6750: the Authorization header's bearer scheme"),
        Shape("Sentry DSN",
              "https://" + r(HEX, 32) + "@o" + r(DIGITS, 6)
              + ".ingest.sentry.io/" + r(DIGITS, 7),
              "Sentry DSN layout from its own setup documentation"),
        Shape("GCP Service Account Key (JSON)",
              '{"type": "service_account", "project_id": "acme-prod",'
              ' "private_key_id": "' + r(HEX, 40) + '"}',
              "Google's generated service-account JSON: private_key_id is 40 hex"),
        Shape("Azure Storage Account Key",
              "DefaultEndpointsProtocol=https;AccountName=acmeassets;AccountKey="
              + r(B64, 86) + "==;EndpointSuffix=core.windows.net",
              "Azure connection string — the only form the portal hands the key out in"),

        # Keyword-anchored providers: the value has no shape of its own, so the
        # construction supplies the keyword a real config would.
        Shape("Twilio API Key SID", "SK" + r(HEX, 32),
              "Twilio SID layout: a two-letter type prefix + 32 hex"),
        Shape("Twilio Auth Token", r(HEX, 32),
              "Twilio auth token: 32 hex, documented beside the account SID",
              context="twilioAuthToken"),
        Shape("Datadog API Key", r(HEX, 32),
              "Datadog API key: 32 hex", context="datadogApiKey"),
        Shape("Heroku API Key",
              r(HEX, 8) + "-" + r(HEX, 4) + "-" + r(HEX, 4) + "-"
              + r(HEX, 4) + "-" + r(HEX, 12),
              "Heroku API key: a UUID", context="herokuApiKey"),
        Shape("Discord Client Secret", r(URLSAFE, 32),
              "Discord OAuth client secret: 32 characters",
              context="discordSecret"),
        Shape("Asana Client Secret", r(ALNUM, 32),
              "Asana OAuth client secret: 32 characters", context="asanaSecret"),
        Shape("Asana Client ID", r(DIGITS, 16),
              "Asana gid: an allocated numeric id", context="asanaClientId"),
        Shape("LinkedIn Client Secret", r(ALNUM, 16),
              "LinkedIn client secret: 16 characters", context="linkedInSecret"),
        Shape("LinkedIn Client ID", r(ALNUM, 14),
              "LinkedIn client id: 14 characters", context="linkedInClientId"),
        Shape("Cohere API Token", r(ALNUM, 40),
              "Cohere API key: 40 characters", context="cohereApiKey"),
        Shape("Confluent Secret Key", r(ALNUM, 64),
              "Confluent Cloud secret: 64 characters", context="confluentSecret"),
        Shape("Confluent Access Token", r(ALNUM, 16),
              "Confluent Cloud key: 16 characters", context="confluentAccessToken"),
        Shape("KuCoin Secret Key",
              r(HEX, 8) + "-" + r(HEX, 4) + "-" + r(HEX, 4) + "-"
              + r(HEX, 4) + "-" + r(HEX, 12),
              "KuCoin API secret: a UUID", context="kucoinSecret"),
        Shape("KuCoin Access Token", r(HEX, 24),
              "KuCoin API key: 24 hex", context="kucoinAccessToken"),
        Shape("Airtable API Key", r(ALNUM, 17),
              "Airtable legacy API key: 17 characters", context="airtableApiKey"),
        Shape("Sourcegraph Access Token (legacy)", r(HEX, 40),
              "Sourcegraph legacy token: 40 hex beside the product name",
              context="sourcegraphToken"),
        Shape("AWS Secret Access Key", r(B64, 40),
              "AWS secret access key: 40 base64 characters",
              context="awsSecretAccessKey"),
    ]
    return out


# Detectors with no shape here, and the reason. Listed rather than left silent:
# an uncovered detector is a detector whose pattern has never been checked
# against anything but itself, and that fact belongs in the open where the
# coverage report can print it.
UNDOCUMENTED: dict[str, str] = {
    "Cloudflare API Token":
        "the cfat_/cfut_/cfk_ prefixed form is asserted by this registry and was "
        "not confirmable from Cloudflare's own documentation; writing a shape "
        "from the registry's own prefix would be circular. The common "
        "unprefixed 40-character form IS covered, as its own detector",
    "Generic High-Entropy Secret":
        "no issuer — a keyword=value catch-all, not a credential format",
    "Framework Public Env Secret":
        "no issuer — a bundler naming convention (NEXT_PUBLIC_, VITE_, …)",
    "OAuth Client Secret":
        "no issuer — the generic `client_secret` spelling, shared across providers",
    "Firebase Cloud Messaging Key":
        "legacy FCM server keys are retired; no current issuer format to check against",
    "Google OAuth Client Secret":
        "format not stated by Google beyond a GOCSPX- prefix; needs a doc lookup",
    "Perplexity API Key": "format not independently confirmed; needs a doc lookup",
    "Pinecone API Key": "format not independently confirmed; needs a doc lookup",
    "PyPI Upload Token": "format not independently confirmed; needs a doc lookup",
    "LangSmith API Key": "format not independently confirmed; needs a doc lookup",
    "Doppler Token": "format not independently confirmed; needs a doc lookup",
    "Supabase Secret Key": "format not independently confirmed; needs a doc lookup",
    "Grafana Legacy API Key": "format not independently confirmed; needs a doc lookup",
    "Terraform Cloud Token": "format not independently confirmed; needs a doc lookup",
    "Discord Bot Token": "format not independently confirmed; needs a doc lookup",
    "Discord Client ID": "covered above by the snowflake construction",
}


def _detected(shape: Shape) -> list[str]:
    """Run one shape through the real extraction path."""
    if shape.context:
        asset = f'{shape.context}: "{shape.value}",\n'
    else:
        asset = f'const v = "{shape.value}";\n'
    return [h.secret_type for h in scanner.extract_secrets(
        "vendor", "https://vendor.test", "https://vendor.test/app.js", asset)]


def main() -> int:
    print("Vendor-shape benchmark — credentials built from issuer documentation")
    print("=" * 68)
    all_shapes = shapes()
    missed: list[tuple[Shape, list[str]]] = []
    mistyped: list[tuple[Shape, list[str]]] = []

    for shape in all_shapes:
        got = _detected(shape)
        if not got:
            missed.append((shape, got))
        elif shape.expect not in got:
            mistyped.append((shape, got))

    ok = len(all_shapes) - len(missed) - len(mistyped)

    # Coverage, reported every run. A detector with no shape here has never been
    # checked against anything but itself, and that is the condition the Mapbox
    # defect lived in for a whole release. Printing it keeps the gap a number
    # instead of something only an audit notices.
    covered = {s.expect for s in all_shapes}
    registry = [p.name for p in scanner.SECRET_PATTERNS]
    uncovered = [n for n in registry if n not in covered]
    unexplained = [n for n in uncovered if n not in UNDOCUMENTED]

    print(f"  shapes           {len(all_shapes)}")
    print(f"  detectors        {len(covered)}/{len(registry)} covered   "
          f"({100 * len(covered) / max(1, len(registry)):.0f}%)")
    print(f"  detected         {ok}/{len(all_shapes)}   "
          f"({100 * ok / max(1, len(all_shapes)):.1f}%)")
    print(f"  not matched      {len(missed):>4}   <- the pattern cannot see a real credential")
    print(f"  wrong detector   {len(mistyped):>4}   matched, but attributed elsewhere")
    print(f"  unchecked        {len(uncovered):>4}   no issuer-documented shape "
          f"({len(unexplained)} without a recorded reason)")

    for label, rows in (("NOT MATCHED", missed), ("WRONG DETECTOR", mistyped)):
        if not rows:
            continue
        print()
        print(f"  {label}:")
        for shape, got in rows:
            print(f"    {shape.expect}")
            print(f"      built from: {shape.source}")
            print(f"      reported:   {got or 'nothing'}")

    if uncovered:
        print()
        print("  unchecked detectors, and why:")
        for name in uncovered:
            why = UNDOCUMENTED.get(name, "NO RECORDED REASON — add a shape or a reason")
            print(f"    {name} — {why}")

    print()
    print("  These values owe nothing to the registry's regexes: each is built")
    print("  from the issuer's documented structure. A pattern that disagrees")
    print("  with a construction here is wrong until someone shows otherwise —")
    print("  which is the check the other benchmarks structurally cannot make.")
    if unexplained:
        print()
        print("  A detector with neither a shape nor a recorded reason is the exact")
        print("  condition the Mapbox defect survived in. Add one or the other.")
    return 1 if (missed or mistyped or unexplained) else 0


if __name__ == "__main__":
    raise SystemExit(main())
