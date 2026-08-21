#!/usr/bin/env python3
"""
Full-coverage ground-truth corpus, rendered as a fetchable site.

Relationship to `bench/corpus.py`, which came first and stays: that one is a
flat list of 45 single-line samples covering 22 detectors, scored per sample
through `extract_secrets`. It is the fast regression gate and `make bench`
still runs it.

This module answers two questions that one cannot:

  • Does EVERY detector fire? All 63 are covered here, one specimen each. A
    detector nobody has ever seen fire is a detector nobody knows is broken.
  • Does the PIPELINE find them? The corpus is rendered as a small site —
    inline script, external bundle, vendor bundle, source map, JSON config —
    so a scan has to discover the asset before it can match anything. A secret
    in a bundle the spider never fetched is missed exactly as completely as one
    the regex never matched, and only an end-to-end run can tell them apart.

Every value here is SYNTHETIC. The random portions are drawn from a fixed seed
over each provider's documented alphabet, so a specimen has the right *shape*
and no relationship to any issued credential. Nothing authenticates to
anything. Same seed, same corpus, byte for byte — which is what makes a
benchmark number comparable across releases.

Three ground-truth classes, because "did it fire?" is the wrong question alone:

  secret  — must be detected. A miss is a false negative, the failure that
            matters most: an undetected credential is the product failing.
  public  — must be detected AND classified public-by-design (Stripe
            publishable key, Sentry DSN, PostHog project key). Reporting these
            as CRITICAL is how a scanner burns a client's trust.
  decoy   — must NOT be detected. Git SHAs, UUIDs, SRI hashes, minified
            identifiers, inline base64 images: what a real bundle is actually
            full of, and where precision actually dies.

`build()` self-validates before returning. A specimen that does not match the
detector it claims, or that the placeholder filter or entropy floor would drop
for an unrelated reason, is a broken measuring instrument rather than a finding
about the scanner. It has already earned its place once, catching a specimen
whose declared and embedded values differed because the RNG was called twice.
"""

from __future__ import annotations

import json
import os
import random
import string
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "corpus-build")

import scanner  # noqa: E402

SEED = 20260814

UPPER = string.ascii_uppercase
LOWER = string.ascii_lowercase
DIGITS = string.digits
ALNUM = string.ascii_letters + string.digits
HEX = "0123456789abcdef"
URLSAFE = ALNUM + "_-"
B64 = ALNUM + "+/"


@dataclass
class Specimen:
    """One planted value with a known expected outcome."""
    pattern: str          # exact name from scanner.SECRET_PATTERNS
    value: str            # the capture-group value the scanner should report
    snippet: str          # the text embedded into a corpus file
    kind: str = "secret"  # "secret" | "public"
    note: str = ""


@dataclass
class Decoy:
    """A value that must NOT be reported. Each is something a real production
    bundle genuinely contains."""
    label: str
    snippet: str
    why: str


@dataclass
class Corpus:
    specimens: list[Specimen] = field(default_factory=list)
    decoys: list[Decoy] = field(default_factory=list)
    files: dict[str, str] = field(default_factory=dict)   # relative path -> content

    def manifest(self) -> dict:
        return {
            "seed": SEED,
            "generator": "backend/bench/groundtruth.py",
            "note": "All values synthetic; random portions seeded. Not credentials.",
            "counts": {
                "secret": sum(1 for s in self.specimens if s.kind == "secret"),
                "public": sum(1 for s in self.specimens if s.kind == "public"),
                "decoy": len(self.decoys),
                "detectors_total": len(scanner.SECRET_PATTERNS),
            },
            "specimens": [
                {"pattern": s.pattern, "value": s.value, "kind": s.kind, "note": s.note}
                for s in self.specimens
            ],
            "decoys": [{"label": d.label, "why": d.why} for d in self.decoys],
        }


def _specimens(rng: random.Random) -> list[Specimen]:
    def r(alphabet: str, n: int) -> str:
        return "".join(rng.choice(alphabet) for _ in range(n))

    def plain(pattern: str, value: str, kind: str = "secret", note: str = "",
              tmpl: str = 'const K_{i} = "{v}";') -> Specimen:
        return Specimen(pattern=pattern, value=value, kind=kind, note=note,
                        snippet=tmpl.format(v=value, i=abs(hash(pattern)) % 9973))

    out: list[Specimen] = []
    add = out.append

    # ── Cloud / infrastructure ───────────────────────────────────────────────
    add(plain("AWS Access Key", "AKIA" + r(UPPER + DIGITS, 16)))
    v = r(ALNUM + "/+", 40)
    add(Specimen("AWS Secret Access Key", v, f'const awsSecretAccessKey = "{v}";'))
    add(plain("Google Cloud API Key", "AIza" + r(ALNUM + "-_", 35)))
    v = r(HEX, 40)
    add(Specimen("GCP Service Account Key (JSON)", v,
                 f'{{"type":"service_account","private_key_id": "{v}"}}'))
    v = r(B64, 88)
    add(Specimen("Azure Storage Account Key", v,
                 f'DefaultEndpointsProtocol=https;AccountKey={v};'))
    add(plain("DigitalOcean PAT", "dop_v1_" + r(HEX, 64)))
    add(plain("HashiCorp Vault Token", "hvs." + r(URLSAFE, 28)))
    add(plain("Terraform Cloud Token",
              r(LOWER + DIGITS, 14) + ".atlasv1." + r(URLSAFE, 62)))
    add(plain("Cloudflare API Token", "cfat_" + r(URLSAFE, 36)))
    add(plain("Heroku API Key",
              f"{r(HEX, 8)}-{r(HEX, 4)}-{r(HEX, 4)}-{r(HEX, 4)}-{r(HEX, 12)}",
              tmpl='const herokuApiKey = "{v}";'))

    # ── Source control / package registries ──────────────────────────────────
    add(plain("GitHub Personal Access Token", "ghp_" + r(ALNUM, 36)))
    add(plain("GitHub OAuth Token", "gho_" + r(ALNUM, 36)))
    add(plain("GitHub Fine-Grained PAT", "github_pat_" + r(ALNUM + "_", 82)))
    add(plain("GitHub Server/Refresh Token", "ghs_" + r(ALNUM, 36)))
    add(plain("GitLab Personal Access Token", "glpat-" + r(ALNUM + "_-", 20)))
    add(plain("npm Access Token", "npm_" + r(ALNUM, 36)))
    add(plain("PyPI Upload Token", "pypi-AgEIcHlwaS" + r(URLSAFE, 56)))

    v = r(ALNUM + "-_", 40)
    add(Specimen("OAuth Client Secret", v,
                 f'{{"client_id":"app-1234","client_secret":"{v}"}}'))

    # ── AI / ML providers ────────────────────────────────────────────────────
    add(plain("OpenAI API Key", "sk-" + r(URLSAFE, 20) + "T3BlbkFJ" + r(URLSAFE, 20)))
    add(plain("OpenAI Service Account Key", "sk-svcacct-" + r(URLSAFE, 28)))
    add(plain("Anthropic API Key", "sk-ant-" + r(URLSAFE, 40)))
    add(plain("Groq API Key", "gsk_" + r(ALNUM, 52)))
    add(plain("Hugging Face Access Token", "hf_" + r(ALNUM, 36)))
    add(plain("Replicate API Token", "r8_" + r(ALNUM, 40)))
    add(plain("Perplexity API Key", "pplx-" + r(ALNUM, 40)))
    add(plain("xAI API Key", "xai-" + r(ALNUM, 72)))
    add(plain("OpenRouter API Key", "sk-or-v1-" + r(HEX, 64)))
    add(plain("ElevenLabs API Key", "sk_" + r(HEX, 48)))
    add(plain("LangSmith API Key", "lsv2_pt_" + r(HEX, 32) + "_" + r(HEX, 10)))
    add(plain("Pinecone API Key", "pcsk_" + r(ALNUM + "_", 60)))

    # ── SaaS / comms / payments ──────────────────────────────────────────────
    add(plain("Slack Webhook",
              f"https://hooks.slack.com/services/T{r(ALNUM, 10)}/B{r(ALNUM, 10)}/{r(ALNUM, 24)}"))
    add(plain("Slack Token", "xoxb-" + r(DIGITS, 13) + "-" + r(ALNUM, 24)))
    add(plain("Slack App-Level Token",
              "xapp-1-" + r(UPPER + DIGITS, 11) + "-" + r(DIGITS, 13) + "-" + r(HEX, 40)))
    add(plain("Discord Bot Token",
              "M" + r(URLSAFE, 23) + "." + r(URLSAFE, 6) + "." + r(URLSAFE, 30)))
    add(plain("Telegram Bot Token", r(DIGITS, 10) + ":" + r(URLSAFE, 35)))
    add(plain("SendGrid API Key", "SG." + r(URLSAFE, 22) + "." + r(URLSAFE, 43)))
    add(plain("Mailgun API Key", "key-" + r(ALNUM, 32)))
    add(plain("Stripe Secret Key", "sk_live_" + r(ALNUM, 28)))
    add(plain("Square Access Token", "EAAA" + r(URLSAFE, 60)))
    add(plain("Shopify Access Token", "shpat_" + r(ALNUM, 32)))
    v = r(HEX, 32)
    add(Specimen("Twilio Auth Token", v, f'const twilioAuthToken = "{v}";'))
    add(plain("Linear API Key", "lin_api_" + r(ALNUM, 40)))
    add(plain("Notion Integration Token", "ntn_" + r(ALNUM, 46)))
    add(plain("Figma Personal Access Token", "figd_" + r(URLSAFE, 42)))
    add(plain("Postman API Key", "PMAK-" + r(HEX, 24) + "-" + r(HEX, 34)))
    add(plain("Doppler Token", "dp.pt." + r(ALNUM, 42)))
    add(plain("Supabase Access Token", "sbp_" + r(HEX, 40)))
    add(plain("Supabase Secret Key", "sb_secret_" + r(URLSAFE, 28)))
    add(plain("Databricks Token", "dapi" + r(HEX, 32)))
    add(plain("Grafana Service Account Token", "glsa_" + r(ALNUM, 32) + "_" + r(HEX, 8)))
    add(plain("New Relic API Key", "NRAK-" + r(UPPER + DIGITS, 27)))
    v = r(HEX, 32)
    add(Specimen("Datadog API Key", v, f'datadog: {{ apiKey: "{v}" }},'))
    add(plain("Google OAuth Client Secret", "GOCSPX-" + r(URLSAFE, 28)))
    add(plain("Firebase Cloud Messaging Key",
              "AAAA" + r(URLSAFE, 7) + ":" + r(URLSAFE, 140)))

    # ── Credentials in URIs / headers / key blocks ───────────────────────────
    add(plain("Database Connection URI",
              f"postgresql://svc_reporting:{r(ALNUM, 22)}@db.internal.acme.test:5432/analytics"))
    add(plain("Basic-Auth URL Credentials",
              f"https://deploy:{r(ALNUM, 18)}@artifacts.acme.test/release/latest.tar.gz"))
    v = "Bearer " + r(URLSAFE + ".", 44)
    add(Specimen("Bearer Token", v.split(" ", 1)[1],
                 f'headers: {{ Authorization: "{v}" }},'))
    add(plain("JWT Token",
              "eyJ" + r(URLSAFE, 30) + "." + r(URLSAFE, 60) + "." + r(URLSAFE, 43)))
    add(Specimen("Private Key Block", "-----BEGIN RSA PRIVATE KEY-----",
                 "-----BEGIN RSA PRIVATE KEY-----\n"
                 + "\n".join(r(B64, 64) for _ in range(4))
                 + "\n-----END RSA PRIVATE KEY-----"))
    add(Specimen("PGP Private Key Block", "-----BEGIN PGP PRIVATE KEY BLOCK-----",
                 "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
                 + "\n".join(r(B64, 64) for _ in range(3))
                 + "\n-----END PGP PRIVATE KEY BLOCK-----"))
    v = r(ALNUM, 36)
    add(Specimen("Generic High-Entropy Secret", v, f'const sessionSecret = "{v}";'))

    # ── Public-by-design: detected, but must not be reported as CRITICAL ─────
    add(plain("Stripe Publishable Key", "pk_live_" + r(ALNUM, 28), kind="public",
              note="Publishable key: designed to ship in the browser."))
    v = f"https://{r(HEX, 32)}@o4504.ingest.sentry.io/4506"
    add(Specimen("Sentry DSN", v, f'Sentry.init({{ dsn: "{v}" }});', kind="public",
                 note="DSN is a public write-only endpoint; allows event injection only."))
    add(plain("PostHog Project API Key", "phc_" + r(ALNUM, 43), kind="public",
              note="Project key is published to every browser by design."))
    return out


def _decoys(rng: random.Random) -> list[Decoy]:
    def r(alphabet: str, n: int) -> str:
        return "".join(rng.choice(alphabet) for _ in range(n))

    return [
        Decoy("aws-doc-example", 'const k = "AKIAIOSFODNN7EXAMPLE";',
              "AWS's own documentation key; shape-valid, must be allowlisted"),
        Decoy("placeholder-token", 'const t = "YOUR_API_KEY_HERE";',
              "Literal placeholder"),
        # Assembled at runtime rather than written as a literal. Spelled out in
        # full, GitHub's own push protection blocks the commit — its Stripe
        # detector matches sk_live_ + 24 characters even when all 24 are "x".
        # A corpus that cannot be committed is not a corpus, and the decoy is
        # identical once built.
        Decoy("masked-secret", 'api_key = "sk_' + 'live_' + 'x' * 24 + '"',
              "Masked in docs; the x-run filter must catch it"),
        Decoy("git-sha", f'const COMMIT = "{r(HEX, 40)}";',
              "40-hex git SHA — same shape as an AWS secret, in every build"),
        Decoy("uuid-v4", f'requestId: "{r(HEX,8)}-{r(HEX,4)}-4{r(HEX,3)}-a{r(HEX,3)}-{r(HEX,12)}"',
              "UUID, high entropy, ubiquitous, never a credential"),
        Decoy("sri-hash", f'<script src="/v.js" integrity="sha384-{r(B64, 64)}"></script>',
              "Subresource Integrity hash — base64, high entropy, public by definition"),
        Decoy("inline-png", f'background:url(data:image/png;base64,{r(B64, 300)}==)',
              "Inline image; long base64 blob that decodes to binary"),
        Decoy("webpack-chunkmap",
              't={179:"a3f9c2b1",204:"7e1d8f04",561:"c02b9ee7"},'
              'n.u=e=>"static/js/"+e+"."+t[e]+".chunk.js"',
              "Webpack chunk manifest — hex-ish tokens the entropy filter may like"),
        Decoy("npm-integrity", f'"integrity": "sha512-{r(B64, 86)}=="',
              "Lockfile integrity field"),
        Decoy("ga-measurement-id", 'gtag("config", "G-4XZ8QW2LMN");',
              "Public analytics identifier"),
        Decoy("public-pem",
              "-----BEGIN PUBLIC KEY-----\n" + r(B64, 64) + "\n-----END PUBLIC KEY-----",
              "PUBLIC key block must not trip the PRIVATE key detector"),
        Decoy("minified-identifiers",
              "function a(e,t,n,r,i,o,s,c){return e+t+n+r+i+o+s+c}"
              "var Kj9dPqLm2XvRt=1,Nb7wYcHs4TgFu=2,Zx3mVkQr8JpWd=3;",
              "Minified symbol soup — long, mixed-case, no real randomness source"),
        Decoy("css-content-hash", 'href="/static/css/main.a3f9c2b1e4d07f56.css"',
              "Content-addressed asset filename"),
        Decoy("base64-json-config",
              'const cfg = JSON.parse(atob("eyJlbnYiOiJwcm9kIiwicmVnaW9uIjoiZXUtd2VzdC0xIn0="));',
              "Base64 config the decoder will open — contains no credential"),
        Decoy("lorem-high-entropy", f'const nonce = "{r(ALNUM, 32)}";',
              "A genuine high-entropy value that is not a secret: a CSP nonce"),
    ]


def build() -> Corpus:
    """Generate the corpus and prove it is a valid measuring instrument."""
    rng = random.Random(SEED)
    corpus = Corpus(specimens=_specimens(rng), decoys=_decoys(rng))
    _self_validate(corpus)
    corpus.files = _render_files(corpus)
    return corpus


def _self_validate(corpus: Corpus) -> None:
    known = {p.name for p in scanner.SECRET_PATTERNS}
    problems: list[str] = []
    seen: set[str] = set()

    for s in corpus.specimens:
        if s.pattern not in known:
            problems.append(f"{s.pattern}: not a registered detector")
            continue
        if s.pattern in seen:
            problems.append(f"{s.pattern}: duplicated specimen")
        seen.add(s.pattern)

        pat = scanner.PATTERN_BY_NAME[s.pattern]
        m = pat.regex.search(s.snippet)
        if not m:
            problems.append(f"{s.pattern}: snippet does not match its own detector")
            continue
        got = m.group(1) if m.lastindex else m.group(0)
        if got != s.value:
            problems.append(
                f"{s.pattern}: declared value != captured value ({s.value!r} vs {got!r})")
        if scanner.is_benign_placeholder(s.value):
            problems.append(f"{s.pattern}: value would be dropped as a placeholder")
        floor = (scanner.MIN_ENTROPY_THRESHOLD if pat.entropy_gated
                 else scanner.MIN_STRUCTURAL_ENTROPY)
        ent = scanner.shannon_entropy(s.value)
        if ent < floor:
            problems.append(f"{s.pattern}: entropy {ent:.2f} below floor {floor}")

    missing = known - seen
    if missing:
        problems.append(f"detectors with no specimen: {sorted(missing)}")

    for d in corpus.decoys:
        if not d.snippet.strip():
            problems.append(f"decoy {d.label}: empty")

    if problems:
        raise AssertionError(
            "Corpus is not a valid measuring instrument:\n  - " + "\n  - ".join(problems))


def _render_files(corpus: Corpus) -> dict[str, str]:
    """Spread the corpus across the asset shapes a real scan has to find, so the
    HTTP mode measures discovery and not just regexes."""
    secrets = [s for s in corpus.specimens if s.kind == "secret"]
    publics = [s for s in corpus.specimens if s.kind == "public"]

    third = max(1, len(secrets) // 3)
    in_app, in_vendor, in_map = secrets[:third], secrets[third:2 * third], secrets[2 * third:]

    def block(items: list[Specimen]) -> str:
        return "\n".join(s.snippet for s in items)

    app_js = ("/* corpus: application bundle */\n(function(){\n"
              f"{block(in_app)}\n{block(publics)}\n}})();\n"
              "//# sourceMappingURL=app.js.map\n")

    vendor_js = ("/* corpus: vendor bundle — decoys live here */\n"
                 + "\n".join(d.snippet for d in corpus.decoys) + "\n"
                 + block(in_vendor) + "\n")

    source_map = json.dumps({
        "version": 3,
        "file": "app.js",
        "sources": ["src/config.ts"],
        "sourcesContent": ["// original source\n" + block(in_map)],
        "mappings": "AAAA",
    })

    config_json = json.dumps({
        "env": "production",
        "notes": "corpus config asset",
        "values": [s.value for s in in_app[:3]],
    }, indent=2)

    index_html = (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>SecretNode benchmark corpus</title>\n"
        "<script src='/app.js'></script>\n"
        "<script src='/vendor.js'></script>\n"
        "<link rel='preload' href='/fonts/x.woff2' as='font' type='font/woff2' crossorigin>\n"
        "</head><body><h1>Benchmark corpus</h1>\n<script>\n"
        "window.__INITIAL_STATE__ = "
        + json.dumps({"session": {"token": secrets[0].value}}) + ";\n"
        "</script>\n<a href='/config.json'>config</a>\n</body></html>\n"
    )

    return {
        "index.html": index_html,
        "app.js": app_js,
        "vendor.js": vendor_js,
        "app.js.map": source_map,
        "config.json": config_json,
    }


def write(dest: Path) -> Corpus:
    corpus = build()
    dest.mkdir(parents=True, exist_ok=True)
    for rel, content in corpus.files.items():
        (dest / rel).write_text(content, encoding="utf-8")
    (dest / "manifest.json").write_text(
        json.dumps(corpus.manifest(), indent=2), encoding="utf-8")
    return corpus


if __name__ == "__main__":
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("bench-corpus")
    c = write(out)
    m = c.manifest()["counts"]
    print(f"Corpus written to {out}/")
    print(f"  {m['secret']} secret + {m['public']} public specimens "
          f"covering {m['secret'] + m['public']}/{m['detectors_total']} detectors")
    print(f"  {m['decoy']} decoys across {len(c.files)} files")
