"""
SecretNode — bench/corpus.py  (R2: FP/FN benchmark corpus)

A small, labelled corpus for measuring the deterministic detection layer
(regex + placeholder allowlist + entropy gate + base64 pass — everything in
extract_secrets(), no network, no AI). It answers, reproducibly:

  • RECALL     — of real secrets planted in code, how many does the layer catch?
  • PRECISION  — of everything it flags, how much is a real secret vs noise/placeholder?

> IMPORTANT: every "secret" here is SYNTHETIC — deterministically generated,
> correctly *shaped* and high-entropy, but not a real credential. Nothing in this
> file is live. It exists only to hold the detector's precision/recall steady as
> the code changes.

Each sample: (id, text, expect) where `expect` is the secret_type that SHOULD be
detected, or None for a negative (nothing should be detected).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

_ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def _rand(n: int, seed: str, alphabet: str = _ALNUM) -> str:
    """Deterministic, high-entropy string of length n over `alphabet`.
    Deterministic so the corpus is stable across runs; high-entropy so valid
    positives clear the entropy gate (>= 3.5 bits/char)."""
    out: list[str] = []
    h = hashlib.sha256(seed.encode()).digest()
    while len(out) < n:
        h = hashlib.sha256(h).digest()
        for b in h:
            out.append(alphabet[b % len(alphabet)])
            if len(out) >= n:
                break
    return "".join(out)


@dataclass(frozen=True)
class Sample:
    id: str
    text: str
    expect: str | None   # secret_type that must be detected, or None for a clean negative

    @property
    def is_positive(self) -> bool:
        return self.expect is not None


# ── POSITIVES — a real (synthetic) secret is planted; the layer must catch it ──
_POSITIVES: list[Sample] = [
    Sample("aws-access-key",
           f'const AWS_KEY = "AKIA{_rand(16, "aws", _UPPER)}";',
           "AWS Access Key"),
    Sample("github-pat",
           f'GITHUB_TOKEN=ghp_{_rand(36, "ghpat")}',
           "GitHub Personal Access Token"),
    Sample("stripe-secret",
           f'stripe.setApiKey("sk_live_{_rand(24, "stripe")}");',
           "Stripe Secret Key"),
    Sample("google-api-key",
           f'apiKey: "AIza{_rand(35, "goog")}",',
           "Google Cloud API Key"),
    Sample("slack-webhook",
           f'https://hooks.slack.com/services/T{_rand(9, "sa", _UPPER)}/B{_rand(9, "sb", _UPPER)}/{_rand(24, "sc")}',
           "Slack Webhook"),
    Sample("jwt",
           f'Authorization: Bearer eyJ{_rand(20, "j1")}.eyJ{_rand(30, "j2")}.{_rand(43, "j3")}',
           "JWT Token"),
    Sample("gitlab-pat",
           f'GITLAB_TOKEN=glpat-{_rand(20, "glp")}',
           "GitLab Personal Access Token"),
    Sample("openai",
           # real OpenAI keys carry the literal "T3BlbkFJ" infix; the detector
           # requires it (rejects look-alikes) — so the corpus must include it.
           f'OPENAI_API_KEY=sk-{_rand(20, "oai1")}T3BlbkFJ{_rand(20, "oai2")}',
           "OpenAI API Key"),
    Sample("sendgrid",
           f'SG.{_rand(22, "sg1")}.{_rand(43, "sg2")}',
           "SendGrid API Key"),
    Sample("npm-token",
           f'//registry.npmjs.org/:_authToken=npm_{_rand(36, "npm")}',
           "npm Access Token"),
    Sample("database-uri",
           f'DATABASE_URL=postgres://dbuser:{_rand(16, "dbp")}@db.internal:5432/prod',
           "Database Connection URI"),
    Sample("basic-auth-url",
           f'fetch("https://admin:{_rand(14, "bap")}@api.internal.example.com/v1/")',
           "Basic-Auth URL Credentials"),
]

# ── NEGATIVES — placeholders / examples / noise; the layer must stay silent ──
_NEGATIVES: list[Sample] = [
    Sample("aws-doc-example", 'key = "AKIAIOSFODNN7EXAMPLE"', None),
    Sample("your-api-key", 'apiKey: "YOUR_API_KEY_HERE"', None),
    Sample("stripe-placeholder", 'sk_live_your_secret_key_here', None),
    Sample("github-xxxx", 'token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"', None),
    Sample("google-zeros", 'apiKey: "AIzaSy00000000000000000000000000000000000"', None),
    Sample("env-ref", 'const key = process.env.STRIPE_SECRET_KEY;', None),
    Sample("angle-placeholder", 'Authorization: Bearer <YOUR_ACCESS_TOKEN>', None),
    Sample("changeme", 'password = "changeme_changeme_changeme"', None),
    Sample("redacted", 'secret = "redacted_for_security_reasons"', None),
    Sample("git-sha", "const commit = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0';", None),
    Sample("uuid", "id: '550e8400-e29b-41d4-a716-446655440000'", None),
    Sample("low-entropy-aws", 'k = "AKIAAAAAAAAAAAAAAAAA"', None),
    Sample("plain-prose", "This build ships no credentials; configure them via environment variables.", None),
    Sample("semver-list", 'deps: ["1.2.3", "4.5.6", "7.8.9", "10.11.12"]', None),
    Sample("css-color-hash", ".btn { color: #a3f2c1; background: #1b2e4d; border: #ff00aa; }", None),
]

CORPUS: list[Sample] = _POSITIVES + _NEGATIVES
