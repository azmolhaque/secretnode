"""
R3 — regex safety / ReDoS audit (automated + permanent).

Secret detectors run untrusted, attacker-influenceable input (a target's own
minified JS) through 54 regexes. A single catastrophic-backtracking pattern
would let a crafted asset hang a scan (denial of service). This suite proves,
and keeps proving as patterns are added, that:

  1. no detector exhibits catastrophic backtracking on adversarial input
     (empirical wall-clock bound — the real guarantee), and
  2. no detector source contains the classic nested-quantifier ReDoS construct
     (static guard that gates future contributions), and
  3. the per-pattern match cap bounds work on a match-flood input.
"""

import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import scanner

# Per-pattern per-input wall-clock ceiling. A linear regex clears 50 KB in well
# under a millisecond; a backtracking one blows past this by orders of magnitude.
_TIME_BUDGET_S = 0.75

# Adversarial inputs: long single-char runs, near-miss prefixes that start a
# match then force a fail, and structures that target the ".{0,N}"-gap and
# credential-in-URL patterns specifically.
_N = 50_000
_ADVERSARIAL = [
    "A" * _N, "a" * _N, "0" * _N, "=" * _N, "/" * _N, " " * _N, "!" * _N,
    "AKIA" + "A" * _N,
    "sk_live_" + "x" * _N,
    "ghp_" + "a" * _N,
    "eyJ" + "A" * _N,
    "aws" + " " * 19 + "secret" + " " * 19 + "'" + "A" * _N,   # AWS-secret .{0,20} gap
    "twilio" + " " * 19 + "'" + "a" * _N,                        # Twilio .{0,20} gap
    "heroku" + " " * 29 + "'" + "a" * _N,                        # Heroku .{0,30} gap
    "https://" + "a" * _N + ":" + "b" * _N + "@" + "c" * _N,     # basic-auth URL creds
    "-----BEGIN " + "A" * _N,
    "https://hooks.slack.com/services/T" + "A" * _N,
    ("Bearer " + "a" * 500 + " ") * 100,
    ("A" * 80 + "\n") * 600,                                      # base64-ish lines
]

# Classic ReDoS shape: a group that contains an unbounded quantifier and is
# ITSELF unbounded-quantified, e.g. (a+)+, (.*)*, (\w+)*. Char classes like
# [A-Za-z0-9/+=]+ (quantifier on a class, not a group) are linear and excluded.
_NESTED_QUANT_RE = re.compile(r"\((?![?]:)[^)]*[+*][^)]*\)[+*]")


def test_no_detector_catastrophic_backtracking():
    slow = []
    for p in scanner.SECRET_PATTERNS:
        for inp in _ADVERSARIAL:
            t0 = time.perf_counter()
            list(p.regex.finditer(inp))
            dt = time.perf_counter() - t0
            if dt > _TIME_BUDGET_S:
                slow.append((p.name, round(dt, 3), len(inp)))
    assert not slow, f"potential ReDoS — patterns exceeded {_TIME_BUDGET_S}s: {slow}"


def test_no_nested_quantifier_construct_in_sources():
    offenders = [p.name for p in scanner.SECRET_PATTERNS
                 if _NESTED_QUANT_RE.search(p.regex.pattern)]
    assert not offenders, f"nested-quantifier ReDoS construct in: {offenders}"


def test_match_cap_bounds_a_flood():
    # A blob with far more distinct, high-entropy AWS keys than the cap must not
    # yield unbounded findings for that one pattern.
    import hashlib
    alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    parts = []
    for i in range(400):
        h = hashlib.sha256(f"k{i}".encode()).digest()
        body = "".join(alpha[b % len(alpha)] for b in h[:16])
        parts.append(f'k="AKIA{body}"')
    text = "\n".join(parts)
    findings = scanner._scan_text("s", "t", "u", text)
    aws = [f for f in findings if f.secret_type == "AWS Access Key"]
    assert len(aws) <= scanner.MAX_MATCHES_PER_PATTERN
    assert len(aws) < 400  # proves the cap actually engaged
