"""
v2.2.0 — tests for the expanded pattern registry, audit metadata propagation,
and env-configurable tuning.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import secrets
import string

import pytest

import scanner


def _rnd(n: int) -> str:
    return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(n))


def _hits(body: str) -> set[str]:
    return {
        f.secret_type
        for f in scanner.extract_secrets("s", "https://t", "https://t/a.js", body)
    }


@pytest.mark.parametrize(
    "expected,body",
    [
        ("OpenAI API Key",              f'k="sk-proj-{_rnd(20)}T3BlbkFJ{_rnd(20)}"'),
        ("Anthropic API Key",           f'k="sk-ant-{_rnd(40)}"'),
        ("GitLab Personal Access Token", f'k="glpat-{_rnd(20)}"'),
        ("GitHub Fine-Grained PAT",     f'k="github_pat_{_rnd(82)}"'),
        ("npm Access Token",            f"_authToken=npm_{_rnd(36)}"),
        ("DigitalOcean PAT",            'k="dop_v1_' + "".join(secrets.choice("abcdef0123456789") for _ in range(64)) + '"'),
        ("HashiCorp Vault Token",       f'k="hvs.{_rnd(30)}"'),
        ("Telegram Bot Token",          f'tg="1234567890:{_rnd(35)}"'),
        ("Database Connection URI",     'DB="postgres://admin:' + _rnd(16) + '@db.example.com:5432/app"'),
        ("PGP Private Key Block",       "-----BEGIN PGP PRIVATE KEY BLOCK-----"),
        ("Bearer Token",                f"Authorization: Bearer {_rnd(40)}"),
    ],
)
def test_new_detectors(expected, body):
    assert expected in _hits(body)


def test_registry_grew_past_thirty():
    # v2.0 shipped 16 patterns; v2.2 expands coverage substantially.
    assert len(scanner.SECRET_PATTERNS) >= 30


def test_every_pattern_has_valid_metadata():
    for p in scanner.SECRET_PATTERNS:
        assert p.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        assert p.cwe.startswith("CWE-")
        assert p.remediation and len(p.remediation) > 10


def test_pattern_names_are_unique():
    names = [p.name for p in scanner.SECRET_PATTERNS]
    assert len(names) == len(set(names))


def test_metadata_propagates_into_finding_dict():
    rf = scanner.RawFinding(
        scan_id="s", target_url="https://t", source_url="https://t/a.js",
        secret_type="AWS Access Key", raw_match="AKIAIOSFODNN7EXAMPLE",
        context_snippet="ctx", entropy=4.2,
    )
    d = scanner.ValidatedFinding(raw=rf, is_valid=True, confidence=95, reason="r").to_dict()
    assert d["severity"] == "CRITICAL"
    assert d["cwe"].startswith("CWE-")
    assert "remediation" in d and d["remediation"]


def test_unknown_secret_type_gets_safe_default_metadata():
    rf = scanner.RawFinding(
        scan_id="s", target_url="https://t", source_url="https://t/a.js",
        secret_type="Totally Unknown Type", raw_match="whatever",
        context_snippet="ctx", entropy=4.0,
    )
    d = scanner.ValidatedFinding(raw=rf, is_valid=True, confidence=95, reason="r").to_dict()
    assert d["severity"] == "MEDIUM"
    assert d["cwe"] == "CWE-798"


def test_env_helpers_parse_and_fallback(monkeypatch):
    monkeypatch.setenv("SN_TEST_INT", "42")
    monkeypatch.setenv("SN_TEST_BAD", "not-a-number")
    assert scanner._env_int("SN_TEST_INT", 1) == 42
    assert scanner._env_int("SN_TEST_BAD", 7) == 7          # malformed → default
    assert scanner._env_int("SN_TEST_MISSING", 9) == 9      # unset → default
    monkeypatch.setenv("SN_TEST_FLOAT", "3.5")
    assert scanner._env_float("SN_TEST_FLOAT", 1.0) == 3.5
    assert scanner._env_float("SN_TEST_BAD", 2.5) == 2.5


def test_placeholder_still_filtered_by_entropy():
    # Expanded registry must not start matching obvious placeholders.
    assert _hits('const KEY = "YOUR_API_KEY_HERE";') == set() or \
        "Generic High-Entropy Secret" not in _hits('const KEY = "YOUR_API_KEY_HERE";')


# ── v2.3.0: accuracy layer (base64 decoding + allowlist) + new detectors ──────

def test_base64_encoded_secret_is_decoded_and_detected():
    import base64
    token = "glpat-" + _rnd(20)
    blob = base64.b64encode(f"authToken={token}".encode()).decode()
    body = f'const cfg = "{blob}";'
    assert "GitLab Personal Access Token" in _hits(body)


def test_placeholder_values_are_allowlisted():
    assert scanner.is_benign_placeholder("AKIAIOSFODNN7EXAMPLE")      # AWS doc example
    assert scanner.is_benign_placeholder("your_api_key_here")
    assert scanner.is_benign_placeholder("REPLACE_WITH_YOUR_TOKEN".lower())
    assert not scanner.is_benign_placeholder("aK7xQ2mN9pL4vR8sT1wY6zB3")  # real-looking


@pytest.mark.parametrize(
    "expected,body",
    [
        ("GitHub Server/Refresh Token", f'x="ghs_{_rnd(36)}"'),
        ("OpenAI Service Account Key",  f'x="sk-svcacct-{_rnd(40)}"'),
        ("Grafana Service Account Token", 'x="glsa_' + _rnd(32) + "_" + "".join(secrets.choice("abcdef0123456789") for _ in range(8)) + '"'),
        ("New Relic API Key",           'x="NRAK-' + "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(27)) + '"'),
    ],
)
def test_v230_new_detectors(expected, body):
    assert expected in _hits(body)


def test_extract_secrets_deduplicates_by_fingerprint():
    token = "glpat-" + _rnd(20)
    # same token appears twice in the same source -> one finding
    body = f'a="{token}"; b="{token}";'
    fs = [f for f in scanner.extract_secrets("s", "https://t", "https://t/a.js", body)
          if f.secret_type == "GitLab Personal Access Token"]
    assert len(fs) == 1


# ── v2.7.2 — AI/ML provider detector pack ────────────────────────────────────
# Grounded in a real authorized-scope finding: an ElevenLabs key shipped in a
# client-side EnvConfig.js was previously caught only by the generic
# high-entropy catch-all (MEDIUM, untyped). These structural detectors type it
# correctly and carry provider-specific remediation.

def _hex(n: int) -> str:
    return "".join(secrets.choice("abcdef0123456789") for _ in range(n))


@pytest.mark.parametrize(
    "expected,body",
    [
        ("ElevenLabs API Key",         f'window.REACT_APP_ELEVENLABS_API_KEY = "sk_{_hex(48)}";'),
        ("Groq API Key",               f'k="gsk_{_rnd(52)}"'),
        ("Hugging Face Access Token",  f'k="hf_{_rnd(37)}"'),
        ("Replicate API Token",        f'k="r8_{_rnd(40)}"'),
        ("Perplexity API Key",         f'k="pplx-{_rnd(48)}"'),
        ("xAI API Key",                f'k="xai-{_rnd(80)}"'),
        ("OpenRouter API Key",         f'k="sk-or-v1-{_hex(64)}"'),
        ("LangSmith API Key",          f'k="lsv2_pt_{_hex(32)}_{_hex(10)}"'),
        ("Pinecone API Key",           f'k="pcsk_{_rnd(60)}"'),
    ],
)
def test_ai_provider_patterns_detected(expected: str, body: str) -> None:
    assert expected in _hits(body), f"{expected} not detected in: {body[:70]}"


def test_elevenlabs_is_typed_not_generic() -> None:
    """The real-world case: a typed detector must win over the generic catch-all."""
    body = f'window.REACT_APP_ELEVENLABS_API_KEY = "sk_{_hex(48)}";'
    hits = _hits(body)
    assert "ElevenLabs API Key" in hits


def test_ai_provider_patterns_reject_near_misses() -> None:
    """Wrong length / wrong alphabet must not match — precision guard."""
    negatives = [
        f'k="sk_{_hex(20)}"',            # ElevenLabs: too short
        f'k="sk_{_rnd(48)}XYZ"',         # ElevenLabs: not pure hex, over length
        f'k="gsk_{_rnd(10)}"',           # Groq: too short
        f'k="hf_{_rnd(5)}"',             # HF: too short
        f'k="r8_{_rnd(4)}"',             # Replicate: too short
        'k="sk-or-v1-nothex"',           # OpenRouter: not hex
    ]
    for body in negatives:
        typed = _hits(body) - {"Generic High-Entropy Secret"}
        assert not typed, f"false positive on {body!r}: {typed}"


def test_ai_provider_regexes_are_redos_safe() -> None:
    """A hostile minified bundle must not stall the new detectors."""
    import time
    ai_names = {
        "ElevenLabs API Key", "Groq API Key", "Hugging Face Access Token",
        "Replicate API Token", "Perplexity API Key", "xAI API Key",
        "OpenRouter API Key", "LangSmith API Key", "Pinecone API Key",
    }
    hostile = "sk_" + "a" * 5000 + "!" + "gsk_" + "0" * 5000
    for p in scanner.SECRET_PATTERNS:
        if p.name in ai_names:
            t0 = time.monotonic()
            p.regex.search(hostile)
            assert time.monotonic() - t0 < 0.5, f"{p.name} too slow (possible ReDoS)"


def test_typed_detector_collapses_generic_duplicate() -> None:
    """One credential must yield ONE finding, typed — not a typed + generic pair.

    Regression guard: the fingerprint includes secret_type, so before v2.7.2 the
    same value at the same URL was reported twice (HIGH typed + MEDIUM generic),
    double-counting the exposure and spending two AI-validation calls on it.
    """
    body = f'window.REACT_APP_ELEVENLABS_API_KEY = "sk_{_hex(48)}";'
    findings = scanner.extract_secrets("s", "https://t", "https://t/EnvConfig.js", body)
    assert len(findings) == 1, [f.secret_type for f in findings]
    assert findings[0].secret_type == "ElevenLabs API Key"


def test_generic_survives_when_no_typed_detector_matches() -> None:
    """The catch-all must still fire for credentials no provider detector knows."""
    body = f'api_key = "{_rnd(44)}"'
    hits = _hits(body)
    assert hits == {scanner.GENERIC_SECRET_TYPE}, hits


def test_generic_kept_for_a_different_value_in_same_file() -> None:
    """Collapsing is per-value, not per-file: an untyped second secret survives."""
    body = (
        f'window.REACT_APP_ELEVENLABS_API_KEY = "sk_{_hex(48)}";\n'
        f'window.OTHER_TOKEN = "{_rnd(44)}";'
    )
    hits = _hits(body)
    assert "ElevenLabs API Key" in hits
    assert scanner.GENERIC_SECRET_TYPE in hits
