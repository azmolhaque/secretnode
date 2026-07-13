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
