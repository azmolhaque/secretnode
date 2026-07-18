"""
R8 — passive HTTP security-posture checks (headers / misconfig).
Pure analysis; a lightweight mock stands in for httpx for the fetch path.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import pytest

import posture


def _names(findings):
    return {f.name for f in findings}


def test_bare_https_response_flags_the_core_headers():
    out = posture.analyze_security_headers({}, "https://x.com")
    n = _names(out)
    assert "Missing HSTS" in n
    assert "Missing Content-Security-Policy" in n
    assert "Missing X-Content-Type-Options: nosniff" in n
    assert "No clickjacking protection" in n
    assert "Missing Referrer-Policy" in n
    assert "Missing Permissions-Policy" in n


def test_hardened_headers_produce_no_findings():
    hardened = {
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=()",
    }
    assert posture.analyze_security_headers(hardened, "https://x.com") == []


def test_hsts_not_flagged_on_plain_http():
    out = posture.analyze_security_headers({}, "http://x.com")
    assert "Missing HSTS" not in _names(out)


def test_csp_frame_ancestors_satisfies_clickjacking():
    out = posture.analyze_security_headers(
        {"Content-Security-Policy": "frame-ancestors 'none'"}, "https://x.com")
    assert "No clickjacking protection" not in _names(out)


def test_version_disclosure_flagged():
    out = posture.analyze_security_headers({"Server": "nginx/1.18.0"}, "https://x.com")
    hit = [f for f in out if f.name.startswith("Version disclosure")]
    assert hit and hit[0].cwe == "CWE-200"


def test_insecure_cookie_flags():
    out = posture.analyze_security_headers({"Set-Cookie": "sid=abc"}, "https://x.com")
    n = _names(out)
    assert "Cookie without Secure flag" in n
    assert "Cookie without HttpOnly flag" in n
    secure_ok = posture.analyze_security_headers(
        {"Set-Cookie": "sid=abc; Secure; HttpOnly"}, "https://x.com")
    assert "Cookie without Secure flag" not in _names(secure_ok)


def test_findings_serialize():
    out = posture.analyze_security_headers({}, "https://x.com")
    d = out[0].to_dict()
    assert {"name", "severity", "cwe", "evidence", "remediation", "category"} <= set(d)


@pytest.mark.asyncio
async def test_fetch_posture_reads_headers():
    class _Resp:
        headers = {"Server": "Apache/2.4.7"}
        url = "https://x.com/"
    class _Client:
        async def get(self, url, **kw):
            return _Resp()
    out = await posture.fetch_posture(_Client(), "https://x.com")
    assert any(f.name.startswith("Version disclosure") for f in out)


@pytest.mark.asyncio
async def test_fetch_posture_fails_closed():
    class _Boom:
        async def get(self, *a, **k):
            raise RuntimeError("network down")
    assert await posture.fetch_posture(_Boom(), "https://x.com") == []
