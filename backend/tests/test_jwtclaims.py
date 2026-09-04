"""
JWT claim decoding — the questions a shape match cannot answer.

The registry has always matched a JWT's shape. Nothing opened one, so a
fifteen-minute session token, a token that expired in 2023, and an unsigned
admin token were one finding at one severity.

The evidence that this mattered came from a live scan rather than from theory:
against vulnweb.com the AI tier dismissed two JWTs by reading their payloads —
"an example payload ('user':'test') used as sample documentation" — while the
offline tier retained both, because with no API key it had no way to separate a
demonstration token from a live session. Offline is the documented default.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import jwtclaims
import scanner

NOW = int(time.time())


def mk(header: dict, payload: dict) -> str:
    def seg(o: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
    return f"{seg(header)}.{seg(payload)}.sig_aBcDeF1234567890abcd"


def verdict(token: str):
    hits = [h for h in scanner.extract_secrets(
        "s", "https://t", "https://t/a.js", f'const t="{token}";') if "JWT" in h.secret_type]
    assert hits, "the JWT detector must still fire"
    return scanner._ai_skipped(hits[0], "AI unavailable.")


class TestDecoding:
    def test_expiry_is_read(self):
        f = jwtclaims.read(mk({"alg": "HS256"}, {"exp": NOW - 86400}))
        assert f.decoded and f.expired and not f.never_expires

    def test_an_absent_expiry_is_not_expiry(self):
        """The opposite, and the more dangerous of the two."""
        f = jwtclaims.read(mk({"alg": "HS256"}, {"iss": "https://a.test"}))
        assert not f.expired
        assert f.never_expires

    def test_issuer_and_audience_give_a_bare_token_a_provider(self):
        f = jwtclaims.read(mk({"alg": "RS256"},
                              {"iss": "https://auth.acme.io", "aud": "api.acme.io"}))
        assert f.issuer == "https://auth.acme.io"
        assert f.audience == "api.acme.io"

    def test_scopes_are_read_however_the_issuer_spells_them(self):
        for key in ("scope", "scp", "permissions", "roles"):
            f = jwtclaims.read(mk({"alg": "HS256"}, {key: "admin write:all"}))
            assert "admin" in f.scopes, key

    def test_a_list_audience_is_handled(self):
        f = jwtclaims.read(mk({"alg": "HS256"}, {"aud": ["a.test", "b.test"]}))
        assert "a.test" in f.audience

    def test_alg_none_is_flagged(self):
        assert jwtclaims.read(mk({"alg": "none"}, {"sub": "x"})).unsigned

    def test_a_numeric_string_timestamp_is_understood(self):
        """Some issuers emit exp as a string."""
        assert jwtclaims.read(mk({"alg": "HS256"}, {"exp": str(NOW - 10)})).expired

    def test_a_boolean_is_not_a_timestamp(self):
        f = jwtclaims.read(mk({"alg": "HS256"}, {"exp": True}))
        assert f.expires_at is None and f.never_expires


class TestNothingButAJwtIsDecoded:
    def test_non_jwt_input_never_raises(self):
        for junk in ("", "not.a.jwt", "eyJ", "AIzaSyCjFe", "a.b.c", None, "....", "eyJ.@@@.x"):
            assert jwtclaims.read(junk).decoded is False

    def test_a_non_json_payload_is_refused(self):
        seg = base64.urlsafe_b64encode(b"plain text").decode().rstrip("=")
        assert jwtclaims.read(f"eyJhbGciOiJIUzI1NiJ9.{seg}.sig").decoded is False

    def test_a_json_array_payload_is_refused(self):
        seg = base64.urlsafe_b64encode(b"[1,2,3]").decode().rstrip("=")
        assert jwtclaims.read(f"eyJhbGciOiJIUzI1NiJ9.{seg}.sig").decoded is False


class TestIdentityClaimsNeverLeave:
    """A payload is routinely full of personal data. Lifting an email address out
    of a token and printing it into a client-facing document turns a security
    finding into a data-protection problem, so identity claims are never read."""

    TOKEN = mk({"alg": "HS256"},
               {"sub": "alice@acme.io", "email": "alice@acme.io",
                "name": "Alice Smith", "picture": "https://cdn/a.png", "exp": NOW + 60})

    def test_no_identity_claim_appears_in_the_facts(self):
        blob = repr(jwtclaims.read(self.TOKEN)) + jwtclaims.read(self.TOKEN).summary()
        for pii in ("alice", "Alice", "Smith", "picture", "cdn"):
            assert pii not in blob, pii

    def test_no_identity_claim_reaches_the_verdict(self):
        v = verdict(self.TOKEN)
        assert "alice" not in (v.reason + v.impact).lower()

    def test_operational_claims_still_do(self):
        assert "acme.io" not in jwtclaims.read(
            mk({"alg": "HS256"}, {"sub": "alice@acme.io"})).summary()
        assert "auth.acme.io" in jwtclaims.read(
            mk({"alg": "HS256"}, {"iss": "https://auth.acme.io"})).summary()


class TestTheOfflineTierNowHasAVerdict:
    def test_a_demonstration_token_is_dismissed_without_an_api_key(self):
        """The vulnweb case. This previously required Gemini; it is now
        deterministic, which matters because offline is the default."""
        v = verdict(mk({"alg": "HS256"}, {"user": "test", "iss": "http://example.com"}))
        assert v.is_valid is False
        assert scanner.classify_validated(v) == "drop"
        assert "Demonstration token" in v.reason

    def test_an_expired_token_is_dismissed_but_not_deleted(self):
        """Confidence sits below the drop threshold on purpose. The token cannot
        be used, but a reader who sees nothing cannot tell whether the scanner
        examined it or never looked."""
        v = verdict(mk({"alg": "HS256"}, {"exp": NOW - 99999, "iss": "https://a.test"}))
        assert v.is_valid is False
        assert scanner.classify_validated(v) == "review"
        assert "expired" in v.reason.lower()

    def test_an_unsigned_token_says_it_is_forgeable(self):
        v = verdict(mk({"alg": "none"}, {"iss": "https://a.test"}))
        assert v.is_valid is True
        assert "forge" in v.impact.lower()

    def test_a_never_expiring_privileged_token_says_so(self):
        v = verdict(mk({"alg": "RS256"},
                       {"iss": "https://a.test", "scope": "admin write:all"}))
        assert "service token" in v.impact.lower()
        assert "revoked" in v.impact.lower()

    def test_an_ordinary_session_token_is_retained_with_its_issuer(self):
        v = verdict(mk({"alg": "HS256"},
                       {"exp": NOW + 3600, "iss": "https://login.acme.io"}))
        assert scanner.classify_validated(v) == "review"
        assert "login.acme.io" in v.reason

    def test_five_tokens_that_used_to_read_alike_now_differ(self):
        """The whole point. Before decoding, every one of these produced the same
        sentence at the same severity."""
        tokens = [
            mk({"alg": "HS256"}, {"user": "test", "iss": "http://example.com"}),
            mk({"alg": "HS256"}, {"exp": NOW - 99999, "iss": "https://a.test"}),
            mk({"alg": "none"}, {"iss": "https://a.test"}),
            mk({"alg": "RS256"}, {"iss": "https://a.test", "scope": "admin"}),
            mk({"alg": "HS256"}, {"exp": NOW + 3600, "iss": "https://a.test"}),
        ]
        reasons = {verdict(t).reason for t in tokens}
        assert len(reasons) == 5

    def test_a_non_jwt_finding_is_untouched_by_any_of_this(self):
        hits = scanner.extract_secrets(
            "s", "https://t", "https://t/a.js",
            'const k="ghp_' + '16C7e42F292c6912E7710c838347Ae178B4a";')
        v = scanner._ai_skipped(hits[0], "AI unavailable.")
        assert "JWT" not in v.reason
