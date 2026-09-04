"""
v2.14.6 — the Google key format that actually ships today.

AI Studio now issues `AQ.`-prefixed keys and the `AIzaSy…` format is being
retired. That inverted this scanner's value on Google: the `AIza` keys it
reliably caught are, in real web bundles, overwhelmingly Firebase *web config*
keys — public by design, correctly downgraded to INFO — while the `AQ.` keys it
could not see at all are live credentials with billing attached. It found the
harmless ones and was blind to the dangerous ones.

Google has published no specification for the new format, so the detector is
sized from an observed key (`AQ.` plus 50 base64url characters) and then
deliberately widened. Pinning an observed length is exactly what left the OpenAI
pattern demanding twenty characters before `T3BlbkFJ` and blind to every
`sk-proj-` key issued today.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import scanner


def _types(src: str) -> list[str]:
    return [h.secret_type for h in scanner.extract_secrets(
        "s", "https://t", "https://t/a.js", src)]


AQ_KEY = "Google AI Studio API Key"
_AQ = "AQ." + "Ab8RN6J-6XXlcm-Zfvl5n8ION_9gXCeNmZ0OMg9j0ImJRP_MoA"


class TestGoogleAiStudioKey:
    """AI Studio now issues `AQ.`-prefixed keys and the `AIzaSy…` format is being
    retired. That inverted this scanner's value on Google: the `AIza` keys it
    reliably caught are, in real bundles, overwhelmingly Firebase web config
    keys — public by design — while the `AQ.` keys it could not see at all are
    live credentials with billing attached.
    """

    def test_the_pattern_is_registered_as_critical_with_remediation(self):
        p = scanner.PATTERN_BY_NAME[AQ_KEY]
        assert p.severity == "CRITICAL"
        assert "aistudio.google.com" in p.remediation

    def test_an_observed_shape_key_is_found(self):
        assert AQ_KEY in _types(f'const k="{_AQ}";')

    def test_a_shorter_body_is_still_found(self):
        """The bound is not pinned to the one length anyone has seen — pinning an
        observed length is what left the OpenAI pattern blind to `sk-proj-`."""
        assert AQ_KEY in _types('GEMINI_API_KEY=AQ.' + 'Cd4Tz9Wq2XvRt7KpLm3NbYcHs8JgFu1AeZo5iWqSxYl0MnPrQ')

    def test_a_longer_body_is_still_found(self):
        assert AQ_KEY in _types(
            'key:"AQ.' + 'Zx3mVkQr8JpWdNb7wYcHs4TgFuKj9dPqLm2XvRtAeZo5iWqSxYl0MnPrQtVbXcNdMeFg' + '"')

    def test_a_jwt_whose_segment_ends_in_aq_is_not_a_key(self):
        """The word boundary is load-bearing. A JWT separator after a segment
        ending in `AQ` produces a literal `AQ.` followed by base64url, and JWTs
        are in nearly every bundle."""
        assert AQ_KEY not in _types(
            'const t="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCAQ.eyJzdWIiOiIxMjM0NTY3ODkwIn0";')

    def test_a_hostname_beginning_aq_is_not_a_key(self):
        assert AQ_KEY not in _types('<a href="https://AQ.example.com/docs">x</a>')

    def test_something_too_short_is_not_a_key(self):
        assert AQ_KEY not in _types('const s="AQ.short";')

    def test_it_is_never_cleared_as_public_by_design(self):
        """The whole point. An AIza value may be a Firebase web key and routinely
        is; an AQ. key never is — and one sitting inside a Firebase config block
        is more alarming, not less."""
        src = (f'const cfg={{apiKey:"{_AQ}",authDomain:"x.firebaseapp.com",'
               'projectId:"x",appId:"1:2:web:3"}};')
        hits = [h for h in scanner.extract_secrets("s", "https://t", "https://t/a.js", src)
                if h.secret_type == AQ_KEY]
        assert hits
        vf = scanner._ai_skipped(hits[0], "AI unavailable.")
        assert vf.public_by_design is False
        assert vf.effective_severity() == "CRITICAL"
        assert scanner.classify_validated(vf) != "drop"

    def test_the_legacy_aiza_detector_still_works(self):
        """Both formats are in the wild during the migration."""
        assert "Google Cloud API Key" in _types(
            'apiKey:"AIzaSyCjFeYsl3rpaFFGbgYh_JAmft-U5FW0O-o"')
