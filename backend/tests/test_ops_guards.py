"""
v2.10.0 — tests for the operations-layer guards.

These are the tests that decide whether an unattended business process may use a
language model at all. The grounding tests pin the property that an invented
value cannot travel onward as a fact; the prompt-hygiene tests pin that a live
credential cannot be sent to a model by this layer.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import pytest

from ops import guards


# ── Grounding: the anti-hallucination primitive ──────────────────────────────

def test_a_value_present_in_a_source_is_grounded_and_returns_its_citation():
    sources = {
        "https://acme.test/about": "Reach the team at hello@acme.test any time.",
        "https://acme.test/": "Welcome to Acme.",
    }
    assert guards.assert_grounded("hello@acme.test", sources, label="email") \
        == "https://acme.test/about"


def test_a_plausible_but_invented_value_is_rejected():
    """The headline property. 'contact@acme.test' is exactly what a model
    guesses when it cannot find the real address, and it looks correct in
    review — which is why a human is not asked to catch it."""
    sources = {"https://acme.test/": "Reach the team at hello@acme.test."}
    with pytest.raises(guards.Ungrounded, match="invented"):
        guards.assert_grounded("contact@acme.test", sources, label="email")


def test_grounding_with_no_sources_fails_rather_than_passing_vacuously():
    with pytest.raises(guards.Ungrounded):
        guards.assert_grounded("hello@acme.test", {}, label="email")


def test_empty_value_is_rejected():
    with pytest.raises(guards.Ungrounded):
        guards.assert_grounded("   ", {"a": "anything"}, label="email")


@pytest.mark.parametrize("rendered", [
    "hello [at] acme.test",
    "hello (at) acme.test",
    "hello&#64;acme.test",
    "HELLO@ACME.TEST",
    "hello​@acme.test",          # zero-width space, an anti-scraper trick
])
def test_common_obfuscations_still_ground(rendered):
    """A real address written defensively must not be rejected — that would send
    a human to re-verify something that was already correct."""
    sources = {"https://acme.test/": f"Contact us: {rendered}"}
    assert guards.assert_grounded("hello@acme.test", sources) == "https://acme.test/"


def test_ground_all_is_all_or_nothing():
    """A partially-verified record is more dangerous than an unverified one: it
    carries the credibility of the fields that did check out."""
    sources = {"https://acme.test/": "Call Jane Roe on hello@acme.test"}
    ok = guards.ground_all({"email": "hello@acme.test", "name": "Jane Roe"}, sources)
    assert ok == {"email": "https://acme.test/", "name": "https://acme.test/"}

    with pytest.raises(guards.Ungrounded, match="name"):
        guards.ground_all({"email": "hello@acme.test", "name": "John Doe"}, sources)


def test_normalise_is_not_so_aggressive_that_different_addresses_collide():
    """A false accept here means outreach to an address nobody reads."""
    sources = {"https://acme.test/": "sales@acme.test"}
    with pytest.raises(guards.Ungrounded):
        guards.assert_grounded("sale@acme.test", sources)


# ── Prompt hygiene: never send a credential to a model ───────────────────────

def test_a_prompt_containing_a_credential_is_refused():
    text = 'const cfg = { token: "ghp_1234567890abcdEFGHijklMNOPqrstUVWX12" };'
    with pytest.raises(guards.SecretInPrompt):
        guards.assert_no_secrets(text, context="summarisation prompt")


def test_the_refusal_names_types_but_never_the_credential_itself():
    """The exception message is logged. Logging the secret in order to explain
    that it must not be transmitted would defeat the guard."""
    secret = "ghp_1234567890abcdEFGHijklMNOPqrstUVWX12"
    try:
        guards.assert_no_secrets(f'token = "{secret}"')
    except guards.SecretInPrompt as exc:
        msg = str(exc)
        assert secret not in msg
        assert "deliberately omitted" in msg
        assert "GitHub" in msg          # the *type* is named
    else:
        pytest.fail("expected SecretInPrompt")


def test_ordinary_business_text_passes_cleanly():
    text = (
        "Draft a follow-up to Acme Ltd about their attack-surface snapshot. "
        "They asked about pricing for continuous monitoring."
    )
    assert guards.find_secrets(text) == []
    guards.assert_no_secrets(text)      # must not raise
    assert guards.safe_prompt(text) == text


def test_safe_prompt_raises_instead_of_silently_sanitising():
    """A caller that does not know its data was altered will misreport what
    happened, so the guard refuses rather than scrubbing and continuing."""
    # Deliberately NOT "AKIAIOSFODNN7EXAMPLE": that is AWS's own documentation
    # key and the scanner's placeholder allowlist filters it, correctly. A
    # fixture using it would test the allowlist, not this guard.
    with pytest.raises(guards.SecretInPrompt):
        guards.safe_prompt('aws_key = "AKIAQZ7YH3MNBVCXLK2P"')


def test_documentation_example_keys_do_not_trip_the_guard():
    """The placeholder allowlist is load-bearing here: if AWS's published
    example key raised, every prompt quoting AWS docs would be refused."""
    guards.assert_no_secrets('see the docs example: AKIAIOSFODNN7EXAMPLE')


def test_find_secrets_reports_each_type_once_and_stably():
    text = (
        'a = "ghp_1234567890abcdEFGHijklMNOPqrstUVWX12"\n'
        'b = "ghp_ZZZZ567890abcdEFGHijklMNOPqrstUVWX99"\n'
    )
    found = guards.find_secrets(text)
    assert len(found) == len(set(found))
    assert guards.find_secrets(text) == found      # stable across calls
