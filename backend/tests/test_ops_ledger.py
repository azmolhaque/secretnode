"""
v2.11.0 — tests for the authorization ledger.

The matcher tests are the important ones. This is the single place in the
codebase where a subtle bug means scanning an organisation that never agreed,
so the classic scope-confusion attacks are pinned explicitly rather than left
to the reader's confidence in `endswith`.
"""

from __future__ import annotations

import os
import sys
from datetime import date

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import pytest

from ops import ledger
from ops.ledger import Authorization

TODAY = date(2026, 8, 13)


def _auth(**over) -> Authorization:
    base = dict(
        engagement_id="ENG-001",
        client="Acme Ltd",
        scope=["acme.test", "*.acme.test"],
        starts_at="2026-01-01",
        expires_at="2026-12-31",
        recipient="security@acme.test",
        roe_reference="RoE-2026-001 signed 2026-01-01",
    )
    base.update(over)
    return Authorization(**base)


# ── Host normalisation ───────────────────────────────────────────────────────

@pytest.mark.parametrize("raw,expected", [
    ("https://acme.test/path?q=1", "acme.test"),
    ("http://ACME.test", "acme.test"),
    ("acme.test", "acme.test"),
    ("acme.test:8443", "acme.test"),
    ("acme.test.", "acme.test"),            # trailing FQDN dot
    ("https://user:pw@acme.test/x", "acme.test"),
])
def test_normalise_host(raw, expected):
    assert ledger.normalise_host(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", None])
def test_unparseable_targets_return_none_rather_than_guessing(raw):
    assert ledger.normalise_host(raw) is None


# ── Scope confusion: the attacks this matcher must not fall for ──────────────

@pytest.mark.parametrize("host", [
    "notacme.test",           # bare endswith("acme.test") is True — must still deny
    "acme.test.evil.net",     # substring containment — must deny
    "evil-acme.test",
    "acmeXtest",
    "acme.test.co",
])
def test_lookalike_hosts_are_denied_against_an_exact_pattern(host):
    assert ledger.host_matches(host, "acme.test") is False


@pytest.mark.parametrize("host", [
    "notacme.test",
    "acme.test.evil.net",
    "wwwacme.test",
])
def test_lookalike_hosts_are_denied_against_a_wildcard_pattern(host):
    assert ledger.host_matches(host, "*.acme.test") is False


def test_exact_pattern_does_not_imply_subdomains():
    """Nothing is inferred: authorising the apex is not authorising www."""
    assert ledger.host_matches("acme.test", "acme.test") is True
    assert ledger.host_matches("www.acme.test", "acme.test") is False


def test_wildcard_does_not_imply_the_apex():
    """A host is not a subdomain of itself, and an RoE saying '*.acme.test'
    has not said 'acme.test'."""
    assert ledger.host_matches("www.acme.test", "*.acme.test") is True
    assert ledger.host_matches("a.b.acme.test", "*.acme.test") is True
    assert ledger.host_matches("acme.test", "*.acme.test") is False


def test_matching_is_case_and_trailing_dot_insensitive():
    assert ledger.host_matches("WWW.Acme.Test.", "*.acme.test") is True


# ── IP and CIDR scope ────────────────────────────────────────────────────────

def test_exact_ip_scope():
    assert ledger.host_matches("192.0.2.10", "192.0.2.10") is True
    assert ledger.host_matches("192.0.2.11", "192.0.2.10") is False


def test_cidr_scope_contains_and_excludes():
    assert ledger.host_matches("192.0.2.10", "192.0.2.0/24") is True
    assert ledger.host_matches("192.0.3.10", "192.0.2.0/24") is False


def test_a_hostname_is_never_inside_a_cidr():
    assert ledger.host_matches("acme.test", "192.0.2.0/24") is False


def test_a_malformed_pattern_denies_rather_than_raising():
    assert ledger.host_matches("acme.test", "not/a/cidr") is False
    assert ledger.host_matches("acme.test", "*.") is False


# ── Window, status, exclusions ───────────────────────────────────────────────

def test_in_scope_and_in_window_is_allowed():
    d = ledger.evaluate(_auth(), "https://www.acme.test/app.js", now=TODAY)
    assert d.allowed and d.matched_rule == "*.acme.test"
    assert bool(d) is True


def test_before_the_window_opens_is_denied():
    d = ledger.evaluate(_auth(starts_at="2026-09-01", expires_at="2026-12-31"),
                        "acme.test", now=TODAY)
    assert not d.allowed and "has not opened" in d.reason


def test_after_expiry_is_denied():
    d = ledger.evaluate(_auth(expires_at="2026-08-12"), "acme.test", now=TODAY)
    assert not d.allowed and "expired" in d.reason


def test_expiry_is_inclusive_of_the_final_day():
    d = ledger.evaluate(_auth(expires_at="2026-08-13"), "acme.test", now=TODAY)
    assert d.allowed


def test_revoked_engagement_denies_immediately():
    d = ledger.evaluate(
        _auth(status="revoked", revoked_reason="client withdrew in writing"),
        "acme.test", now=TODAY,
    )
    assert not d.allowed and "revoked" in d.reason and "withdrew" in d.reason


def test_exclusion_beats_inclusion():
    """The carve-out is usually the part someone will be upset about."""
    a = _auth(scope=["*.acme.test"], exclusions=["prod.acme.test"])
    assert ledger.evaluate(a, "staging.acme.test", now=TODAY).allowed
    d = ledger.evaluate(a, "prod.acme.test", now=TODAY)
    assert not d.allowed and "explicitly excluded" in d.reason


def test_a_revoked_engagement_does_not_claim_hosts_it_never_covered():
    """Found by a failing test: checking status before scope meant a revoked
    engagement reported 'revoked' for every host in the world. In an audit trail
    that reads as a client withdrawing consent for infrastructure that was never
    theirs."""
    a = _auth(scope=["acme.test"], status="revoked", revoked_reason="withdrew")
    d = ledger.evaluate(a, "somebody-else.test", now=TODAY)
    assert not d.allowed
    assert "not in the scope" in d.reason
    assert "revoked" not in d.reason
    assert d.in_scope is False


def test_a_revoked_engagement_does_explain_denial_for_hosts_it_covers():
    a = _auth(scope=["acme.test"], status="revoked", revoked_reason="withdrew")
    d = ledger.evaluate(a, "acme.test", now=TODAY)
    assert not d.allowed and "revoked" in d.reason and d.in_scope is True


def test_an_exclusion_still_applies_in_a_revoked_engagement():
    """A carve-out is a safety rule; honouring it in a dead engagement fails
    closed, which is the direction to fail in."""
    a = _auth(scope=["*.acme.test"], exclusions=["prod.acme.test"], status="revoked")
    d = ledger.evaluate(a, "prod.acme.test", now=TODAY)
    assert not d.allowed and d.excluded is True


def test_an_expired_engagement_gives_the_specific_reason_for_hosts_it_covers():
    a = _auth(scope=["acme.test"], expires_at="2026-01-31")
    d = ledger.evaluate_all([a], "acme.test", now=TODAY)
    assert not d.allowed and "expired" in d.reason and "2026-01-31" in d.reason


def test_a_specific_reason_wins_over_a_generic_count():
    """With several authorizations, the one that actually covers the host gets
    to explain the denial."""
    a1 = _auth(engagement_id="ENG-001", scope=["other.test"])
    a2 = _auth(engagement_id="ENG-002", scope=["acme.test"], expires_at="2026-02-01")
    d = ledger.evaluate_all([a1, a2], "acme.test", now=TODAY)
    assert not d.allowed
    assert d.engagement_id == "ENG-002" and "expired" in d.reason


def test_out_of_scope_host_is_denied():
    d = ledger.evaluate(_auth(), "someone-else.test", now=TODAY)
    assert not d.allowed and "not in the scope" in d.reason


def test_unparseable_target_is_denied():
    assert not ledger.evaluate(_auth(), "   ", now=TODAY).allowed


# ── Multiple authorizations ──────────────────────────────────────────────────

def test_an_empty_ledger_denies_everything():
    d = ledger.evaluate_all([], "acme.test", now=TODAY)
    assert not d.allowed and "empty ledger denies everything" in d.reason


def test_one_engagements_exclusion_is_not_overridden_by_anothers_scope():
    """Two clients on shared infrastructure, one of whom carved something out."""
    a1 = _auth(engagement_id="ENG-001", scope=["*.shared.test"],
               exclusions=["locked.shared.test"])
    a2 = _auth(engagement_id="ENG-002", client="Other Ltd",
               scope=["*.shared.test"])
    d = ledger.evaluate_all([a1, a2], "locked.shared.test", now=TODAY)
    assert not d.allowed and d.engagement_id == "ENG-001"


def test_a_host_in_the_second_engagement_is_allowed():
    a1 = _auth(engagement_id="ENG-001", scope=["acme.test"])
    a2 = _auth(engagement_id="ENG-002", client="Beta", scope=["beta.test"])
    d = ledger.evaluate_all([a1, a2], "beta.test", now=TODAY)
    assert d.allowed and d.engagement_id == "ENG-002"


# ── Construction validation ──────────────────────────────────────────────────

def test_an_empty_scope_is_rejected_at_construction():
    """An empty list is one keystroke from being read as 'everything'."""
    with pytest.raises(ValueError, match="empty scope"):
        _auth(scope=[])


def test_missing_required_fields_are_rejected():
    with pytest.raises(ValueError, match="recipient"):
        _auth(recipient="")


def test_expiry_before_start_is_rejected():
    with pytest.raises(ValueError, match="expires before it starts"):
        _auth(starts_at="2026-12-01", expires_at="2026-01-01")


def test_a_malformed_date_is_rejected():
    with pytest.raises(ValueError):
        _auth(expires_at="31/12/2026")


# ── Persistence and the audit trail ──────────────────────────────────────────

async def test_round_trip_through_sqlite(tmp_path):
    db = tmp_path / "ops.db"
    await ledger.init_db(db)
    await ledger.save_authorization(_auth(notes="pilot"), db)

    loaded = await ledger.load_authorizations(db)
    assert len(loaded) == 1
    assert loaded[0].scope == ["acme.test", "*.acme.test"]
    assert loaded[0].notes == "pilot"
    assert loaded[0].passive_only is True


async def test_a_missing_database_denies_rather_than_erroring(tmp_path):
    d = await ledger.check_target("acme.test", db_path=tmp_path / "absent.db",
                                  now=TODAY, record=False)
    assert not d.allowed


async def test_assert_authorized_raises_for_an_out_of_scope_target(tmp_path):
    db = tmp_path / "ops.db"
    await ledger.init_db(db)
    await ledger.save_authorization(_auth(), db)

    auth = await ledger.assert_authorized("https://www.acme.test/", db_path=db, now=TODAY)
    assert auth.engagement_id == "ENG-001"

    with pytest.raises(ledger.NotAuthorized, match="not in the scope"):
        await ledger.assert_authorized("https://evil.test/", db_path=db, now=TODAY)


async def test_revocation_takes_effect_on_the_next_decision(tmp_path):
    db = tmp_path / "ops.db"
    await ledger.init_db(db)
    await ledger.save_authorization(_auth(), db)
    assert (await ledger.check_target("acme.test", db_path=db, now=TODAY)).allowed

    assert await ledger.revoke("ENG-001", "client withdrew", db) is True
    d = await ledger.check_target("acme.test", db_path=db, now=TODAY)
    assert not d.allowed and "revoked" in d.reason


async def test_every_decision_is_recorded_for_audit(tmp_path):
    db = tmp_path / "ops.db"
    await ledger.init_db(db)
    await ledger.save_authorization(_auth(), db)

    await ledger.check_target("www.acme.test", db_path=db, now=TODAY)
    await ledger.check_target("evil.test", db_path=db, now=TODAY)

    trail = await ledger.recent_decisions(db_path=db)
    assert len(trail) == 2
    by_target = {r["target"]: r for r in trail}
    assert by_target["www.acme.test"]["allowed"] == 1
    assert by_target["evil.test"]["allowed"] == 0
    assert by_target["evil.test"]["reason"]
