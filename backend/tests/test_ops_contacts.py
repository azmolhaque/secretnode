"""
v2.12.0 — tests for contact verification.

The case that motivated the module gets its own test: an address that exists
only in a search snippet, never on the company's own site, must not be
returned. That is the `now@intelligentmachin.es` bounce, encoded.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import httpx
import pytest

from ops import contacts

HOME = """
<html><body>
  <h1>Acme Robotics</h1>
  <a href="/contact-us">Contact us</a>
  <a href="/careers">Jobs</a>
  <a href="https://twitter.com/acme">Twitter</a>
  <footer>General: <a href="mailto:hello@acme.test">hello@acme.test</a></footer>
</body></html>
"""

CONTACT_PAGE = """
<html><body>
  <p>Sales: <a href="mailto:sales@acme.test">sales@acme.test</a></p>
  <p>Security reports: <a href="mailto:security@acme.test">security@acme.test</a></p>
  <p>Do not reply to noreply@acme.test</p>
</body></html>
"""

SECURITY_TXT = """Contact: mailto:psirt@acme.test
Expires: 2027-01-01T00:00:00.000Z
Preferred-Languages: en
"""


def _transport(pages: dict[str, str]):
    def handler(request: httpx.Request) -> httpx.Response:
        body = pages.get(str(request.url))
        if body is None:
            return httpx.Response(404, text="not found")
        ctype = "text/plain" if str(request.url).endswith(".txt") else "text/html"
        return httpx.Response(200, text=body, headers={"content-type": ctype})
    return httpx.MockTransport(handler)


def _client(pages: dict[str, str]) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=_transport(pages))


# ── Extraction ───────────────────────────────────────────────────────────────

def test_extracts_addresses_and_marks_mailto_links():
    found = {c.email: c for c in contacts.extract_emails(HOME, "https://acme.test/")}
    assert "hello@acme.test" in found
    assert found["hello@acme.test"].is_mailto is True


def test_extraction_deduplicates_and_prefers_the_mailto_signal():
    html = 'contact@acme.test and <a href="mailto:contact@acme.test">here</a>'
    found = contacts.extract_emails(html, "u")
    assert len(found) == 1 and found[0].is_mailto is True


def test_obfuscated_addresses_are_recovered():
    html = "Write to hello [at] acme [dot] test for anything."
    assert any(c.email == "hello@acme.test" for c in contacts.extract_emails(html, "u"))


def test_security_txt_contacts_are_extracted():
    found = contacts.extract_security_txt_contacts(SECURITY_TXT, "u")
    assert [c.email for c in found] == ["psirt@acme.test"]
    assert found[0].from_security_txt is True


# ── Scoring ──────────────────────────────────────────────────────────────────

def test_noreply_addresses_are_never_used():
    c = contacts.ContactCandidate("noreply@acme.test", "u")
    assert contacts.score_candidate(c, "acme.test") < 0
    assert contacts.rank([c], "acme.test") == []


def test_security_txt_outranks_everything():
    cands = [
        contacts.ContactCandidate("hello@acme.test", "u", is_mailto=True),
        contacts.ContactCandidate("psirt@acme.test", "u", from_security_txt=True),
    ]
    assert contacts.rank(cands, "acme.test")[0].email == "psirt@acme.test"


def test_role_priority_puts_security_above_sales():
    cands = [
        contacts.ContactCandidate("sales@acme.test", "u"),
        contacts.ContactCandidate("security@acme.test", "u"),
        contacts.ContactCandidate("marketing@acme.test", "u"),
    ]
    assert [c.email for c in contacts.rank(cands, "acme.test")][0] == "security@acme.test"


def test_an_address_on_the_companys_own_domain_outranks_a_freemail_one():
    cands = [
        contacts.ContactCandidate("acmerobotics@gmail.com", "u"),
        contacts.ContactCandidate("hello@acme.test", "u"),
    ]
    assert contacts.rank(cands, "acme.test")[0].email == "hello@acme.test"


def test_ranking_is_stable_for_identical_input():
    cands = [
        contacts.ContactCandidate("b@acme.test", "u"),
        contacts.ContactCandidate("a@acme.test", "u"),
    ]
    assert [c.email for c in contacts.rank(cands, "acme.test")] == \
           [c.email for c in contacts.rank(list(reversed(cands)), "acme.test")]


def test_a_clear_winner_is_not_treated_as_ambiguous():
    """Spending 15s of Pi inference to confirm the obvious makes the agent
    slower than doing it by hand."""
    ranked = contacts.rank([
        contacts.ContactCandidate("security@acme.test", "u"),
        contacts.ContactCandidate("marketing@acme.test", "u"),
    ], "acme.test")
    assert contacts.is_ambiguous(ranked) is False


def test_close_candidates_are_ambiguous():
    ranked = contacts.rank([
        contacts.ContactCandidate("hello@acme.test", "u"),
        contacts.ContactCandidate("contact@acme.test", "u"),
    ], "acme.test")
    assert contacts.is_ambiguous(ranked) is True


# ── Domain handling ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("host,expected", [
    ("acme.test", "acme.test"),
    ("www.acme.test", "acme.test"),
    ("a.b.acme.test", "acme.test"),
    ("acme.co.uk", "acme.co.uk"),
    ("www.acme.com.bd", "acme.com.bd"),
])
def test_registrable_domain(host, expected):
    assert contacts.registrable_domain(host) == expected


def test_same_site_rejects_lookalikes():
    assert contacts.same_site("https://www.acme.test/x", "acme.test") is True
    assert contacts.same_site("https://acme.test.evil.net/x", "acme.test") is False
    assert contacts.same_site("https://notacme.test/x", "acme.test") is False


def test_link_discovery_stays_on_site_and_ignores_mailto():
    links = contacts.discover_links(HOME, "https://acme.test/", "acme.test")
    assert "https://acme.test/contact-us" in links
    assert not any("twitter" in u for u in links)
    assert not any(u.startswith("mailto") for u in links)


# ── End to end ───────────────────────────────────────────────────────────────

async def test_finds_the_security_address_and_cites_its_page():
    pages = {
        "https://acme.test/": HOME,
        "https://acme.test/contact-us": CONTACT_PAGE,
    }
    async with _client(pages) as c:
        res = await contacts.verify_contact("acme.test", client=c,
                                            use_model=False, delay_s=0)
    assert res.verified
    assert res.chosen.email == "security@acme.test"
    assert res.chosen.source_url == "https://acme.test/contact-us"
    assert res.method == "deterministic"


async def test_security_txt_wins_when_published():
    pages = {
        "https://acme.test/": HOME,
        "https://acme.test/.well-known/security.txt": SECURITY_TXT,
        "https://acme.test/contact-us": CONTACT_PAGE,
    }
    async with _client(pages) as c:
        res = await contacts.verify_contact("acme.test", client=c,
                                            use_model=False, delay_s=0)
    assert res.chosen.email == "psirt@acme.test"


async def test_an_address_only_in_a_search_snippet_is_never_returned():
    """The bounce that motivated this module. `now@acme.test` is what a search
    result claimed; it appears nowhere on the company's own site, so it must not
    be produced no matter how confident any upstream source was."""
    pages = {"https://acme.test/": HOME}
    async with _client(pages) as c:
        res = await contacts.verify_contact("acme.test", client=c,
                                            use_model=False, delay_s=0)
    assert res.verified
    assert res.chosen.email == "hello@acme.test"
    assert all(c.email != "now@acme.test" for c in res.candidates)


async def test_no_contact_found_is_a_result_not_an_error():
    """A prospect with no published address is information, not a failure."""
    pages = {"https://acme.test/": "<html><body>No contact here.</body></html>"}
    async with _client(pages) as c:
        res = await contacts.verify_contact("acme.test", client=c,
                                            use_model=False, delay_s=0)
    assert res.verified is False
    assert "no usable contact address" in res.notes


async def test_an_unreachable_site_reports_why():
    async with _client({}) as c:
        res = await contacts.verify_contact("acme.test", client=c,
                                            use_model=False, delay_s=0)
    assert res.verified is False
    assert "Could not fetch" in res.notes


async def test_page_budget_is_respected():
    pages = {"https://acme.test/": HOME, "https://acme.test/contact-us": CONTACT_PAGE}
    async with _client(pages) as c:
        res = await contacts.verify_contact("acme.test", client=c, use_model=False,
                                            max_pages=1, delay_s=0)
    assert len(res.pages_fetched) <= 1


async def test_a_bad_domain_raises():
    with pytest.raises(contacts.ContactError):
        await contacts.verify_contact("not-a-domain", use_model=False, delay_s=0)


async def test_it_works_with_the_model_switched_off_entirely():
    """The model improves a ranking; it is never load-bearing for correctness."""
    pages = {"https://acme.test/": HOME, "https://acme.test/contact-us": CONTACT_PAGE}
    async with _client(pages) as c:
        res = await contacts.verify_contact("acme.test", client=c,
                                            use_model=False, delay_s=0)
    assert res.verified and res.method == "deterministic"


async def test_model_failure_falls_back_to_the_deterministic_ranking(monkeypatch):
    async def boom(*a, **k):
        raise RuntimeError("ollama is down")

    from ops import llm
    monkeypatch.setattr(llm, "classify", boom)

    pages = {"https://acme.test/": HOME}      # hello@ vs nothing close -> ambiguous path
    async with _client(pages) as c:
        res = await contacts.verify_contact("acme.test", client=c,
                                            use_model=True, delay_s=0)
    assert res.verified and res.method == "deterministic"


async def test_result_serialises_for_a_pipeline_record():
    pages = {"https://acme.test/": HOME, "https://acme.test/contact-us": CONTACT_PAGE}
    async with _client(pages) as c:
        res = await contacts.verify_contact("acme.test", client=c,
                                            use_model=False, delay_s=0)
    d = res.to_dict()
    assert d["email"] == "security@acme.test"
    assert d["source_url"].startswith("https://acme.test/")
    assert d["verified"] is True
