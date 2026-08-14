"""
v2.12.4 — five defects surfaced by a real deep scan of cindrasec.com, found by
reading the exported HTML/CSV/SARIF against the dashboard and the source.

The scan itself was clean. These are all bugs in how the scanner decided what
to touch and what to tell the operator afterwards.
"""

from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import orchestrator
import scanner
import surface


# ── 1. Scope: str.lstrip("www.") is not prefix removal ───────────────────────

class TestSameScopeLstripRegression:
    """`base_host.lower().lstrip("www.")` stripped a CHARACTER SET, not a
    prefix. This gate decides whether a request leaves the box, so the
    over-accepting direction was an unauthorized fetch, not a cosmetic bug.

    Every pre-existing test used example.com, where the lstrip is a no-op —
    the fixture could not fail. These use hosts that actually trip it."""

    def test_leading_w_domain_does_not_admit_a_stranger(self):
        # "web3forms.com".lstrip("www.") == "eb3forms.com"
        assert not surface.same_scope("web3forms.com", "eb3forms.com")
        assert not surface.same_scope("web3forms.com", "evil.eb3forms.com")

    def test_leading_w_domain_does_not_admit_shortened_root(self):
        # "wolf.com" -> "olf.com";  "w3.org" -> "3.org"
        assert not surface.same_scope("wolf.com", "olf.com")
        assert not surface.same_scope("w3.org", "3.org")

    def test_repeated_w_domain_still_owns_its_subdomains(self):
        # "wwf.org".lstrip("www.") == "f.org", which rejected assets.wwf.org
        assert surface.same_scope("wwf.org", "assets.wwf.org")
        assert surface.same_scope("wwf.org", "wwf.org")

    def test_www_prefix_is_still_equivalent_to_bare_host(self):
        assert surface.same_scope("www.cindrasec.com", "cindrasec.com")
        assert surface.same_scope("cindrasec.com", "www.cindrasec.com")

    def test_original_guarantees_preserved(self):
        assert surface.same_scope("example.com", "example.com")
        assert surface.same_scope("example.com", "cdn.example.com")
        assert not surface.same_scope("example.com", "evil.com")
        assert not surface.same_scope("example.com", "notexample.com")

    def test_empty_hosts_are_never_in_scope(self):
        assert not surface.same_scope("", "example.com")
        assert not surface.same_scope("example.com", "")

    def test_scanner_gate_delegates_to_one_implementation(self):
        """The fetch decision and the domain report must not be able to
        disagree about what in-scope means."""
        assert not scanner._same_scope("web3forms.com", "eb3forms.com")
        assert scanner._same_scope("wwf.org", "assets.wwf.org")


# ── 2. robots.txt: RFC 9309 groups, not a file-wide grep ─────────────────────

class TestRobotsGroupParsing:
    """`re.search(r"^disallow:\\s*/\\s*$", body)` matched a Disallow inside ANY
    group. One Cloudflare-managed AI-crawler block was enough to make the
    scanner announce that the target "disallows all crawling" while every
    general-purpose crawler was free to fetch the whole site."""

    CINDRASEC_ROBOTS = (
        "User-agent: *\n"
        "Disallow: /src/\n"
        "Disallow: /build.py\n"
        "Allow: /\n"
        "\n"
        "User-agent: GPTBot\n"
        "Allow: /\n"
    )
    AI_BLOCKED = CINDRASEC_ROBOTS + (
        "\n"
        "User-agent: AI2Bot\n"
        "Disallow: /\n"
        "\n"
        "User-agent: Amazonbot\n"
        "Disallow: /\n"
    )

    def _wildcard(self, body):
        groups = scanner.parse_robots_groups(body)
        return next(((r, d) for a, r, d in groups if "*" in a), None)

    def test_path_scoped_disallows_do_not_block_the_root(self):
        rules, _delay = self._wildcard(self.CINDRASEC_ROBOTS)
        assert not scanner._group_blocks_root(rules)

    def test_named_agent_block_does_not_block_the_wildcard(self):
        """The exact false positive observed on cindrasec.com."""
        rules, _delay = self._wildcard(self.AI_BLOCKED)
        assert not scanner._group_blocks_root(rules)

    def test_named_agent_blocks_are_still_detected(self):
        groups = scanner.parse_robots_groups(self.AI_BLOCKED)
        blocked = sorted({
            a for agents, rules, _d in groups
            for a in agents
            if a != "*" and scanner._group_blocks_root(rules)
        })
        assert blocked == ["ai2bot", "amazonbot"]

    def test_genuine_wildcard_disallow_all_is_detected(self):
        rules, _delay = self._wildcard("User-agent: *\nDisallow: /\n")
        assert scanner._group_blocks_root(rules)

    def test_allow_root_wins_the_length_tie(self):
        """Google resolves conflicts by longest match, ties to Allow."""
        rules, _delay = self._wildcard("User-agent: *\nDisallow: /\nAllow: /\n")
        assert not scanner._group_blocks_root(rules)

    def test_consecutive_user_agents_share_one_group(self):
        groups = scanner.parse_robots_groups(
            "User-agent: a\nUser-agent: b\nDisallow: /\n"
        )
        assert len(groups) == 1
        assert groups[0][0] == ["a", "b"]
        assert scanner._group_blocks_root(groups[0][1])

    def test_user_agent_after_rules_opens_a_new_group(self):
        groups = scanner.parse_robots_groups(
            "User-agent: a\nDisallow: /\nUser-agent: b\nAllow: /\n"
        )
        assert [g[0] for g in groups] == [["a"], ["b"]]

    def test_comments_and_blank_lines_are_ignored(self):
        groups = scanner.parse_robots_groups(
            "# a comment\n\nUser-agent: *  # trailing\nDisallow: /   # blocked\n"
        )
        assert groups[0][0] == ["*"]
        assert scanner._group_blocks_root(groups[0][1])

    def test_rules_before_any_user_agent_are_discarded(self):
        assert scanner.parse_robots_groups("Disallow: /\n") == []

    def test_crawl_delay_is_captured(self):
        _rules, delay = self._wildcard("User-agent: *\nCrawl-delay: 2.5\nDisallow: /x\n")
        assert delay == 2.5

    def test_malformed_crawl_delay_is_ignored(self):
        _rules, delay = self._wildcard("User-agent: *\nCrawl-delay: soon\nDisallow: /x\n")
        assert delay is None


class TestRobotsBroadcast:
    """End-to-end through check_robots_txt: what does the operator actually see?"""

    class _Resp:
        def __init__(self, text, status_code=200):
            self.text, self.status_code = text, status_code

    class _Client:
        def __init__(self, resp):
            self._resp = resp

        async def get(self, _url, **_kw):
            return self._resp

    def _messages(self, body, status_code=200):
        sent: list[dict] = []

        async def broadcast(msg):
            sent.append(msg)

        client = self._Client(self._Resp(body, status_code))
        asyncio.run(scanner.check_robots_txt(client, "https://acme.test/", broadcast))
        return sent

    def test_ai_blocking_no_longer_warns_about_all_crawling(self):
        msgs = self._messages(TestRobotsGroupParsing.AI_BLOCKED)
        assert not any(m.get("level") == "WARN" for m in msgs)
        info = " ".join(m["message"] for m in msgs if m.get("level") == "INFO")
        assert "2 named user-agent(s)" in info
        assert "general crawling is permitted" in info

    def test_real_disallow_all_still_warns(self):
        msgs = self._messages("User-agent: *\nDisallow: /\n")
        warns = [m for m in msgs if m.get("level") == "WARN"]
        assert len(warns) == 1
        assert "disallows all crawling" in warns[0]["message"]

    def test_clean_robots_says_nothing(self):
        assert self._messages(TestRobotsGroupParsing.CINDRASEC_ROBOTS) == []

    def test_crawl_delay_is_surfaced(self):
        msgs = self._messages("User-agent: *\nCrawl-delay: 3\nDisallow: /admin\n")
        assert any("3s crawl-delay" in m["message"] for m in msgs)

    def test_missing_robots_is_not_an_error(self):
        assert self._messages("", status_code=404) == []


# ── 5. The target's own hosts are not third-party infrastructure ─────────────

class TestAssociatedHostClassification:
    """cindrasec.com appeared in cindrasec.com's own client report under
    "Associated hosts (third-party / connected infrastructure)", because the
    www. scan compared hostnames with `host == base_host`."""

    def test_apex_is_in_scope_when_scanning_www(self):
        same, others = surface.classify_endpoints(
            ["https://cindrasec.com/app.js", "https://api.web3forms.com/submit"],
            "www.cindrasec.com",
        )
        assert same == ["https://cindrasec.com/app.js"]
        assert others == ["api.web3forms.com"]

    def test_sibling_subdomain_is_in_scope(self):
        same, others = surface.classify_endpoints(
            ["https://cdn.acme.test/a.js", "https://cdn.other.test/b.js"], "www.acme.test"
        )
        assert same == ["https://cdn.acme.test/a.js"]
        assert others == ["cdn.other.test"]

    def test_explicit_scope_hosts_are_honoured(self):
        """A deep scan's enumerated hosts count as the target even when they do
        not share a registrable root (vanity domains, regional TLDs)."""
        same, others = surface.classify_endpoints(
            ["https://acme.co.uk/a.js"], "acme.test", scope_hosts={"acme.co.uk"}
        )
        assert same == ["https://acme.co.uk/a.js"]
        assert others == []

    def test_classification_is_symmetric_across_apex_and_www(self):
        """Identical content served at both hosts must produce the same counts —
        the asymmetry that showed up as 24 endpoints / 8 hosts against 19 / 9."""
        eps = [
            "https://cindrasec.com/app.js",
            "https://www.cindrasec.com/app.js",
            "https://api.web3forms.com/submit",
        ]
        apex = surface.classify_endpoints(eps, "cindrasec.com")
        www = surface.classify_endpoints(eps, "www.cindrasec.com")
        assert apex == www
        assert len(apex[0]) == 2 and apex[1] == ["api.web3forms.com"]

    def test_domain_report_excludes_the_targets_own_hosts(self):
        """orchestrator union, as it reaches the client-facing report."""
        result = orchestrator.DeepScanResult(domain="cindrasec.com")
        result.scans = [
            {"associated_hosts": ["cindrasec.com", "github.com"]},
            {"associated_hosts": ["www.cindrasec.com", "api.web3forms.com"]},
        ]
        assoc = result.to_dict()["associated_hosts"]
        assert "cindrasec.com" not in assoc
        assert "www.cindrasec.com" not in assoc
        assert assoc == ["api.web3forms.com", "github.com"]
