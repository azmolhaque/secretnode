"""
v2.12.6 — the two defects an unauthorized deep scan of a real company exposed.

The scan should never have run. That it did is the first finding: the ledger had
existed for weeks and nothing in the scan path called it. The second is what the
report said afterwards — `console.log` and a dozen developer blogs listed as the
target's "third-party / connected infrastructure".
"""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import pytest

import surface
from ops import ledger


# ── Comments are not infrastructure ──────────────────────────────────────────

class TestCommentsAreNotInfrastructure:
    """A minified bundle is full of `//console.log(…)`. `_ABS_URL` matches
    protocol-relative `//host`, so every commented-out line became a hostname
    and went into a client deliverable."""

    BUNDLE = (
        "function f(){\n"
        '  //console.log("debug", x);\n'
        "  //i.test(v) ? a : b\n"
        "  // see https://stackoverflow.com/questions/1 and https://caniuse.com\n"
        "  /* ported from https://davidwalsh.name/foo\n"
        "     see also https://pastebin.com/raw/abc */\n"
        '  var u = "//cdn.real.example.com/a.js";\n'
        '  fetch("https://api.real.example.com/v1/session");\n'
        "}\n"
    )

    def test_commented_code_is_not_reported_as_a_host(self):
        hosts = surface.extract_referenced_hosts(self.BUNDLE, "https://acme.test/app.js")
        assert "console.log" not in hosts
        assert "i.test" not in hosts

    def test_documentation_links_in_comments_are_excluded(self):
        hosts = surface.extract_referenced_hosts(self.BUNDLE, "https://acme.test/app.js")
        for cited in ("stackoverflow.com", "caniuse.com",
                      "davidwalsh.name", "pastebin.com"):
            assert cited not in hosts, cited

    def test_real_references_survive(self):
        hosts = surface.extract_referenced_hosts(self.BUNDLE, "https://acme.test/app.js")
        assert hosts == {"cdn.real.example.com", "api.real.example.com"}

    def test_endpoints_exclude_comments_too(self):
        eps = surface.extract_endpoints(self.BUNDLE, "https://acme.test/app.js")
        assert eps == [
            "https://api.real.example.com/v1/session",
            "https://cdn.real.example.com/a.js",
        ]


class TestStripJsComments:
    def test_url_inside_a_string_is_untouched(self):
        """The obvious way to get this wrong: `https://` contains `//`."""
        src = 'var u = "https://real.example.com/a"; // https://fake.example.com'
        out = surface.strip_js_comments(src)
        assert "real.example.com" in out
        assert "fake.example.com" not in out

    def test_all_quote_styles_protect_their_contents(self):
        for q in ('"', "'", "`"):
            src = f"var u = {q}//keep.example.com/x{q}; //drop.example.com"
            out = surface.strip_js_comments(src)
            assert "keep.example.com" in out, q
            assert "drop.example.com" not in out, q

    def test_escaped_quote_does_not_end_the_string(self):
        src = r'var u = "a\"//still-inside.example.com"; //dropped.example.com'
        out = surface.strip_js_comments(src)
        assert "still-inside.example.com" in out
        assert "dropped.example.com" not in out

    def test_block_comment_preserves_line_count(self):
        """Offsets and line numbers must survive, so anything reported against
        this text still points at the right place."""
        src = "a\n/* x\n   y\n*/\nb\n"
        out = surface.strip_js_comments(src)
        assert len(out) == len(src)
        assert out.count("\n") == src.count("\n")

    def test_unterminated_block_comment_does_not_hang_or_leak(self):
        src = "a = 1;\n/* https://leak.example.com never closed"
        assert "leak.example.com" not in surface.strip_js_comments(src)

    def test_text_without_comments_is_returned_unchanged(self):
        src = 'const a = "x"; fetch("/api/v1");'
        assert surface.strip_js_comments(src) == src


# ── The gate that should have stopped the scan ───────────────────────────────

def _auth(scope: list[str], **kw) -> ledger.Authorization:
    return ledger.Authorization(
        engagement_id=kw.pop("engagement_id", "ENG-1"),
        client="Example Corp",
        scope=scope,
        exclusions=kw.pop("exclusions", []),
        starts_at=(date.today() - timedelta(days=1)).isoformat(),
        expires_at=(date.today() + timedelta(days=30)).isoformat(),
        recipient="security@example.com",
        roe_reference="ROE-1",
        **kw,
    )


@pytest.fixture
def seeded(tmp_path: Path, monkeypatch):
    db = tmp_path / "ops.db"

    async def _seed():
        await ledger.init_db(db)
        await ledger.save_authorization(_auth(["example.com", "*.example.com"]), db)

    asyncio.run(_seed())
    monkeypatch.setattr(ledger, "DB_PATH", db)
    monkeypatch.setattr(ledger, "REQUIRE_AUTHORIZATION", True)
    monkeypatch.setattr(ledger, "ALLOW_PRIVATE_TARGETS", False)
    return db


@pytest.fixture
def empty_ledger(tmp_path: Path, monkeypatch):
    db = tmp_path / "empty.db"
    asyncio.run(ledger.init_db(db))
    monkeypatch.setattr(ledger, "DB_PATH", db)
    monkeypatch.setattr(ledger, "REQUIRE_AUTHORIZATION", True)
    monkeypatch.setattr(ledger, "ALLOW_PRIVATE_TARGETS", False)
    return db


class TestEnforceFailsClosed:
    def test_an_unauthorized_company_is_refused(self, seeded):
        """The scan that prompted this release."""
        with pytest.raises(ledger.NotAuthorized):
            asyncio.run(ledger.enforce("pepsico.com"))

    def test_an_empty_ledger_denies_everything(self, empty_ledger):
        with pytest.raises(ledger.NotAuthorized):
            asyncio.run(ledger.enforce("example.com"))

    def test_an_authorized_target_is_allowed(self, seeded):
        auth = asyncio.run(ledger.enforce("example.com"))
        assert auth is not None and auth.engagement_id == "ENG-1"

    def test_an_authorized_subdomain_is_allowed(self, seeded):
        assert asyncio.run(ledger.enforce("api.example.com")) is not None

    def test_a_lookalike_domain_is_refused(self, seeded):
        """`notexample.com` and `example.com.evil.net` must both be denied —
        the failure mode a bare endswith() would wave through."""
        for host in ("notexample.com", "example.com.evil.net"):
            with pytest.raises(ledger.NotAuthorized):
                asyncio.run(ledger.enforce(host))

    def test_a_full_url_is_normalised_before_matching(self, seeded):
        assert asyncio.run(ledger.enforce("https://api.example.com/path?q=1")) is not None

    def test_every_decision_is_recorded(self, seeded):
        """'We only scanned what was authorised' is a claim; the trail is the
        evidence. Denials are logged as well as grants."""
        with pytest.raises(ledger.NotAuthorized):
            asyncio.run(ledger.enforce("pepsico.com"))
        rows = asyncio.run(ledger.recent_decisions(db_path=seeded))
        assert any(r["target"] == "pepsico.com" and not r["allowed"] for r in rows)


class TestEnforceEscapeHatches:
    def test_private_lab_target_skips_the_ledger(self, empty_ledger, monkeypatch):
        monkeypatch.setattr(ledger, "ALLOW_PRIVATE_TARGETS", True)
        assert asyncio.run(ledger.enforce("http://127.0.0.1:8099/")) is None

    def test_private_target_still_denied_without_the_opt_in(self, empty_ledger):
        with pytest.raises(ledger.NotAuthorized):
            asyncio.run(ledger.enforce("http://127.0.0.1:8099/"))

    def test_public_target_is_never_treated_as_a_lab_target(self, empty_ledger, monkeypatch):
        """ALLOW_PRIVATE_TARGETS is for a local lab. It must not become a
        blanket bypass for the internet."""
        monkeypatch.setattr(ledger, "ALLOW_PRIVATE_TARGETS", True)
        with pytest.raises(ledger.NotAuthorized):
            asyncio.run(ledger.enforce("pepsico.com"))

    def test_explicit_opt_out_is_honoured_but_returns_no_authorization(
        self, empty_ledger, monkeypatch
    ):
        monkeypatch.setattr(ledger, "REQUIRE_AUTHORIZATION", False)
        assert asyncio.run(ledger.enforce("pepsico.com")) is None


class TestScanPathsAreGated:
    """The gate has to be in the request path. A control an operator must
    remember to invoke is a comment, not a control."""

    def test_single_scan_endpoint_calls_enforce(self):
        import main
        src = Path(main.__file__).read_text(encoding="utf-8")
        assert "ledger.enforce(request.target_url)" in src

    def test_deep_scan_endpoint_calls_enforce(self):
        import main
        src = Path(main.__file__).read_text(encoding="utf-8")
        assert "ledger.enforce(request.domain)" in src

    def test_cli_calls_enforce(self):
        src = (Path(__file__).parent.parent / "cli.py").read_text(encoding="utf-8")
        assert "ledger.enforce(args.target)" in src
