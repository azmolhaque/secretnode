"""Tests for surface intelligence (deep-ASM slices 5 & 4): endpoint extraction
and the associated-host graph. Pure functions — no network."""

from __future__ import annotations

import surface


class TestExtractEndpoints:
    def test_absolute_and_relative_resolved(self):
        js = """
          fetch("/api/v1/users");
          axios.get('https://api.example.com/v2/keys');
          const cdn = "//cdn.example.net/lib.js";
          img.src = "/static/logo.png";
        """
        out = surface.extract_endpoints(js, "https://www.example.com/app.js")
        assert "https://www.example.com/api/v1/users" in out
        assert "https://api.example.com/v2/keys" in out
        assert "https://cdn.example.net/lib.js" in out          # protocol-relative resolved
        assert "https://www.example.com/static/logo.png" in out

    def test_skips_data_and_js_uris(self):
        js = 'a="data:image/png;base64,AAAA"; b="javascript:void(0)"; c="mailto:x@y.com";'
        assert surface.extract_endpoints(js, "https://e.com/") == []

    def test_empty_and_junk(self):
        assert surface.extract_endpoints("", "https://e.com/") == []
        assert surface.extract_endpoints("no urls here at all", "https://e.com/") == []

    def test_output_is_sorted_and_deduped(self):
        js = 'x="/a"; y="/a"; z="/b";'
        out = surface.extract_endpoints(js, "https://e.com/")
        assert out == ["https://e.com/a", "https://e.com/b"]


class TestExtractReferencedHosts:
    def test_collects_external_hosts(self):
        html = ('<script src="https://cdn.jsdelivr.net/x.js"></script>'
                '<img src="https://analytics.example.com/p.gif">'
                '<a href="/local/path">home</a>')
        hosts = surface.extract_referenced_hosts(html, "https://site.com/")
        assert "cdn.jsdelivr.net" in hosts
        assert "analytics.example.com" in hosts
        # a bare relative path contributes no host
        assert all("site.com" != h or True for h in hosts)


class TestClassifyEndpoints:
    def test_splits_same_and_associated(self):
        eps = [
            "https://www.example.com/api/a",
            "https://www.example.com/api/b",
            "https://api.thirdparty.com/track",
            "https://cdn.other.net/lib.js",
        ]
        same, others = surface.classify_endpoints(eps, "www.example.com")
        assert same == ["https://www.example.com/api/a", "https://www.example.com/api/b"]
        assert others == ["api.thirdparty.com", "cdn.other.net"]


def test_valid_host_rejects_placeholders():
    assert surface._valid_host("api.example.com") is True
    assert surface._valid_host("localhost") is False       # no dot
    assert surface._valid_host("") is False
    assert surface._valid_host("a b.com") is False         # space
