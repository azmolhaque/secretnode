"""
R5 — source-map surface expansion.

A JS source map embeds the ORIGINAL, un-minified source in `sourcesContent`.
The raw .map is scanned as text, but secrets in the original source are often
escaped/structured there (or absent from the shipped bundle entirely). These
tests cover decoding that embedded source into scannable, per-file-attributed
code — and the defensive handling around it.
"""

import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import scanner

_A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def _awskey(seed: str = "s") -> str:
    h = hashlib.sha256(seed.encode()).digest()
    return "AKIA" + "".join(_A[b % len(_A)] for b in h[:16])


def _map(sources, contents) -> str:
    return json.dumps({"version": 3, "sources": sources, "sourcesContent": contents, "mappings": "AAAA"})


def test_extract_sources_decodes_and_pairs_names():
    body = _map(["src/config.js", "src/app.js"], ["const A = 1;", "const B = 2;"])
    out = scanner.extract_sourcemap_sources(body, "https://x.com/app.js.map")
    assert len(out) == 2
    assert out[0][0].endswith("src/config.js") and out[0][1] == "const A = 1;"
    assert out[1][0].endswith("src/app.js")


def test_malformed_map_returns_empty():
    assert scanner.extract_sourcemap_sources("{not json", "u") == []
    assert scanner.extract_sourcemap_sources("[]", "u") == []           # not a dict
    assert scanner.extract_sourcemap_sources('{"version":3}', "u") == []  # no sourcesContent


def test_null_and_nonstring_entries_are_skipped():
    body = _map(["a.js", "b.js", "c.js"], ["const A=1;", None, 123])
    out = scanner.extract_sourcemap_sources(body, "m")
    assert len(out) == 1 and out[0][1] == "const A=1;"


def test_looks_like_sourcemap_detection():
    assert scanner.looks_like_sourcemap("https://x.com/app.js.map", "")
    assert scanner.looks_like_sourcemap("https://x.com/app.js.map?v=2", "")
    assert scanner.looks_like_sourcemap("https://x.com/bundle", '{"version":3,"mappings":"A","sources":[]}')
    assert scanner.looks_like_sourcemap("u", '{"sourcesContent":["x"]}')
    assert not scanner.looks_like_sourcemap("https://x.com/app.js", "console.log(1)")


def test_secret_in_original_source_is_found_and_attributed():
    """A secret living in the map's original source is decoded, scanned, and
    reported against a precise per-file virtual source URL (R5's core value)."""
    key = _awskey("r5")
    body = _map(["src/secrets.js"], [f'export const AWS_KEY = "{key}";'])
    for vsrc_url, content in scanner.extract_sourcemap_sources(body, "https://x.com/app.js.map"):
        findings = scanner.extract_secrets("s", "https://x.com", vsrc_url, content)
        aws = [f for f in findings if f.secret_type == "AWS Access Key"]
        assert aws, "AWS key in sourcesContent was not detected"
        assert aws[0].raw_match == key
        assert "src/secrets.js" in aws[0].source_url   # precise attribution


def test_respects_max_sources_cap(monkeypatch):
    monkeypatch.setattr(scanner, "MAX_SOURCEMAP_SOURCES", 5)
    body = _map([f"s{i}.js" for i in range(50)], [f"const X{i}=1;" for i in range(50)])
    out = scanner.extract_sourcemap_sources(body, "m")
    assert len(out) == 5
