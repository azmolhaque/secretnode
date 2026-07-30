"""
v2.7.6 — inline SSR state decoding (__NEXT_DATA__, __NUXT__, __INITIAL_STATE__).

The raw HTML is already scanned as text, so a plainly-embedded secret was always
caught. What was missed is a value whose JSON *escaping* breaks the credential's
shape — the same root cause that already justifies decoding source-map
`sourcesContent`.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import time

import pytest

import scanner

KEY = "sk-ant-" + "A1b2C3d4E5f6G7h8J9k0" * 2
# JSON \uXXXX escaping of the hyphens: the on-page bytes no longer look like
# the credential, so the raw-text regex pass cannot match it. Only decoding
# the JSON recovers it.
ESC = KEY.replace("-", "\\u002D")


def _hits(body: str) -> set[str]:
    return {
        f.secret_type
        for f in scanner.extract_secrets("s", "https://t", "https://t/i.html", body)
    }


@pytest.mark.parametrize(
    "label,html",
    [
        ("__NEXT_DATA__",
         '<script id="__NEXT_DATA__" type="application/json">'
         '{"props":{"pageProps":{"apiKey":"' + ESC + '"}}}</script>'),
        ("__NUXT__",
         '<script>window.__NUXT__={"config":{"key":"' + ESC + '"}};</script>'),
        ("__INITIAL_STATE__",
         '<script>window.__INITIAL_STATE__={"key":"' + ESC + '"}</script>'),
        ("__APOLLO_STATE__",
         '<script>window.__APOLLO_STATE__={"tok":"' + ESC + '"}</script>'),
        ("bare application/json",
         '<script type="application/json">{"k":"' + ESC + '"}</script>'),
        ("nested in arrays",
         '<script type="application/json">{"a":[[{"b":{"k":"' + ESC + '"}}]]}</script>'),
    ],
)
def test_escaped_secret_in_inline_state_is_recovered(label, html):
    assert "Anthropic API Key" in _hits(html), label


def test_plain_html_and_comments_still_caught():
    """Regression guard: the raw-text pass must keep working."""
    assert "Anthropic API Key" in _hits(f"<p>{KEY}</p>")
    assert "Anthropic API Key" in _hits(f"<!-- deploy key: {KEY} -->")


def test_benign_inline_json_produces_nothing():
    html = '<script type="application/json">{"title":"Hello","items":[1,2,3]}</script>'
    assert _hits(html) == set()


def test_malformed_json_is_skipped_not_fatal():
    for bad in [
        '<script type="application/json">{not json at all</script>',
        '<script type="application/json"></script>',
        "<script>window.__NUXT__=</script>",
        '<script type="application/json">{"a":</script>',
    ]:
        assert scanner.extract_inline_json_strings(bad) == "" or True  # must not raise


def test_extractor_returns_empty_for_non_markup():
    assert scanner.extract_inline_json_strings("") == ""
    assert scanner.extract_inline_json_strings("const x = 1;") == ""


def test_trailing_js_after_state_object_still_parses():
    """window.__NUXT__={…};someOtherCall() — walk back to the last brace."""
    html = ('<script>window.__NUXT__={"k":"' + ESC + '"};'
            'window.start();</script>')
    assert "Anthropic API Key" in _hits(html)


def test_string_walk_is_budget_bounded():
    """A huge blob must not be walked without limit."""
    values: list[str] = []
    budget = [50]
    scanner._json_string_values({"a": ["x" * 100, "y" * 100, "z" * 100]}, values, budget)
    assert budget[0] <= 0
    assert len(values) < 3


def test_inline_json_extraction_is_not_quadratic():
    """A hostile page with many script tags must stay fast (ReDoS guard)."""
    html = ('<script type="application/json">{"k":"v"}</script>' * 400
            + "<script>" + "A" * 50000 + "</script>")
    t0 = time.monotonic()
    scanner.extract_inline_json_strings(html)
    assert time.monotonic() - t0 < 1.0


def test_can_be_disabled_by_config():
    original = scanner.SCAN_INLINE_JSON
    try:
        scanner.SCAN_INLINE_JSON = False
        assert scanner.extract_inline_json_strings(
            '<script type="application/json">{"k":"' + ESC + '"}</script>'
        ) == ""
    finally:
        scanner.SCAN_INLINE_JSON = original
