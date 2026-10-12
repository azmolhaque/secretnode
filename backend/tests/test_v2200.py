"""
v2.20.0 — a bucket is not the same kind of fact as a font CDN.

The external-hosts graph put an S3 bucket beside `fonts.googleapis.com`. They
are not the same class of thing: a bucket URL in a shipped bundle names storage
the application reaches, whether that storage is readable by the world is the
first question any reviewer asks, and a bucket is the one piece of
infrastructure that can be exposed with **no credential leaking at all**.

`extract_referenced_hosts` could never have reported it properly, because it
keeps the hostname and discards the path — and S3 and GCS both have a path
style where the bucket IS the first path segment, while Azure always puts the
container there.

The hard line this release draws: SecretNode does not request the bucket.
Checking whether one is public means issuing a request against third-party
infrastructure the target's authorization does not cover, and which the client
may not even own.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import pytest  # noqa: E402

import orchestrator  # noqa: E402
import report  # noqa: E402
import surface  # noqa: E402

BASE = "https://acme.test/app.js"


# ── Recognising every provider's shape ───────────────────────────────────

@pytest.mark.parametrize("url,provider,bucket,style", [
    # S3 virtual-hosted, all three region spellings.
    ("https://acme-assets.s3.amazonaws.com/logo.png",
     "AWS S3", "acme-assets", "virtual-hosted"),
    ("https://acme-assets.s3.eu-west-1.amazonaws.com/logo.png",
     "AWS S3", "acme-assets", "virtual-hosted"),
    ("https://acme-assets.s3-us-west-2.amazonaws.com/logo.png",
     "AWS S3", "acme-assets", "virtual-hosted"),
    # S3 path style — the bucket is in the PATH, which the host extractor drops.
    ("https://s3.amazonaws.com/acme-backups/db.sql",
     "AWS S3", "acme-backups", "path"),
    ("https://s3.eu-central-1.amazonaws.com/acme-backups/db.sql",
     "AWS S3", "acme-backups", "path"),
    # Google Cloud Storage, both styles.
    ("https://storage.googleapis.com/acme-public/app.js",
     "Google Cloud Storage", "acme-public", "path"),
    ("https://acme-public.storage.googleapis.com/app.js",
     "Google Cloud Storage", "acme-public", "virtual-hosted"),
    # Azure names the ACCOUNT in the host; the container is what a reviewer needs.
    ("https://acmeaccount.blob.core.windows.net/uploads/file.pdf",
     "Azure Blob Storage", "uploads", "path"),
    # R2's host names the account id, same reasoning.
    ("https://abc123.r2.cloudflarestorage.com/acme-media/v.mp4",
     "Cloudflare R2", "acme-media", "path"),
    # DigitalOcean puts the region between the space and the suffix.
    ("https://acme-space.nyc3.digitaloceanspaces.com/x.css",
     "DigitalOcean Spaces", "acme-space", "virtual-hosted"),
    ("https://f002.backblazeb2.com/file/acme-files/doc.pdf",
     "Backblaze B2", "acme-files", "path"),
])
def test_every_provider_shape_is_recognised(url, provider, bucket, style):
    ref = surface.classify_storage_url(url)
    assert ref is not None, url
    assert (ref.provider, ref.bucket, ref.style) == (provider, bucket, style)


@pytest.mark.parametrize("url", [
    "https://fonts.googleapis.com/css2?family=Inter",      # the look-alike
    "https://cdn.jsdelivr.net/npm/chart.js/dist/chart.js",
    "https://acme.example.com/assets/logo.png",
    "https://s3.amazonaws.com/",                            # no bucket at all
    "https://storage.googleapis.com/",
    "https://acmeaccount.blob.core.windows.net/",           # no container
    "https://f002.backblazeb2.com/not-file/acme/doc.pdf",   # wrong path shape
    "not a url at all",
])
def test_things_that_are_not_buckets_are_not_claimed(url):
    assert surface.classify_storage_url(url) is None


def test_fonts_googleapis_is_not_mistaken_for_storage_googleapis():
    """The two share a parent domain and are completely different services.
    Matching on the parent would have put a font request in the bucket table."""
    assert surface.classify_storage_url(
        "https://fonts.googleapis.com/css2?family=Inter") is None
    assert surface.classify_storage_url(
        "https://storage.googleapis.com/acme-public/x") is not None


def test_bucket_names_shorter_than_three_characters_are_refused():
    """S3 and GCS both set 3 characters as the minimum bucket name length, so a
    one- or two-character label is something else wearing a bucket-shaped URL."""
    assert surface.classify_storage_url("https://s3.amazonaws.com/b/x") is None
    assert surface.classify_storage_url("https://s3.amazonaws.com/ab/x") is None
    assert surface.classify_storage_url("https://s3.amazonaws.com/abc/x") is not None


# ── Extracting them from a bundle ────────────────────────────────────────

class TestExtraction:
    BUNDLE = """
    // see https://fake-bucket.s3.amazonaws.com/docs for the old layout
    const CFG = {
      cdn: "https://acme-assets.s3.eu-west-1.amazonaws.com/v2/app.css",
      backups: "https://s3.amazonaws.com/acme-db-backups/nightly.sql.gz",
      media: "https://storage.googleapis.com/acme-public-media/hero.webm",
      fonts: "https://fonts.googleapis.com/css2?family=Inter"
    };
    """

    def test_it_finds_every_bucket_in_a_realistic_bundle(self):
        refs = surface.extract_storage_references(self.BUNDLE, BASE)
        assert {r.bucket for r in refs} == {
            "acme-assets", "acme-db-backups", "acme-public-media"}

    def test_a_bucket_named_only_in_a_comment_is_documentation(self):
        """Same reasoning as `extract_referenced_hosts`: a host cited in a
        comment is documentation, not infrastructure the application reaches."""
        refs = surface.extract_storage_references(self.BUNDLE, BASE)
        assert "fake-bucket" not in {r.bucket for r in refs}

    def test_the_font_cdn_does_not_appear(self):
        refs = surface.extract_storage_references(self.BUNDLE, BASE)
        assert all("fonts" not in r.host for r in refs)

    def test_protocol_relative_urls_resolve_against_the_base(self):
        refs = surface.extract_storage_references(
            'x = "//acme-assets.s3.amazonaws.com/a.png"', BASE)
        assert {r.bucket for r in refs} == {"acme-assets"}

    def test_the_host_graph_is_unchanged_by_this_release(self):
        """Buckets are reported in ADDITION to the host graph, not instead of
        it: a reader comparing the two sections should see the same hosts."""
        hosts = surface.extract_referenced_hosts(self.BUNDLE, BASE)
        assert "s3.amazonaws.com" in hosts
        assert "fonts.googleapis.com" in hosts

    def test_an_asset_with_no_storage_yields_nothing(self):
        assert surface.extract_storage_references(
            'const a = "https://example.com/x.js";', BASE) == set()


# ── One bucket, one row ──────────────────────────────────────────────────

def _scan(target: str, refs: list[dict]) -> dict:
    return {"target_url": target, "storage_references": refs,
            "confirmed_findings": [], "needs_review_findings": [],
            "informational_findings": [], "posture_findings": []}


def test_one_bucket_seen_many_ways_is_one_row():
    """The same bucket is routinely referenced through both URL styles and from
    several subdomains. That is one piece of infrastructure to check, not four
    lines to read."""
    r = orchestrator.DeepScanResult(domain="acme.test")
    r.scans = [
        _scan("https://a.acme.test", [
            {"provider": "AWS S3", "bucket": "acme-assets",
             "host": "acme-assets.s3.amazonaws.com", "style": "virtual-hosted"},
            {"provider": "AWS S3", "bucket": "acme-assets",
             "host": "s3.amazonaws.com", "style": "path"}]),
        _scan("https://b.acme.test", [
            {"provider": "AWS S3", "bucket": "acme-assets",
             "host": "acme-assets.s3.amazonaws.com", "style": "virtual-hosted"},
            {"provider": "Azure Blob Storage", "bucket": "uploads",
             "host": "x.blob.core.windows.net", "style": "path"}]),
    ]
    refs = r.to_dict()["storage_references"]
    assert [(x["provider"], x["bucket"]) for x in refs] == [
        ("AWS S3", "acme-assets"), ("Azure Blob Storage", "uploads")]


def test_a_scan_with_no_storage_reports_an_empty_list():
    r = orchestrator.DeepScanResult(domain="acme.test")
    r.scans = [_scan("https://acme.test", [])]
    assert r.to_dict()["storage_references"] == []


# ── Reaching the report, and saying what it did not do ───────────────────

class TestItReachesBothReports:
    REFS = [{"provider": "AWS S3", "bucket": "acme-db-backups",
             "host": "s3.amazonaws.com", "style": "path"}]

    def test_the_single_target_report_has_the_section(self):
        page = report.generate_html_report(_scan("https://acme.test", self.REFS))
        assert "Cloud storage referenced" in page
        assert "acme-db-backups" in page

    def test_the_deep_scan_report_has_the_section(self):
        r = orchestrator.DeepScanResult(domain="acme.test")
        r.scans = [_scan("https://acme.test", self.REFS)]
        page = report.generate_deep_scan_html(r.to_dict())
        assert "Cloud storage referenced across the domain" in page
        assert "acme-db-backups" in page

    def test_both_reports_state_that_no_bucket_was_requested(self):
        """The passive contract, written where the reader is deciding what to
        do. Without it, a bucket table reads as 'we checked these'."""
        single = report.generate_html_report(_scan("https://acme.test", self.REFS))
        r = orchestrator.DeepScanResult(domain="acme.test")
        r.scans = [_scan("https://acme.test", self.REFS)]
        deep = report.generate_deep_scan_html(r.to_dict())
        for page in (single, deep):
            assert "did not request any of them" in page

    def test_the_bucket_name_is_rendered_verbatim(self):
        """Masking it would make the row unactionable. A bucket name is
        infrastructure, not a secret — which is why it is reported here rather
        than among the findings."""
        page = report.generate_html_report(_scan("https://acme.test", self.REFS))
        assert "acme-db-backups" in page and "***" not in page

    def test_an_empty_section_says_so_rather_than_vanishing(self):
        page = report.generate_html_report(_scan("https://acme.test", []))
        assert "No cloud-storage buckets referenced." in page

    def test_the_table_escapes_what_it_renders(self):
        page = report.generate_html_report(_scan("https://acme.test", [
            {"provider": "<script>alert(1)</script>", "bucket": "b",
             "host": "h", "style": "path"}]))
        assert "<script>alert(1)</script>" not in page
        assert "&lt;script&gt;" in page


def test_no_bucket_is_ever_requested():
    """The contract, asserted against the module rather than trusted.

    Determining whether a bucket is public means issuing a request against
    third-party infrastructure the target's authorization does not cover. The
    extractor is a pure function over text that was already fetched, and it
    must stay that way.
    """
    import inspect
    src = inspect.getsource(surface)
    storage_src = src[src.index("def classify_storage_url"):]
    for forbidden in ("httpx", "requests", "urlopen", "aiohttp", "socket"):
        assert forbidden not in storage_src, (
            f"the storage extractor must make no request; found {forbidden!r}")


# ── One row per bucket ───────────────────────────────────────────────────────

class TestDedup:
    """The same bucket reached through two URL styles is one piece of
    infrastructure. Both the single-target scan and the deep scan need that
    rule, so they share one implementation."""

    REFS = [
        {"provider": "AWS S3", "bucket": "acme-assets", "style": "path",
         "host": "s3.amazonaws.com"},
        {"provider": "AWS S3", "bucket": "acme-assets", "style": "virtual-hosted",
         "host": "acme-assets.s3.eu-west-1.amazonaws.com"},
        {"provider": "Google Cloud Storage", "bucket": "acme-media",
         "style": "path", "host": "storage.googleapis.com"},
    ]

    def test_same_bucket_through_two_styles_collapses_to_one_row(self):
        out = surface.dedupe_storage_references(self.REFS)
        assert [(r["provider"], r["bucket"]) for r in out] == [
            ("AWS S3", "acme-assets"),
            ("Google Cloud Storage", "acme-media"),
        ]

    def test_the_record_kept_is_the_first_seen(self):
        """`host` and `style` become an example of where the bucket was
        referenced, not a claim that it was the only place."""
        out = surface.dedupe_storage_references(self.REFS)
        assert out[0]["style"] == "path"

    def test_same_bucket_name_at_two_providers_stays_two_rows(self):
        """Bucket names are per-provider namespaces, so `backups` on S3 and
        `backups` on GCS are different buckets and collapsing them would hide
        one of them."""
        out = surface.dedupe_storage_references([
            {"provider": "AWS S3", "bucket": "backups", "style": "path", "host": "h"},
            {"provider": "Google Cloud Storage", "bucket": "backups",
             "style": "path", "host": "h"},
        ])
        assert len(out) == 2

    def test_a_row_without_a_bucket_is_dropped_not_keyed_on_empty(self):
        """A malformed record must not become a row keyed on "", which would
        render as a blank bucket name a reviewer cannot act on."""
        assert surface.dedupe_storage_references(
            [{"provider": "AWS S3", "bucket": "", "host": "h", "style": "path"}]) == []

    def test_the_input_records_are_not_mutated(self):
        src = [dict(self.REFS[0])]
        out = surface.dedupe_storage_references(src)
        out[0]["bucket"] = "changed"
        assert src[0]["bucket"] == "acme-assets"

    def test_it_accepts_a_generator(self):
        """Both call sites pass one — the scanner a comprehension over sorted
        refs, the orchestrator a nested generator over every scan."""
        out = surface.dedupe_storage_references(r for r in self.REFS)
        assert len(out) == 2
