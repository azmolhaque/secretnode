"""
v2.14.5 — the leak pattern that actually dominates shipped bundles, and the
first corpus that can measure precision from outside.

Both come from the same research question: what does a real leaked credential in
browser-delivered JavaScript look like in 2026? The answer is not an exotic
format. It is a developer putting a genuine secret behind a build-time env
prefix — NEXT_PUBLIC_, REACT_APP_, VITE_ — whose entire meaning is "publish
this to every visitor", and reading it as a naming convention.
"""

from __future__ import annotations

import csv
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

import scanner
from bench import secretbench

FW = "Framework Public Env Secret"

# Credential shapes are ASSEMBLED, never written as literals.
#
# The first version of this file spelled them out and GitHub push protection
# refused the push — correctly, and on three separate lines. A fixture shaped
# exactly like a live Stripe or Slack key is indistinguishable from one to every
# scanner that meets it, including this project's own. `bench/groundtruth.py`
# already had this discipline (`'sk_' + 'live_' + 'x' * 24`); the tests did not.
_STRIPE_LIVE = "sk_" + "live_" + "51H8xQ2eZvKYlo2CkQm7Vb3Nw"
_SLACK_BOT = "xoxb" + "-2340923409-2340923409-" + "AbCdEfGhIjKlMnOpQrStUvWx"
_GITHUB_PAT = "ghp_" + "16C7e42F292c6912E7710c838347Ae178B4a"


def _types(src: str) -> list[str]:
    return [h.secret_type for h in scanner.extract_secrets(
        "s", "https://t", "https://t/a.js", src)]


# ─────────────────────────────────────────────────────────────────────────────
# 1 · A secret behind a "public" prefix
# ─────────────────────────────────────────────────────────────────────────────

class TestFrameworkPublicEnvSecret:
    def test_the_pattern_is_registered_with_severity_and_remediation(self):
        p = scanner.PATTERN_BY_NAME[FW]
        assert p.severity == "HIGH"
        assert p.cwe
        assert "rotate" in p.remediation.lower()

    def test_a_password_behind_react_app_is_found(self):
        assert FW in _types('REACT_APP_DB_PASSWORD = "hunter2Correct!Horse9Battery"')

    def test_punctuation_in_a_password_does_not_hide_it(self):
        """The first charset allowlisted base64, so any password with a `!` in it
        was invisible — and a `_PASSWORD` is exactly where punctuation lives."""
        assert FW in _types('VITE_ADMIN_PASSWORD="P@ssw0rd!With#Symbols%Here"')

    def test_an_angular_environment_object_is_found(self):
        """Angular compiles environment.ts into the bundle with property names
        intact, which is one of the places the name actually survives."""
        assert FW in _types(
            'environment={production:!0,VUE_APP_API_SECRET:"a7Kd93MzQp1XvR4TbN8LcYeW"}')

    def test_a_supabase_service_role_key_behind_vite_is_found(self):
        assert FW in _types(
            'VITE_SUPABASE_SERVICE_ROLE_KEY:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9xyz"')

    def test_every_documented_prefix_fires(self):
        for prefix in ("NEXT_PUBLIC", "REACT_APP", "VUE_APP", "VITE",
                       "NUXT_PUBLIC", "GATSBY", "EXPO_PUBLIC", "PUBLIC"):
            src = f'{prefix}_APP_SECRET="a7Kd93MzQp1XvR4TbN8LcYeWq2Zx"'
            assert FW in _types(src), prefix

    def test_a_publishable_token_is_not_flagged(self):
        """`NEXT_PUBLIC_MAPBOX_TOKEN` is public by design. Matching on TOKEN or
        KEY alone would turn this detector into a false-positive engine aimed at
        exactly the values the informational bucket exists to clear."""
        assert FW not in _types(
            'NEXT_PUBLIC_MAPBOX_TOKEN="pk.eyJ1IjoiZGVtbyIsImEiOiJjbGFiY2RlZmcifQ"')

    def test_an_analytics_key_is_not_flagged(self):
        assert FW not in _types('NEXT_PUBLIC_POSTHOG_KEY="phc_aB3xY9zQ1mNpLkRtVwEsDfGhJ2"')

    def test_a_supabase_anon_key_is_not_flagged(self):
        """`anon` is the public half of a Supabase pair. Only `service_role` is
        the one that must never ship."""
        assert FW not in _types('PUBLIC_SUPABASE_ANON_KEY="eyJhbGciOiJIUzI1NiJ9abcdefghijk"')

    def test_a_plain_url_is_not_flagged(self):
        assert FW not in _types('NEXT_PUBLIC_API_URL="https://api.example.com/v1"')

    def test_a_real_provider_detector_wins_over_this_one(self):
        """`_collapse_duplicates` gives a typed detector priority, and it should:
        a Stripe finding carries CRITICAL and Stripe's own remediation, which is
        strictly more useful than a generic framework verdict."""
        got = _types(f'NEXT_PUBLIC_STRIPE_SECRET_KEY="{_STRIPE_LIVE}"')
        assert "Stripe Secret Key" in got
        assert FW not in got

    def test_a_value_too_short_to_be_a_credential_is_ignored(self):
        assert FW not in _types('NEXT_PUBLIC_APP_SECRET="short"')


# ─────────────────────────────────────────────────────────────────────────────
# 2 · SecretBench: measurable from outside, and safe to hold
# ─────────────────────────────────────────────────────────────────────────────

ROWS = [
    (_GITHUB_PAT, "true", "API Key", "GitHub Token"),
    (_SLACK_BOT, "true", "API Key", "Slack Token"),
    (_STRIPE_LIVE + "XyZaBcDeFg", "true", "API Key", "Stripe Secret Key"),
    ("0123456789abcdef0123456789abcdef01234567", "false", "Other", "git commit SHA"),
    ("00000000-0000-0000-0000-000000000000", "false", "Other", "null UUID"),
    ("YOUR_API_KEY_HERE", "false", "API Key", "documentation placeholder"),
]


def _export(tmp_path: Path, rows=ROWS, suffix: str = ".csv") -> Path:
    p = tmp_path / f"sb{suffix}"
    if suffix == ".csv":
        with p.open("w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["secret", "label", "category", "comment"])
            w.writerows(rows)
    else:
        import json
        p.write_text("\n".join(json.dumps(
            {"secret": s, "label": lab, "category": c, "comment": cm})
            for s, lab, c, cm in rows))
    return p


class TestExportLoading:
    def test_csv_rows_are_read_with_their_labels(self, tmp_path):
        rows = secretbench.load_export(_export(tmp_path))
        assert len(rows) == 6
        assert sum(1 for r in rows if r["label"] is True) == 3
        assert sum(1 for r in rows if r["label"] is False) == 3

    def test_jsonl_is_read_the_same_way(self, tmp_path):
        rows = secretbench.load_export(_export(tmp_path, suffix=".jsonl"))
        assert len(rows) == 6
        assert sum(1 for r in rows if r["label"] is True) == 3

    def test_an_unrecognised_label_is_excluded_rather_than_guessed(self, rows=None):
        """A guessed label silently biases whichever metric it lands in."""
        assert secretbench._is_true("maybe") is None
        assert secretbench._is_true("") is None

    def test_label_spellings_are_all_understood(self):
        for v in ("true", "TRUE", "T", "yes", "1"):
            assert secretbench._is_true(v) is True
        for v in ("false", "FALSE", "F", "no", "0"):
            assert secretbench._is_true(v) is False


class TestBucketing:
    def test_a_three_letter_provider_still_counts_as_covered(self):
        """`len(head) > 3` filed a missed AWS Access Key as "provider never
        claimed" — moving a defect into the bucket labelled not-a-defect, which
        is how a real gap goes unnoticed. aws/npm/pgp/gcp/xai are all real."""
        assert secretbench._has_detector("API Key", "AWS Access Key") is True
        assert secretbench._has_detector("API Key", "npm token") is True

    def test_a_provider_never_claimed_is_not_called_covered(self):
        assert secretbench._has_detector("API Key", "Freshdesk widget id") is False

    def test_private_keys_are_always_in_scope(self):
        assert secretbench._has_detector("Private Key", "RSA private key") is True


class TestTheDataIsHandledAsCredentials:
    def test_an_export_inside_the_repository_is_refused(self):
        """These are live credentials from real repositories. One `git add -A`
        publishes them, and this project has been bitten by that shape twice."""
        inside = secretbench.REPO_ROOT / "backend" / "bench" / "would-be-catastrophic.csv"
        inside.write_text("secret,label\nabc,true\n")
        try:
            assert secretbench._resolve(str(inside)) is None
        finally:
            inside.unlink()

    def test_an_export_outside_the_repository_is_accepted(self, tmp_path):
        assert secretbench._resolve(str(_export(tmp_path))) is not None

    def test_a_missing_export_resolves_to_none_rather_than_raising(self, tmp_path):
        assert secretbench._resolve(str(tmp_path / "absent.csv")) is None

    def test_masking_never_reveals_a_usable_value(self):
        masked = secretbench._mask(_GITHUB_PAT)
        assert _GITHUB_PAT[4:20] not in masked
        assert masked.startswith("ghp")

    def test_a_short_value_is_masked_completely(self):
        assert set(secretbench._mask("abc123")) == {"*"}


class TestMeasurement:
    def test_a_true_secret_is_probed_in_context_not_bare(self, tmp_path):
        """A naked string denies every keyword-anchored detector the context it
        legitimately relies on, which would understate recall by measuring a
        situation that does not occur in real code."""
        assert secretbench._probe(_GITHUB_PAT, "API Key")

    def test_a_labelled_non_secret_is_not_reported(self):
        assert not secretbench._probe("00000000-0000-0000-0000-000000000000", "Other")
        assert not secretbench._probe("YOUR_API_KEY_HERE", "API Key")

    def test_the_module_skips_cleanly_with_no_export(self, monkeypatch, capsys):
        monkeypatch.delenv("SECRETBENCH_EXPORT", raising=False)
        monkeypatch.setattr(sys, "argv", ["secretbench"])
        assert secretbench.main() == 0
        out = capsys.readouterr().out
        assert "skip, not a pass" in out
        assert "data protection agreement" in out


# ─────────────────────────────────────────────────────────────────────────────
# 3 · Basic-Auth URL credentials must not be assembled across string boundaries
# ─────────────────────────────────────────────────────────────────────────────

BASIC_AUTH = "Basic-Auth URL Credentials"


class TestBasicAuthUrlDoesNotCrossStringBoundaries:
    """Found by QA, not by the suite: running the new detector through the real
    pipeline surfaced a fabricated HIGH finding from a bundle that contains no
    credential at all.

    The character classes excluded only `/` and whitespace, so a match could
    start inside one JS string and end inside another. It needed a base URL with
    no path — which is exactly the form a config object holds — and that is why
    it survived this long: a `/` in the path breaks the run, so the obvious test
    cases all passed.
    """

    def test_a_package_json_shape_is_not_a_credential(self):
        assert BASIC_AUTH not in _types(
            '{"homepage":"https://acme.com","author":"dev@acme.com"}')

    def test_a_config_object_beside_a_support_email_is_not_a_credential(self):
        assert BASIC_AUTH not in _types(
            '{apiBase:"https://api.acme.com",support:"help@acme.com"}')

    def test_a_base_url_beside_any_later_at_sign_is_not_a_credential(self):
        assert BASIC_AUTH not in _types(
            'window.__env={A:"https://api.acme.test",P:"Qx7!vR2m@Lp9Zt4W"};')

    def test_a_genuine_basic_auth_url_is_still_found(self):
        """The fix must not buy precision with recall."""
        assert BASIC_AUTH in _types(
            'fetch("https://deploy:s3cretPassw0rd@artifacts.acme.test/latest.tar.gz")')

    def test_a_genuine_basic_auth_url_with_a_port_is_still_found(self):
        assert BASIC_AUTH in _types(
            'https://admin:hunter2horse@internal.acme.test:8443/api')


# ─────────────────────────────────────────────────────────────────────────────
# 4 · Un-interpolated template syntax is not a credential
# ─────────────────────────────────────────────────────────────────────────────

class TestTemplatePlaceholdersAreRejected:
    """Found by scanning this project's own diff with this scanner — it reported
    the literal `{_STRIPE_LIVE}` out of a test fixture as a credential.

    These ship for real: a broken build, a server-rendered template that never
    ran, a Docker entrypoint whose substitution failed. The allowlist already
    covered `<PLACEHOLDER>` and missed every interpolation form.
    """

    def test_shell_and_js_interpolation_is_rejected(self):
        assert scanner.is_benign_placeholder("${NEXT_PUBLIC_API_SECRET}")
        assert scanner.is_benign_placeholder("${process.env.DB_PASSWORD}")

    def test_handlebars_and_jinja_are_rejected(self):
        assert scanner.is_benign_placeholder("{{ API_SECRET }}")
        assert scanner.is_benign_placeholder("{{DATABASE_PASSWORD}}")

    def test_a_bare_brace_placeholder_is_rejected(self):
        assert scanner.is_benign_placeholder("{_STRIPE_LIVE}")

    def test_python_printf_mapping_is_rejected(self):
        assert scanner.is_benign_placeholder("%(client_secret)s")

    def test_real_values_are_still_accepted(self):
        """The fix must not buy precision with recall."""
        for v in ("Qx7!vR2m@Lp9Zt4W", "a7Kd93MzQp1XvR4TbN8LcYeWq2Zx",
                  "hunter2Correct!Horse9Battery"):
            assert not scanner.is_benign_placeholder(v)

    def test_an_uninterpolated_template_is_not_reported_end_to_end(self):
        assert FW not in _types('NEXT_PUBLIC_APP_SECRET="${BUILD_SECRET}"')
