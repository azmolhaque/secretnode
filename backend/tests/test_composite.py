"""
R7 — the composite/proximity rule engine, and the false negative it closes.

Several registry detectors are keyword-anchored: they only match when the
provider's name sits beside the value.

    AWS Secret Access Key   (?i)aws.{0,20}secret.{0,20}['"]([A-Za-z0-9/+=]{40})['"]

The keyword is doing all the work, and a bundler deletes it. What ships is

    {a:"AKIA…",b:"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}

so the scan reports the half that is a public identifier and misses the half
that is the actual credential.

The first test below fails against the pre-R7 scanner. The rest are the
precision discipline that keeps the fix from becoming a false-positive engine —
including the git-SHA case, which the ground-truth benchmark caught on the first
run of the unconstrained rule.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import composite  # noqa: E402
import scanner  # noqa: E402

# Assembled from parts rather than written as literals. Spelled out in full,
# GitHub's push protection blocks the commit: these authenticate to nothing, but
# they are correctly SHAPED credentials, which is exactly the property that makes
# them useful here. `bench/groundtruth.py` already does this for the same reason
# (see its masked-secret decoy) — a test suite that cannot be committed is not a
# test suite, and the values are identical once built.
AKIA = "AKIA" + "Z7QF3XBNQ2WKLMNP"
# 40 characters, mixed alphabet — deliberately NOT AWS's documentation secret.
#
# This fixture used to end in `EXAMPLEK3yQ`, borrowing the shape of AWS's public
# sample key. v2.15.0 added the `EXAMPLE` marker to the placeholder allowlist,
# because vendors mark their documentation credentials that way and reporting one
# is a false positive — so this test began asserting that the scanner reports a
# documentation sample. The composite rule is about pairing an ID with a nearby
# secret; the fixture only ever needed a realistic 40-character value.
AWS_SECRET = "wJalrXUtnFEMI7K9" + "MDENGbPxRfiCY" + "hT4uQm2K3yQ"   # 40, mixed alphabet
TWILIO_SID = "AC" + "9f3b2a1c4d5e6f708192a3b4c5d6e7f8"
TWILIO_TOKEN = "1a2b3c4d5e6f708192a3b4c5d6e7f809"


def _scan(text, source="https://t/app.js"):
    return scanner.extract_secrets("s", "https://t", source, text)


def _types(findings):
    return {f.secret_type for f in findings}


# ── the false negative ───────────────────────────────────────────────────────

def test_a_minified_aws_pair_is_no_longer_half_missed():
    """The regression this whole module exists for. Fails before R7: the
    keyword-anchored detector sees no 'aws' and no 'secret', so only the public
    identifier is reported."""
    bundle = f'var n={{a:"{AKIA}",b:"{AWS_SECRET}"}},r=n.a;'
    found = _scan(bundle)

    assert "AWS Access Key" in _types(found), "the ID was always found"
    assert "AWS Secret Access Key" in _types(found), (
        "the secret half is the actual credential and used to be missed entirely"
    )
    secret = next(f for f in found if f.secret_type == "AWS Secret Access Key")
    assert secret.raw_match == AWS_SECRET


def test_the_finding_carries_its_own_justification():
    """A shapeless 40-character string reported as CRITICAL has to be able to
    show its reasoning, or an analyst is right to distrust it."""
    found = _scan(f'var n={{a:"{AKIA}",b:"{AWS_SECRET}"}};')
    secret = next(f for f in found if f.secret_type == "AWS Secret Access Key")
    assert "composite" in secret.context_snippet
    assert "AKIA" in secret.context_snippet


def test_a_twilio_token_is_identified_by_the_sid_beside_it():
    bundle = f'var c={{sid:"{TWILIO_SID}",tok:"{TWILIO_TOKEN}"}};'
    found = _scan(bundle)
    assert "Twilio Auth Token" in _types(found)


def test_an_oauth_client_secret_is_found_beside_its_client_id():
    bundle = 'cfg={client_id:"app-12345",client_secret:"Zx9KpLmQr7TvWy2BnHs4"};'
    found = _scan(bundle)
    assert "OAuth Client Secret" in _types(found)


# ── precision discipline ─────────────────────────────────────────────────────

def test_a_git_sha_next_to_an_akia_is_not_an_aws_secret():
    """The false positive the ground-truth benchmark caught on the first run.
    A 40-hex commit hash is exactly as long as an AWS secret key and appears in
    essentially every build, so proximity alone made every such build produce a
    CRITICAL finding on a value that is public by definition."""
    sha = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
    found = _scan(f'var n={{k:"{AKIA}"}},COMMIT="{sha}";')
    assert "AWS Secret Access Key" not in _types(found)


def test_the_mixed_alphabet_rule_is_what_separates_them():
    assert composite._mixed_alphabet(AWS_SECRET) is True
    assert composite._mixed_alphabet("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0") is False
    assert composite._mixed_alphabet("A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0") is False


def test_distance_matters():
    """Two values a kilobyte apart are not a pair. If proximity did not
    constrain anything the rule would be 'any 40-char base64 in a file that
    also contains an AKIA', which is most bundles."""
    far = f'var a="{AKIA}";' + ("/* padding */" * 100) + f'var b="{AWS_SECRET}";'
    assert "AWS Secret Access Key" not in _types(_scan(far))


def test_the_anchor_is_never_reported_as_its_own_companion():
    """A Twilio SID is AC + 32 hex, and the companion pattern is 32 hex. Without
    an overlap check the rule reports the public identifier as the credential."""
    matches = composite.find_composites(f'var s="{TWILIO_SID}";')
    assert not [m for m in matches if m.value in TWILIO_SID]


def test_an_anchorless_document_costs_nothing():
    """Anchors are rare by construction, and the early exit on 'no anchor' is
    what keeps this pass affordable on every asset of every scan."""
    assert composite.find_composites('var x="' + AWS_SECRET + '";') == []


def test_a_placeholder_companion_is_still_filtered():
    """The composite rule supplies an identity, not a licence to skip the gates
    every other detector passes through."""
    found = _scan(f'var n={{a:"{AKIA}",b:"YOUR_AWS_SECRET_KEY_HERE_XXXXXXXXXXXXXXX"}};')
    assert "AWS Secret Access Key" not in _types(found)


def test_the_match_count_is_bounded():
    """Defence in depth against a pathological blob, mirroring the per-pattern
    match cap the main scanner applies."""
    blob = f'"{AKIA}",' + ",".join(f'"{AWS_SECRET}"' for _ in range(200))
    matches = [m for m in composite.find_composites(blob) if m.secret_type == "AWS Secret Access Key"]
    assert len(matches) <= 25


# ── ranking against the real detectors ───────────────────────────────────────

def test_a_real_detector_outranks_the_composite_claim_on_the_same_value():
    """When the keyword IS present, both the registry detector and the composite
    rule claim the value. Reporting both would double-count one credential and
    spend two AI-validation calls on one string."""
    text = f'const awsSecretAccessKey = "{AWS_SECRET}"; const id = "{AKIA}";'
    found = _scan(text)
    aws_secrets = [f for f in found if f.raw_match == AWS_SECRET]
    assert len(aws_secrets) == 1, "one credential, one finding"


def test_the_generic_catch_all_still_loses_to_everything():
    assert scanner._claim_rank(scanner.GENERIC_SECRET_TYPE) == 0
    assert scanner._claim_rank("AWS Secret Access Key") == 1, (
        "composite-reachable types rank below a pure registry match"
    )
    assert scanner._claim_rank("GitHub Personal Access Token") == 2


def test_composite_can_be_switched_off(monkeypatch):
    monkeypatch.setattr(scanner, "SCAN_COMPOSITE", False)
    found = _scan(f'var n={{a:"{AKIA}",b:"{AWS_SECRET}"}};')
    assert "AWS Secret Access Key" not in _types(found)
    assert "AWS Access Key" in _types(found), "only the composite pass is disabled"


# ── the benchmark must still be clean ────────────────────────────────────────

def test_the_labelled_corpus_is_unaffected():
    """R7 adds a detection path, so the precision gate has to be re-measured
    rather than assumed."""
    from bench import corpus as corpus_mod

    c = corpus_mod.CORPUS
    for sample in c:
        if sample.expect is not None:
            continue
        found = _scan(sample.text)
        assert not found, f"negative {sample.id} produced {[f.secret_type for f in found]}"


@pytest.mark.parametrize("rule", composite.COMPOSITE_RULES, ids=lambda r: r.name)
def test_every_rule_names_a_type_the_registry_knows(rule):
    """A composite finding whose type is absent from the registry would fall
    back to MEDIUM/CWE-798 in `_meta()`, silently losing the severity and the
    remediation text the report is supposed to carry."""
    assert rule.name in scanner.PATTERN_BY_NAME, (
        f"{rule.name} has no registry entry, so its severity and remediation "
        f"would silently degrade to the generic fallback"
    )
