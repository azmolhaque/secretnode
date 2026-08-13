#!/usr/bin/env python3
"""
Safety guards for the operations layer.

Two independent problems, both of which have to be solved before an unattended
business process may use a language model.

1. GROUNDING — stopping invented facts reaching a business decision
------------------------------------------------------------------
A schema constrains shape, not truth. `{"email": "contact@acme.com"}` satisfies
any reasonable schema and may be pure invention — and it is a *plausible*
invention, which is worse, because it will not look wrong in review. Outreach
sent to a fabricated address is the exact failure that already cost a cycle when
`now@intelligentmachin.es` bounced.

`assert_grounded` inverts the trust: the model does not get to assert a fact, it
gets to *point at* one. The extracted value must literally appear in a source
document that was actually fetched. If it does not, it is rejected — no matter
how confident the model was, and no matter how plausible the value looks.

This makes hallucination structurally unable to pass through, rather than
something reviewers are asked to catch.

2. PROMPT HYGIENE — not feeding credentials to a model
-------------------------------------------------------
This layer sits next to a scanner whose entire job is finding live credentials.
Passing a finding to a model for summarising would put a working secret into a
prompt. Locally that is merely wrong; the day any of this is pointed at a hosted
model it becomes a client-credential disclosure by the security vendor.

So prompts are scanned before they are sent, using SecretNode's own 63
detectors. The tool that finds other people's exposed secrets is not permitted
to leak them itself.

Both guards fail closed and raise. Neither silently sanitises and continues,
because a caller that does not know its data was altered will misreport what
happened.
"""

from __future__ import annotations

import html
import re
import unicodedata

import scanner  # flat import — see the repo's documented import convention


class GuardError(Exception):
    """Base for guard failures."""


class Ungrounded(GuardError):
    """A claimed value does not appear in any provided source document."""


class SecretInPrompt(GuardError):
    """A prompt contained something the scanner recognises as a credential."""


# ── Grounding ────────────────────────────────────────────────────────────────

_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿"))


def normalise(text: str) -> str:
    """Fold the presentation differences that hide a literal match.

    A site writes `contact [at] acme.com`, or `contact&#64;acme.com`, or splits
    an address with a zero-width space to defeat scrapers. All three are the
    same address, and a naive substring check would reject a perfectly real
    extraction and send a human off to verify something that was already right.

    Only *unambiguous* obfuscations are folded. Anything requiring a guess about
    intent is left alone, because a false accept here means outreach to an
    address nobody at the company reads.
    """
    t = unicodedata.normalize("NFKC", text)
    t = t.translate(_ZERO_WIDTH)
    t = html.unescape(t)
    t = re.sub(r"\s*\[\s*at\s*\]\s*|\s*\(\s*at\s*\)\s*|\s+at\s+", "@", t, flags=re.I)
    t = re.sub(r"\s*\[\s*dot\s*\]\s*|\s*\(\s*dot\s*\)\s*|\s+dot\s+", ".", t, flags=re.I)
    t = re.sub(r"\s+", " ", t)
    return t.strip().lower()


def assert_grounded(
    value: str,
    sources: dict[str, str],
    *,
    label: str = "value",
) -> str:
    """Require `value` to literally appear in one of `sources`. Returns its key.

    `sources` maps an identifier a human can check — a URL, a file path — to the
    text actually retrieved from it. The returned key becomes the citation
    recorded alongside the extracted fact, so any later reader can go and look.

    Raises `Ungrounded` if nothing matches. That is the point: an unsupported
    extraction stops here rather than travelling onward as a fact.
    """
    if not value or not value.strip():
        raise Ungrounded(f"{label} is empty — nothing to ground")
    if not sources:
        raise Ungrounded(f"no source documents supplied to ground {label} against")

    needle = normalise(value)
    for key, doc in sources.items():
        if needle and needle in normalise(doc or ""):
            return key

    raise Ungrounded(
        f"{label} {value!r} does not appear in any of the {len(sources)} source "
        f"document(s): {', '.join(list(sources)[:3])}"
        + (" …" if len(sources) > 3 else "")
        + ". Treating it as invented rather than accepting it."
    )


def ground_all(
    values: dict[str, str],
    sources: dict[str, str],
) -> dict[str, str]:
    """Ground several extracted fields at once. Returns {field: source_key}.

    All-or-nothing: the first ungrounded field raises. A partially-verified
    record is more dangerous than an unverified one, because it carries the
    credibility of the fields that did check out.
    """
    return {
        field: assert_grounded(val, sources, label=field)
        for field, val in values.items()
    }


# ── Prompt hygiene ───────────────────────────────────────────────────────────

def find_secrets(text: str) -> list[str]:
    """Secret types the scanner recognises in `text`. Empty list means clean."""
    findings = scanner.extract_secrets(
        scan_id="ops-prompt-guard",
        target_url="internal://ops",
        source_url="internal://ops/prompt",
        text=text,
    )
    # De-duplicated, order-stable: a caller logs these, and a stable list keeps
    # a repeated failure recognisable as the same failure.
    seen: list[str] = []
    for f in findings:
        if f.secret_type not in seen:
            seen.append(f.secret_type)
    return seen


def assert_no_secrets(text: str, *, context: str = "prompt") -> None:
    """Refuse to send credential-bearing text to a model.

    Fails closed and names the *types* found, never the values — an exception
    message ends up in logs, and logging the credential to explain that it must
    not be transmitted would defeat the guard it is enforcing.
    """
    found = find_secrets(text)
    if found:
        raise SecretInPrompt(
            f"Refusing to send {context} to a language model: it contains "
            f"{len(found)} credential type(s) the scanner recognises "
            f"({', '.join(found)}). Redact before calling. Values are "
            f"deliberately omitted from this message."
        )


def safe_prompt(text: str, *, context: str = "prompt") -> str:
    """`assert_no_secrets` then return the text, for use inline at a call site."""
    assert_no_secrets(text, context=context)
    return text
