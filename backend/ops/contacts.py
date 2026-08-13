#!/usr/bin/env python3
"""
Contact verification — resolve a real contact address from a company's own site.

WHY THIS EXISTS
---------------
An outreach email to `now@intelligentmachin.es` hard-bounced because the address
came from a repeated search snippet rather than the company's own page. The
correct address was sitting in a `mailto:` link on their website the whole time.
That cost a full outreach cycle, and it is a mechanical failure with a
mechanical fix: never accept an address that cannot be pointed at on a page that
was actually fetched.

DIVISION OF LABOUR: REGEX EXTRACTS, THE MODEL ONLY CHOOSES
-----------------------------------------------------------
This is the part worth understanding before changing anything here.

  * **Extraction is deterministic.** A regex finds every address in a document
    with perfect recall and — the point — *cannot invent one*. Asking a language
    model to "find the contact email" invites it to produce `contact@` +
    domain, which is plausible, frequently wrong, and does not look wrong in
    review.
  * **The model's only job is ranking**, and only when the deterministic scorer
    is ambiguous. It picks from an enum of addresses that were actually found,
    so its answer is constrained to real candidates by construction. Choosing
    from a short list is the one task a 3B model is genuinely reliable at.
  * **Every result is grounded anyway** (`guards.assert_grounded`), as
    belt-and-braces. It should be impossible to fail by construction; it is
    checked because "impossible by construction" is a claim that survives right
    up until someone edits the constructor.

Consequence worth stating: this works with Ollama switched off. The model
improves a ranking; it is never load-bearing for correctness.

THIS IS BROWSING, NOT SCANNING
------------------------------
This fetches a handful of a company's own public pages the way a person opening
a browser would, and that distinction is the difference between research and an
unauthorised scan. It is enforced, not just intended:

  * Only the company's own registrable domain. No third-party hosts.
  * A hard cap on pages fetched, sequentially, with a delay between them.
  * Links are *followed*, not guessed — except a short allowlist of conventional
    public paths (`/contact`, `/about`, `/security`) and `/.well-known/security.txt`,
    which is an RFC 9116 invitation to be read.
  * GET only. Nothing is submitted, nothing authenticated, no unlinked-path
    discovery, no parameter fuzzing.

Deliberately NOT routed through `ops.ledger`: the ledger authorises *scanning*,
and treating "read a company's public contact page" as a scan would make the
signed-RoE gate meaningless by inflating it to cover ordinary browsing. If this
module ever grows a capability that probes rather than reads, that decision must
be revisited first.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from ops import guards

# A person opening a browser. Not a scanner fingerprint, because this is not a
# scan — and presenting as one invites a WAF block on an ordinary page read.
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
)
MAX_PAGES = 6
FETCH_TIMEOUT = 15.0
POLITE_DELAY_S = 1.0
MAX_PAGE_BYTES = 2_000_000

# Conventional public pages a human would try, plus the RFC 9116 path whose
# entire purpose is to be fetched for exactly this question.
CONVENTIONAL_PATHS = [
    "/.well-known/security.txt",
    "/contact",
    "/contact-us",
    "/about",
    "/security",
]

# Deliberately conservative: no exotic TLD gymnastics, no quoted local parts.
# A missed address costs one manual lookup; a malformed "address" that passes
# costs a bounced outreach and a wasted cycle.
EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", re.ASCII
)
MAILTO_RE = re.compile(r"""mailto:\s*([^"'?\s>]+)""", re.I)
LINK_RE = re.compile(r"""<a\b[^>]*href\s*=\s*["']([^"'#]+)["']""", re.I)
SECURITY_TXT_CONTACT_RE = re.compile(r"^\s*Contact:\s*(?:mailto:)?\s*(\S+)", re.I | re.M)

# Never contact these, whatever their score.
REJECT_LOCALPARTS = frozenset({
    "noreply", "no-reply", "donotreply", "do-not-reply", "postmaster",
    "mailer-daemon", "bounce", "bounces", "unsubscribe",
})

# Higher is better. Tuned for *this* use: a security studio introducing itself.
LOCALPART_PRIORITY: dict[str, float] = {
    "security": 10.0, "abuse": 8.0,
    "hello": 6.0, "contact": 6.0, "hi": 5.5,
    "info": 5.0, "enquiries": 5.0, "inquiries": 5.0, "office": 4.5,
    "support": 4.0, "help": 3.5,
    "sales": 2.5, "marketing": 1.5, "careers": 0.5, "jobs": 0.5, "press": 0.5,
}

# Free mail providers: a real address, but not the company's own, so it ranks
# below anything on their domain rather than being discarded.
FREEMAIL = frozenset({
    "gmail.com", "googlemail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "live.com", "icloud.com", "proton.me", "protonmail.com", "aol.com",
})


class ContactError(Exception):
    """Contact verification could not complete."""


@dataclass
class ContactCandidate:
    email: str
    source_url: str
    is_mailto: bool = False
    from_security_txt: bool = False
    score: float = 0.0
    context: str = ""

    @property
    def localpart(self) -> str:
        return self.email.split("@", 1)[0].lower()

    @property
    def domain(self) -> str:
        return self.email.split("@", 1)[1].lower()


@dataclass
class ContactResult:
    company_domain: str
    chosen: ContactCandidate | None
    candidates: list[ContactCandidate] = field(default_factory=list)
    pages_fetched: list[str] = field(default_factory=list)
    method: str = "deterministic"
    notes: str = ""

    @property
    def verified(self) -> bool:
        return self.chosen is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "company_domain": self.company_domain,
            "email": self.chosen.email if self.chosen else None,
            "source_url": self.chosen.source_url if self.chosen else None,
            "verified": self.verified,
            "method": self.method,
            "candidates": [
                {"email": c.email, "source_url": c.source_url, "score": c.score}
                for c in self.candidates
            ],
            "pages_fetched": self.pages_fetched,
            "notes": self.notes,
        }


# ── Pure extraction and scoring (no network) ─────────────────────────────────

def registrable_domain(host: str) -> str:
    """Best-effort registrable domain, without a public-suffix dependency.

    Handles the common two-label public suffixes (`co.uk`, `com.bd`, …) that
    matter for this use. Not a full PSL implementation — it is used to keep
    fetching on the company's own site, and erring toward *narrower* here means
    fetching fewer pages, never someone else's.
    """
    host = (host or "").strip().rstrip(".").lower()
    parts = [p for p in host.split(".") if p]
    if len(parts) <= 2:
        return ".".join(parts)
    two_label_suffixes = {"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne"}
    if parts[-2] in two_label_suffixes and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def same_site(url: str, company_domain: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return bool(host) and registrable_domain(host) == registrable_domain(company_domain)


def extract_emails(text: str, source_url: str) -> list[ContactCandidate]:
    """Every address in `text`, deduplicated, with `mailto:` links marked.

    A `mailto:` is a much stronger signal than a bare string: someone deliberately
    made it clickable, which is close to a statement that mail sent there is read.
    """
    normalised = guards.normalise(text)
    found: dict[str, ContactCandidate] = {}

    for m in MAILTO_RE.finditer(text):
        raw = guards.normalise(m.group(1))
        for addr in EMAIL_RE.findall(raw):
            found[addr.lower()] = ContactCandidate(
                email=addr.lower(), source_url=source_url, is_mailto=True,
            )

    for addr in EMAIL_RE.findall(normalised):
        key = addr.lower()
        if key not in found:
            found[key] = ContactCandidate(email=key, source_url=source_url)

    return list(found.values())


def extract_security_txt_contacts(text: str, source_url: str) -> list[ContactCandidate]:
    """`Contact:` lines from an RFC 9116 security.txt.

    The strongest signal available: a published, machine-readable declaration of
    where security correspondence should go. If a company has one, arguing with
    it would be perverse.
    """
    out: list[ContactCandidate] = []
    for m in SECURITY_TXT_CONTACT_RE.finditer(text):
        for addr in EMAIL_RE.findall(m.group(1)):
            out.append(ContactCandidate(
                email=addr.lower(), source_url=source_url,
                is_mailto=True, from_security_txt=True,
            ))
    return out


def score_candidate(c: ContactCandidate, company_domain: str) -> float:
    """Deterministic priority. Negative means never use."""
    if c.localpart in REJECT_LOCALPARTS:
        return -1.0

    score = LOCALPART_PRIORITY.get(c.localpart, 3.0)   # unknown local part: neutral

    if c.from_security_txt:
        score += 12.0
    elif c.is_mailto:
        score += 2.0

    if same_site(f"//{c.domain}", company_domain):
        score += 3.0
    elif c.domain in FREEMAIL:
        score -= 2.0                                   # real, but not theirs

    if "." in c.localpart and c.localpart not in LOCALPART_PRIORITY:
        score += 0.5                                   # looks like a named person
    return score


def rank(candidates: list[ContactCandidate], company_domain: str) -> list[ContactCandidate]:
    """Score, drop rejects, and sort best-first. Ties break on address for
    stability, so the same input always produces the same recommendation."""
    scored = []
    for c in candidates:
        c.score = score_candidate(c, company_domain)
        if c.score >= 0:
            scored.append(c)
    return sorted(scored, key=lambda c: (-c.score, c.email))


def is_ambiguous(ranked: list[ContactCandidate]) -> bool:
    """Is the deterministic top choice unclear enough to be worth asking a model?

    Only when the top two are close *and* neither came from security.txt. A
    clear winner needs no second opinion, and spending 15 seconds of Pi
    inference to confirm the obvious is how an agent becomes slower than doing
    it yourself.
    """
    if len(ranked) < 2:
        return False
    if ranked[0].from_security_txt:
        return False
    return (ranked[0].score - ranked[1].score) < 1.5


# ── Fetching (network, deliberately narrow) ──────────────────────────────────

async def _get(client: httpx.AsyncClient, url: str) -> str | None:
    try:
        r = await client.get(url, timeout=FETCH_TIMEOUT,
                             headers={"User-Agent": USER_AGENT},
                             follow_redirects=True)
    except Exception:  # noqa: BLE001 — an unreachable page is a normal outcome
        return None
    if r.status_code != 200:
        return None
    if len(r.content) > MAX_PAGE_BYTES:
        return None
    ctype = r.headers.get("content-type", "")
    if not any(t in ctype for t in ("text/html", "text/plain", "application/xhtml")):
        return None
    return r.text


def discover_links(html: str, base_url: str, company_domain: str) -> list[str]:
    """Same-site links that look like contact pages. Followed, never guessed."""
    wanted = ("contact", "about", "security", "team", "impressum", "support")
    out: list[str] = []
    for href in LINK_RE.findall(html):
        if href.lower().startswith(("mailto:", "tel:", "javascript:")):
            continue
        url = urljoin(base_url, href)
        if not url.startswith(("http://", "https://")):
            continue
        if not same_site(url, company_domain):
            continue
        path = (urlparse(url).path or "").lower()
        if any(w in path for w in wanted) and url not in out:
            out.append(url)
    return out


async def verify_contact(
    company_domain: str,
    *,
    client: httpx.AsyncClient | None = None,
    use_model: bool = True,
    max_pages: int = MAX_PAGES,
    delay_s: float = POLITE_DELAY_S,
) -> ContactResult:
    """Find and verify a contact address for `company_domain`.

    Never raises on "no contact found" — that is a legitimate result and is
    returned with `verified=False` and a note, because a prospect with no
    published address is information, not an error.
    """
    domain = registrable_domain(
        urlparse(company_domain if "://" in company_domain else f"//{company_domain}").hostname
        or company_domain
    )
    if not domain or "." not in domain:
        raise ContactError(f"{company_domain!r} is not a usable domain")

    own = client is None
    c = client or httpx.AsyncClient(timeout=FETCH_TIMEOUT)
    pages: dict[str, str] = {}
    candidates: list[ContactCandidate] = []

    try:
        home = f"https://{domain}/"
        html = await _get(c, home)
        if html:
            pages[home] = html
            candidates += extract_emails(html, home)

        queue = [f"https://{domain}{p}" for p in CONVENTIONAL_PATHS]
        if html:
            queue += [u for u in discover_links(html, home, domain) if u not in queue]

        for url in queue:
            if len(pages) >= max_pages:
                break
            if url in pages:
                continue
            if delay_s:
                await asyncio.sleep(delay_s)        # sequential and polite
            body = await _get(c, url)
            if not body:
                continue
            pages[url] = body
            if url.endswith("security.txt"):
                candidates += extract_security_txt_contacts(body, url)
            else:
                candidates += extract_emails(body, url)

        if not pages:
            return ContactResult(domain, None, notes=(
                f"Could not fetch any page from {domain}. The site may be down, "
                f"blocking automated requests, or the domain may be wrong."
            ))

        ranked = rank(candidates, domain)
        if not ranked:
            return ContactResult(
                domain, None, [], list(pages), notes=(
                    f"Fetched {len(pages)} page(s) but found no usable contact "
                    f"address. Check the site manually — some publish contact "
                    f"details only in an image or a form."
                ),
            )

        chosen, method, note = ranked[0], "deterministic", ""

        if use_model and is_ambiguous(ranked):
            picked = await _choose_with_model(ranked, domain)
            if picked is not None:
                chosen, method = picked, "llm-assisted"
            else:
                note = ("Top candidates scored closely; the local model was "
                        "unavailable, so the deterministic ranking was used.")

        # Belt-and-braces. Extraction came from these documents, so this cannot
        # fail — which is exactly why it is checked rather than assumed.
        try:
            cited = guards.assert_grounded(chosen.email, pages, label="contact email")
            chosen.source_url = cited
        except guards.Ungrounded as exc:
            raise ContactError(
                f"internal inconsistency: selected address is not present in any "
                f"fetched page ({exc})"
            ) from exc

        return ContactResult(domain, chosen, ranked, list(pages), method, note)
    finally:
        if own:
            await c.aclose()


async def _choose_with_model(
    ranked: list[ContactCandidate], domain: str,
) -> ContactCandidate | None:
    """Ask the local model to break a close tie. Returns None if unavailable.

    The enum is built from addresses that were actually found, so the answer is
    constrained to real candidates and an invented address is not expressible.
    """
    from ops import llm  # imported lazily: this module must work without Ollama

    shortlist = ranked[:5]
    options = [c.email for c in shortlist]
    described = "\n".join(
        f"- {c.email} (found on {c.source_url}"
        + (", in a mailto: link" if c.is_mailto else "") + ")"
        for c in shortlist
    )
    try:
        choice, _ = await llm.classify(
            text=described,
            question=(
                f"Which address at {domain} is most likely to be read by someone "
                f"who could act on an unsolicited enquiry about the security of "
                f"their public systems?"
            ),
            options=options,
        )
    except Exception:  # noqa: BLE001 — model trouble must never fail the lookup
        return None
    for c in shortlist:
        if c.email == choice:
            return c
    return None


# ── CLI ──────────────────────────────────────────────────────────────────────

async def _cli(domains: list[str], use_model: bool) -> int:
    worst = 0
    for domain in domains:
        print(f"\n{domain}")
        print("─" * max(len(domain), 40))
        try:
            res = await verify_contact(domain, use_model=use_model)
        except ContactError as exc:
            print(f"  ✗ {exc}")
            worst = 1
            continue

        if not res.verified:
            print(f"  ✗ no verified contact — {res.notes}")
            worst = 1
            continue

        print(f"  ✓ {res.chosen.email}")
        print(f"    found on : {res.chosen.source_url}")
        print(f"    method   : {res.method}")
        if len(res.candidates) > 1:
            others = ", ".join(f"{c.email} ({c.score:.1f})" for c in res.candidates[1:4])
            print(f"    also seen: {others}")
        if res.notes:
            print(f"    note     : {res.notes}")
        print(f"    pages    : {len(res.pages_fetched)} fetched")
    return worst


if __name__ == "__main__":
    import argparse
    import sys

    ap = argparse.ArgumentParser(
        prog="python3 -m ops.contacts",
        description="Resolve a verified contact address from a company's own site. "
                    "Every address returned is one that literally appears on a page "
                    "that was fetched — never a guess, never a search snippet.",
    )
    ap.add_argument("domains", nargs="+", help="company domain(s), e.g. acme.com")
    ap.add_argument("--no-model", action="store_true",
                    help="skip the local model entirely (deterministic ranking only)")
    args = ap.parse_args()

    try:
        sys.exit(asyncio.run(_cli(args.domains, use_model=not args.no_model)))
    except KeyboardInterrupt:
        sys.exit(130)
