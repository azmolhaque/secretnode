#!/usr/bin/env python3
"""
External-validity recall, measured against a corpus nobody here wrote.

    python -m bench.external            # fetches, measures, prints
    python -m bench.external --offline  # skips if the corpus is not cached

WHY THIS EXISTS
---------------
`bench/groundtruth.py` prints its own caveat on every run, and it is the honest
one: every specimen there was built to satisfy SecretNode's own regexes, so a
detector matching its own canonical example proves the detector is wired up, not
that it catches credentials in the wild. 70/70 is a regression net and a
precision measurement. It is not a recall number anyone outside this repository
should believe.

This module answers the other question, using gitleaks' rule definitions as the
corpus: literal specimens written by a different project, for a different
scanner, with no knowledge of these patterns. That is what makes the number
mean something.

WHAT IT MEASURES, AND WHAT IT DELIBERATELY SEPARATES
----------------------------------------------------
A raw percentage would blur three very different outcomes, so they are reported
apart:

  detected      the specimen was found.
  in-scope miss SecretNode has a detector for that provider and did not find
                it. This is the only bucket that is a defect.
  no detector   SecretNode never claimed to cover that provider. A roadmap
                fact, not a failure — gitleaks carries ~220 rules to this
                scanner's 70, and breadth was never the differentiator.

Specimens containing regex metacharacters are dropped. gitleaks builds many of
its samples from pattern fragments, and counting `api_org_(?i:[a-z]{34})` as a
missed credential would understate recall by scoring something no scanner could
ever match — the measuring instrument being wrong about the tool, which is the
one thing a benchmark must never be.

WHY THE CORPUS IS NOT VENDORED
------------------------------
It is ~240 KB of third-party source whose entire purpose is to contain
credential-shaped strings. Committing it would trip GitHub push protection and
copy another project's test data into this repository for no benefit. It is
fetched on demand and cached outside version control; with no network the run
skips and says so rather than reporting a number it did not measure.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "bench-external")

import scanner  # noqa: E402

RAW = "https://raw.githubusercontent.com/gitleaks/gitleaks/master/cmd/generate/config/rules/"
MAIN = "https://raw.githubusercontent.com/gitleaks/gitleaks/master/cmd/generate/config/main.go"
CACHE = Path(os.environ.get("EXTERNAL_CORPUS_CACHE", "")) if os.environ.get(
    "EXTERNAL_CORPUS_CACHE") else Path(__file__).resolve().parent / ".external-cache.json"

# Suffixes stripped to turn a Go constructor name into its likely file name.
_SUFFIXES = [
    "apikeylonglived", "apikeyshortlived", "serviceaccounttoken",
    "personalaccesstoken", "accesstoken", "refreshtoken", "clientsecret",
    "secretkey", "accesskey", "apitoken", "apikey", "clientid", "token",
    "key", "pat", "secret", "credentials", "id",
]

# A specimen carrying regex syntax is a pattern fragment, not a credential.
_FRAGMENT = re.compile(r"\(\?i|\[[a-zA-Z0-9]|\{\d+,|secrets\.NewSecret|\\[dws]|\]\?")


def _candidates(constructor: str) -> list[str]:
    s = re.sub(r"[^a-z0-9]", "", constructor.lower())
    out = [s]
    changed = True
    while changed:
        changed = False
        for suf in _SUFFIXES:
            if s.endswith(suf) and len(s) > len(suf):
                s = s[: -len(suf)]
                out.append(s)
                changed = True
                break
    return out


async def _fetch() -> dict[str, str]:
    import asyncio

    import httpx

    async with httpx.AsyncClient(timeout=25, follow_redirects=True) as client:
        main = (await client.get(MAIN)).text
        names: list[str] = []
        for fn in re.findall(r"rules\.([A-Za-z0-9_]+)\(", main):
            for cand in _candidates(fn):
                if cand and cand not in names:
                    names.append(cand)
        names.append("1password")

        found: dict[str, str] = {}
        sem = asyncio.Semaphore(8)

        async def get(name: str) -> None:
            async with sem:
                try:
                    r = await client.get(f"{RAW}{name}.go")
                    if r.status_code == 200 and "package rules" in r.text:
                        found[name] = r.text
                except Exception:  # noqa: BLE001 — a missing candidate is normal
                    pass

        await asyncio.gather(*(get(n) for n in names))
        return found


def load_corpus(offline: bool) -> dict[str, str] | None:
    if CACHE.exists():
        try:
            return json.loads(CACHE.read_text())
        except Exception:  # noqa: BLE001 — a corrupt cache re-fetches
            pass
    if offline:
        return None
    import asyncio

    try:
        files = asyncio.run(_fetch())
    except Exception as exc:  # noqa: BLE001
        print(f"  corpus unavailable ({exc.__class__.__name__}) — skipping.")
        return None
    if not files:
        return None
    try:
        CACHE.write_text(json.dumps(files))
    except Exception:  # noqa: BLE001 — a read-only checkout still runs
        pass
    return files


# ── Turning gitleaks' Go samples into concrete specimens ────────────────────
#
# Most of gitleaks' samples are GENERATED, not literal:
#
#     tps := utils.GenerateSampleSecrets("AWS", "AKIA"+secrets.NewSecret("[A-Z2-7]{16}"))
#     tps := utils.GenerateSampleSecrets("gitlab", "glpat-"+secrets.NewSecret(utils.AlphaNumeric("20")))
#
# The first version of this module dropped every line containing
# `secrets.NewSecret` as a "regex fragment" and scraped the leftover string
# literals instead. That discarded the majority of the corpus and kept whatever
# happened to be hardcoded — including entries from `fps`, gitleaks' own list of
# values that must NOT match. The result scored SecretNode's correct refusal to
# report a non-secret as a missed detection, and filed it under the bucket this
# module labels "the only one that is a defect".
#
# Measured on the old output: of ten reported in-scope misses, three were gitleaks
# false positives, six were scraped from neither sample list (comments, regex
# bodies, doc strings), and one was the timestamp `2021-02-14T20:41:01Z` sliced
# out of a longer entry. Essentially none were defects. A benchmark being wrong
# about the tool is the one failure this file's own docstring says it must never
# have, so the extractor now parses what gitleaks actually declares.

_CLASS = re.compile(r"\[([^\]]+)\]\{(\d+)\}")


def _expand_class(spec: str, rng: random.Random) -> str | None:
    """`[A-Z2-7]{16}` -> sixteen characters drawn from that class."""
    m = _CLASS.fullmatch(spec.strip())
    if not m:
        return None
    body, n = m.group(1), int(m.group(2))
    chars: list[str] = []
    i = 0
    while i < len(body):
        if i + 2 < len(body) and body[i + 1] == "-":
            chars.extend(chr(c) for c in range(ord(body[i]), ord(body[i + 2]) + 1))
            i += 3
        else:
            chars.append(body[i])
            i += 1
    return "".join(rng.choice(chars) for _ in range(n)) if chars else None


_HELPERS = {
    "AlphaNumeric": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    "AlphaNumericExtended": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-",
    "AlphaNumericExtendedShort": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_",
    "Hex": "0123456789abcdef",
    "Numeric": "0123456789",
    "AlphaNumericExtendedLong": (
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.~+/="),
}
_NEWSECRET = re.compile(r"secrets\.NewSecret\(\s*(.+?)\s*\)\s*$", re.S)
_UTILS_CALL = re.compile(r"utils\.(\w+)\(\s*[\"`](\d+)[\"`]\s*\)")


def _expand_atom(atom: str, rng: random.Random) -> str | None:
    """One `+`-joined piece of a Go sample expression."""
    a = atom.strip()
    if not a:
        return None
    # A quoted literal (Go raw strings use backticks).
    if (a[0] == a[-1] == '"' and len(a) > 1) or (a[0] == a[-1] == "`" and len(a) > 1):
        return a[1:-1].replace('\\"', '"')
    # secrets.NewSecret(...) wrapping either a helper call or a bare char class.
    m = _NEWSECRET.search(a) or (re.fullmatch(r"secrets\.NewSecret\((.*)\)", a, re.S))
    inner = m.group(1) if m else a
    u = _UTILS_CALL.search(inner)
    if u and u.group(1) in _HELPERS:
        alphabet = _HELPERS[u.group(1)]
        return "".join(rng.choice(alphabet) for _ in range(int(u.group(2))))
    lit = re.fullmatch(r"[\"`](.*)[\"`]", inner.strip(), re.S)
    if lit:
        expanded = _expand_class(lit.group(1), rng)
        if expanded:
            return expanded
        # A plain literal inside NewSecret with no quantifier is not generatable.
        return None if _FRAGMENT.search(lit.group(1)) else lit.group(1)
    return None


def _expand_expr(expr: str, rng: random.Random) -> str | None:
    """A full Go sample expression, e.g. `"AKIA"+secrets.NewSecret("[A-Z2-7]{16}")`.

    Returns None when any piece cannot be resolved: a partially-expanded sample
    is a string no scanner could match, and counting it as a miss would repeat
    the mistake this rewrite exists to correct.
    """
    parts, depth, cur = [], 0, ""
    for ch in expr:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "+" and depth == 0:
            parts.append(cur); cur = ""
        else:
            cur += ch
    parts.append(cur)
    out = []
    for part in parts:
        v = _expand_atom(part, rng)
        if v is None:
            return None
        out.append(v)
    joined = "".join(out)
    return joined if len(joined) >= 8 else None


_FUNC_SPLIT = re.compile(r"\nfunc\s+\w+\(\)\s*\*config\.Rule\s*\{")
_RULE_ID = re.compile(r'RuleID:\s*"([^"]+)"')
_SAMPLE_CALL = re.compile(r'GenerateSampleSecrets\(\s*"[^"]*"\s*,\s*', re.S)


def _balanced(text: str, i: int) -> str:
    """Slice from `i` to the paren that closes the call opened before it."""
    depth, out = 1, []
    while i < len(text) and depth:
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if not depth:
                break
        out.append(c)
        i += 1
    return "".join(out)


def _entries(block: str, rng: random.Random) -> list[str]:
    """Every concrete sample declared in one `tps`/`fps` region."""
    found: list[str] = []
    for m in _SAMPLE_CALL.finditer(block):
        v = _expand_expr(_balanced(block, m.end()), rng)
        if v:
            found.append(v)
    for lst in re.finditer(r"\[\]string\{(.*?)\n\s*\}", block, re.S):
        for line in lst.group(1).splitlines():
            line = line.strip().rstrip(",")
            if line and not line.startswith("//"):
                v = _expand_expr(line, rng)
                if v:
                    found.append(v)
    return found


def specimens(files: dict[str, str]) -> list[tuple[str, str, str, str]]:
    """(provider, rule_id, value, kind) where kind is 'tp' or 'fp'.

    `tp` is a value gitleaks declares its rule MUST match; `fp` is one it
    declares the rule must NOT match. Keeping them apart is what lets this
    module report recall and a false-alarm rate instead of one blurred number.
    """
    rng = random.Random(20260904)          # deterministic: same corpus, same run
    out: list[tuple[str, str, str, str]] = []
    seen: set[str] = set()
    for name, src in files.items():
        for fn in _FUNC_SPLIT.split(src)[1:]:
            cut = fn.find("return utils.Validate")
            body = fn[: cut if cut > 0 else len(fn)]
            rid_m = _RULE_ID.search(body)
            rid = rid_m.group(1) if rid_m else name
            # Start at the `tps` assignment, not at the function body. The body
            # also holds the rule definition, whose `Keywords: []string{...}`
            # field is a list of match hints — `"rubygems_"`, `"pscale_pw_"` —
            # not samples. Scanning from the top emitted those bare prefixes as
            # specimens, and a prefix with no body cannot match any detector, so
            # each one was scored as a missed credential. Same failure this
            # rewrite exists to correct, one level in.
            tps_m = re.search(r"\btps\s*:?=", body)
            fps_m = re.search(r"\bfps\s*:?=", body)
            if not tps_m and not fps_m:
                continue
            tps_start = tps_m.start() if tps_m else len(body)
            tps_text = body[tps_start: fps_m.start()] if fps_m else body[tps_start:]
            fps_text = body[fps_m.start():] if fps_m else ""
            for kind, text in (("tp", tps_text), ("fp", fps_text)):
                for v in _entries(text, rng):
                    if v in seen:
                        continue
                    seen.add(v)
                    out.append((name, rid, v, kind))
    return out


def _has_detector(provider: str) -> bool:
    names = [p.name.lower() for p in scanner.SECRET_PATTERNS]
    alias = {"gcp": "google", "googlecloud": "google"}
    p = alias.get(provider.lower(), provider.lower())
    return any(p in n.replace(" ", "") or p in n for n in names)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--offline", action="store_true",
                    help="use the cache only; skip rather than fetch")
    args = ap.parse_args()

    print("External validity — corpus: gitleaks rule definitions")
    print("=" * 68)
    files = load_corpus(args.offline)
    if not files:
        print("  No corpus available (no network and no cache). Skipped.")
        print("  This is a skip, not a pass: no number was measured.")
        return 0

    corpus = specimens(files)
    tps = [c for c in corpus if c[3] == "tp"]
    fps = [c for c in corpus if c[3] == "fp"]

    detected: list[tuple] = []
    in_scope_miss: list[tuple] = []
    no_detector: list[tuple] = []
    false_alarms: list[tuple] = []

    GENERIC = "Generic High-Entropy Secret"

    def types_for(provider: str, value: str) -> list[str]:
        # Embedded the way a credential actually appears in shipped code —
        # gitleaks' own sample generator does the same. A bare string with no
        # provider keyword would unfairly miss every keyword-anchored detector.
        asset = f'const {provider}ApiKey = "{value}";\nexport default {provider}ApiKey;\n'
        return [h.secret_type for h in scanner.extract_secrets(
            "bench", "https://corpus.test", "https://corpus.test/app.js", asset)]

    def reported(provider: str, value: str) -> bool:
        return bool(types_for(provider, value))

    for provider, rid, value, _k in tps:
        if reported(provider, value):
            detected.append((provider, rid, value))
        elif _has_detector(provider):
            in_scope_miss.append((provider, rid, value))
        else:
            no_detector.append((provider, rid, value))

    # gitleaks' `fps` lists mix two things that must not be scored alike:
    #
    #   * values that are genuinely not credentials — documentation examples,
    #     low-entropy filler, wrong case. Reporting one is a precision defect.
    #   * values that ARE credentials but belong to a DIFFERENT rule. The
    #     anthropic-api-key rule lists an admin key under `fps` with the comment
    #     "Wrong prefix (admin key, not API key)", because gitleaks splits those
    #     across two rules. SecretNode covers both with one detector, so matching
    #     it is correct — counting it against this scanner would penalise having
    #     broader coverage than the reference.
    #
    # A third bucket is this harness's own doing: every specimen is wrapped as
    # `const <provider>ApiKey = "…"` so keyword-anchored detectors get the
    # context they legitimately need. That wrapper MANUFACTURES the keyword the
    # generic catch-all looks for, so a generic-only match says more about the
    # scaffold than about the scanner. Reported apart rather than folded in.
    # Matched on a shared prefix rather than an exact value: gitleaks generates
    # the two rules' samples independently, so an admin key in the api-key rule's
    # fps is never byte-identical to one in the admin rule's tps — it just starts
    # the same way. An exact-value test looked correct and silently found nothing.
    tp_prefixes = {v[:10] for _p, _r, v, _k in tps if len(v) >= 10}
    generic_only: list[tuple] = []
    cross_rule: list[tuple] = []
    for provider, rid, value, _k in fps:
        got = types_for(provider, value)
        if not got:
            continue
        if len(value) >= 10 and value[:10] in tp_prefixes:
            cross_rule.append((provider, rid, value))
        elif got == [GENERIC]:
            generic_only.append((provider, rid, value))
        else:
            false_alarms.append((provider, rid, value))

    n_tp, n_fp = len(tps), len(fps)
    print(f"  rule files       {len(files)}")
    print(f"  specimens        {n_tp} true-positive, {n_fp} false-positive")
    print()
    print(f"  recall           {len(detected)}/{n_tp}   "
          f"({100 * len(detected) / max(1, n_tp):.1f}%)")
    print(f"  in-scope misses  {len(in_scope_miss):>4}   <- the only bucket that is a defect")
    print(f"  no detector      {len(no_detector):>4}   provider never claimed")
    print()
    # gitleaks' `fps` are values IT declares must not match. They are the only
    # externally-authored negatives available without a data-protection
    # agreement, which makes this the one precision number here that nobody in
    # this repository chose.
    print(f"  false alarms     {len(false_alarms)}/{n_fp}   "
          f"({100 * len(false_alarms) / max(1, n_fp):.1f}%)   provider detector on a declared non-secret")
    print(f"    cross-rule     {len(cross_rule):>4}   a real credential gitleaks files under another rule")
    print(f"    generic only   {len(generic_only):>4}   the harness's own `…ApiKey =` wrapper supplied the keyword")

    def _by_provider(items: list[tuple], limit: int = 14) -> None:
        counts: dict[str, int] = {}
        for provider, rid, _v in items:
            counts[rid or provider] = counts.get(rid or provider, 0) + 1
        for key, n in sorted(counts.items(), key=lambda kv: -kv[1])[:limit]:
            print(f"    {n:>4}  {key}")

    if in_scope_miss:
        print()
        print("  in-scope misses, by rule:")
        _by_provider(in_scope_miss)
    if no_detector:
        print()
        print("  providers never claimed:")
        print(f"    {', '.join(sorted({p for p, _r, _v in no_detector}))}")
    if false_alarms:
        print()
        print("  false alarms, by rule:")
        _by_provider(false_alarms)

    print()
    print("  Recall here is EXTERNAL: these specimens were written by another")
    print("  project for another scanner and owe nothing to these patterns.")
    print("  The false-alarm rate is measured against values gitleaks itself")
    print("  declares are NOT secrets — the only externally-authored negatives")
    print("  available without a data-protection agreement.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
