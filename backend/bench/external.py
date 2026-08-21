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


def specimens(files: dict[str, str]) -> list[tuple[str, str, str]]:
    """(provider, rule_id, specimen), de-duplicated, fragments removed."""
    out: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for name, src in files.items():
        rid = re.search(r'RuleID:\s*"([^"]+)"', src)
        rid = rid.group(1) if rid else name
        for line in src.splitlines():
            for m in re.finditer(r'"([^"\\\n]{20,400})"', line):
                v = m.group(1)
                if v.startswith(("http", "github.com/")):
                    continue
                if " " in v or "%" in v or _FRAGMENT.search(v):
                    continue
                if not (re.search(r"\d", v) and re.search(r"[A-Za-z]", v)):
                    continue
                if v in seen:
                    continue
                seen.add(v)
                out.append((name, rid, v))
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

    print("External-validity recall — corpus: gitleaks rule definitions")
    print("=" * 66)
    files = load_corpus(args.offline)
    if not files:
        print("  No corpus available (no network and no cache). Skipped.")
        print("  This is a skip, not a pass: no number was measured.")
        return 0

    corpus = specimens(files)
    detected: list[tuple[str, str, str]] = []
    in_scope_miss: list[tuple[str, str, str]] = []
    no_detector: list[tuple[str, str, str]] = []

    for provider, rid, value in corpus:
        # Embedded the way a credential actually appears in shipped code —
        # gitleaks' own sample generator does the same. A bare string with no
        # provider keyword would unfairly miss every keyword-anchored detector.
        asset = f'const {provider}ApiKey = "{value}";\nexport default {provider}ApiKey;\n'
        hits = scanner.extract_secrets(
            "bench", "https://corpus.test", "https://corpus.test/app.js", asset)
        if hits:
            detected.append((provider, rid, value))
        elif _has_detector(provider):
            in_scope_miss.append((provider, rid, value))
        else:
            no_detector.append((provider, rid, value))

    total = len(corpus)
    print(f"  rule files       {len(files)}")
    print(f"  specimens        {total}")
    print()
    print(f"  detected         {len(detected):>3} / {total}   "
          f"({100 * len(detected) / max(1, total):.1f}%)")
    print(f"  in-scope misses  {len(in_scope_miss):>3}   <- the only bucket that is a defect")
    print(f"  no detector      {len(no_detector):>3}   "
          f"[{', '.join(sorted({p for p, _r, _v in no_detector}))}]")

    if in_scope_miss:
        print()
        print("  in-scope misses:")
        for provider, rid, value in in_scope_miss:
            print(f"    {provider:14} {rid:34} {value[:40]}")

    print()
    print("  Recall here is EXTERNAL: these specimens were written by another")
    print("  project for another scanner and owe nothing to these patterns.")
    print("  It is the number to quote. `bench.benchmark`'s 70/70 is a")
    print("  regression net and a precision measurement, not a recall claim.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
