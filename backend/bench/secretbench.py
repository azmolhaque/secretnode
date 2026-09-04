#!/usr/bin/env python3
"""
Precision and recall against SecretBench — a corpus of REAL, human-labelled
secrets that nobody in this project wrote, chose, or influenced.

    python -m bench.secretbench --export /secure/path/secretbench.csv
    SECRETBENCH_EXPORT=/secure/path/secretbench.csv python -m bench.secretbench

WHY THIS IS NOT AUTO-FETCHED LIKE bench.external
-------------------------------------------------
`bench.external` downloads gitleaks' rule files on demand because they are
public source code containing synthetic samples. SecretBench is a different
kind of artifact and must be treated as one.

It is 97,479 candidate secrets mined from 818 public GitHub repositories, of
which 15,084 are labelled TRUE — meaning real credentials, belonging to real
people, that were really committed. The authors gate it deliberately:

    "The researchers and developers who want to use our dataset need to contact
     us. Since the dataset contains sensitive information, a data protection
     agreement has to be signed with us."
                                    — github.com/setu1421/SecretBench

So there is no download here, and there will not be one. Obtain access yourself
(sbasak4@ncsu.edu; BigQuery `dev-range-332204.secretbench.secrets`), export the
rows you are permitted to hold, and point this module at that file. Writing a
fetcher would route around an agreement someone else signed, and shipping one in
an open-source repository would invite every user to do the same.

The same reasoning covers FPSecretBench (`dev-range-332204.fpsecretbench`), the
companion dataset of false positives reported by nine detection tools. This
module reads it through the same `--export` path when you have it, because its
rows carry the same columns.

WHAT IT MEASURES THAT NOTHING ELSE HERE DOES
--------------------------------------------
`bench.benchmark` measures precision against decoys this project invented.
`bench.external` measures recall against another scanner's samples. Neither
measures **precision against values a human looked at and ruled out**, and that
is the number a client is really asking for when they ask how noisy the tool is.

SecretBench carries both labels, so both come from one corpus:

  recall      true-labelled secrets found          (label=True)
  precision   of everything reported, how much was really a secret
  FP rate     false-labelled candidates reported   (label=False)  <- new here

A miss is split the way `bench.external` splits it, and for the same reason: a
provider this scanner covers and missed is a defect, while one it never claimed
is a coverage decision. Blurring them produces a number that cannot be acted on.

HANDLING OF THE DATA ITSELF
---------------------------
These are live credentials, not specimens. Three rules, enforced rather than
documented:

  * The export is never copied, cached, or written anywhere by this module.
  * It refuses to read an export located inside this repository — one
    `git add -A` would publish real credentials, and this project has already
    been bitten twice by exactly that shape (`bench-corpus/`, twice).
  * Nothing secret reaches stdout. Misses print provider, category and a masked
    fragment, never the value.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "bench-secretbench")

import scanner  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# SecretBench's own column names (BigQuery `secrets` table). Aliases cover the
# CSV export and the JSON dump, which differ in case and pluralisation.
_COL_SECRET = ("secret", "secret_value", "value")
_COL_LABEL = ("label", "is_secret", "ground_truth")
_COL_CATEGORY = ("category", "secret_type", "type")
_COL_COMMENT = ("comment", "description", "note")
_COL_FILE = ("file_path", "file", "file_identifier")


def _pick(row: dict, names: tuple[str, ...]) -> str:
    for n in names:
        for k in row:
            if k.strip().lower() == n:
                v = row[k]
                return "" if v is None else str(v)
    return ""


def _is_true(label: str) -> bool | None:
    """SecretBench's `label` is the ground truth. Returns None for a row whose
    label is missing or unrecognised — those are excluded from BOTH numerator
    and denominator rather than guessed at, because a guessed label silently
    biases whichever metric it lands in."""
    v = label.strip().lower()
    if v in ("true", "t", "yes", "y", "1"):
        return True
    if v in ("false", "f", "no", "n", "0"):
        return False
    return None


def load_export(path: Path) -> list[dict]:
    """Rows from a CSV or JSON/JSONL export, normalised to this module's keys."""
    rows: list[dict] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix.lower() in (".json", ".jsonl", ".ndjson"):
        raw: list[dict] = []
        stripped = text.lstrip()
        if stripped.startswith("["):
            raw = json.loads(text)
        else:
            for line in text.splitlines():
                if line.strip():
                    raw.append(json.loads(line))
    else:
        raw = list(csv.DictReader(text.splitlines()))

    for r in raw:
        if not isinstance(r, dict):
            continue
        secret = _pick(r, _COL_SECRET)
        if not secret:
            continue
        rows.append({
            "secret": secret,
            "label": _is_true(_pick(r, _COL_LABEL)),
            "category": _pick(r, _COL_CATEGORY) or "unknown",
            "comment": _pick(r, _COL_COMMENT),
            "file": _pick(r, _COL_FILE),
        })
    return rows


def _has_detector(category: str, comment: str) -> bool:
    """Whether this scanner claims the provider named by the row.

    SecretBench labels by broad category ("API Key", "Private Key") and names
    the provider in `comment` ("Slack Token", "AWS Access Key"), so both are
    consulted — the category alone is too coarse to decide whether a miss is a
    defect or a coverage decision.
    """
    hay = f"{category} {comment}".lower()
    if "private key" in hay:
        return True
    for p in scanner.SECRET_PATTERNS:
        name = p.name.lower()
        # `> 3` excluded every three-letter provider — aws, npm, pgp, gcp, xai —
        # so a missed AWS Access Key was filed as "provider never claimed" when
        # this scanner has covered it since v1. That is the one misclassification
        # this split must never make: it moves a defect into the bucket labelled
        # "not a defect", which is how a real gap goes unnoticed.
        head = name.split()[0]
        if len(head) >= 3 and head in hay:
            return True
        if name in hay:
            return True
    return False


def _mask(value: str) -> str:
    """Enough to recognise a row in the export, never enough to use."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:3]}…{value[-2:]} ({len(value)} chars)"


def _probe(value: str, category: str) -> bool:
    """Does SecretNode report this value when it appears the way code holds one?

    The row is embedded in an assignment rather than scanned bare, matching
    `bench.external`: a naked string denies every keyword-anchored detector the
    context it legitimately relies on, which would understate recall by
    measuring a situation that does not occur.
    """
    name = "".join(ch if ch.isalnum() else "_" for ch in category)[:32] or "secret"
    asset = f'const {name} = "{value}";\nexport default {name};\n'
    return bool(scanner.extract_secrets(
        "bench", "https://corpus.test", "https://corpus.test/app.js", asset))


def _resolve(path_arg: str | None) -> Path | None:
    raw = path_arg or os.environ.get("SECRETBENCH_EXPORT", "")
    if not raw:
        return None
    p = Path(raw).expanduser().resolve()
    if not p.exists():
        print(f"  Export not found: {p}")
        return None
    try:
        p.relative_to(REPO_ROOT)
    except ValueError:
        return p
    # Inside the repo. Refuse — see the module docstring.
    print(f"  REFUSING to read an export inside the repository: {p}")
    print("  SecretBench rows are real credentials from real repositories. Held")
    print("  here, one `git add -A` publishes them. Move it outside the checkout.")
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="Precision/recall vs. SecretBench.")
    ap.add_argument("--export", help="path to a SecretBench export (CSV or JSON/JSONL), "
                                     "outside this repository")
    ap.add_argument("--limit", type=int, default=0, help="sample the first N labelled rows")
    args = ap.parse_args()

    print("SecretBench — external precision AND recall on human-labelled secrets")
    print("=" * 70)

    path = _resolve(args.export)
    if path is None:
        print("  No export available. Skipped.")
        print("  This is a skip, not a pass: no number was measured.")
        print()
        print("  SecretBench is gated behind a signed data protection agreement —")
        print("  it holds real credentials from public repositories, so this module")
        print("  deliberately has no downloader. Request access from the authors")
        print("  (sbasak4@ncsu.edu), export the rows you may hold, and pass")
        print("  --export /path/outside/this/repo.")
        return 0

    rows = [r for r in load_export(path) if r["label"] is not None]
    if args.limit:
        rows = rows[: args.limit]
    if not rows:
        print("  Export contained no rows with a usable `label` column. Skipped.")
        print("  This is a skip, not a pass: no number was measured.")
        return 0

    tp = fn = fp = tn = 0
    in_scope_miss: list[dict] = []
    no_detector: list[dict] = []
    false_alarms: list[dict] = []

    for r in rows:
        reported = _probe(r["secret"], r["category"])
        if r["label"]:
            if reported:
                tp += 1
            else:
                fn += 1
                (in_scope_miss if _has_detector(r["category"], r["comment"])
                 else no_detector).append(r)
        else:
            if reported:
                fp += 1
                false_alarms.append(r)
            else:
                tn += 1

    true_n, false_n = tp + fn, fp + tn
    recall = tp / true_n if true_n else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    fp_rate = fp / false_n if false_n else 0.0

    print(f"  rows (labelled)  {len(rows)}   [{true_n} true, {false_n} false]")
    print()
    print(f"  recall           {recall:.3f}   ({tp}/{true_n} true secrets found)")
    print(f"  precision        {precision:.3f}   ({tp}/{tp + fp} reported were real)")
    print(f"  false-alarm rate {fp_rate:.3f}   ({fp}/{false_n} non-secrets reported)")
    print()
    print(f"  in-scope misses  {len(in_scope_miss):>4}   <- the only bucket that is a defect")
    print(f"  no detector      {len(no_detector):>4}   provider never claimed")

    def _top(items: list[dict], n: int = 12) -> None:
        seen: dict[str, int] = {}
        for r in items:
            key = (r["comment"] or r["category"]).strip()[:38]
            seen[key] = seen.get(key, 0) + 1
        for key, count in sorted(seen.items(), key=lambda kv: -kv[1])[:n]:
            print(f"    {count:>4}  {key}")

    if in_scope_miss:
        print()
        print("  in-scope misses, by provider:")
        _top(in_scope_miss)
        print("  sample (masked):")
        for r in in_scope_miss[:5]:
            print(f"    {(r['comment'] or r['category'])[:28]:30} {_mask(r['secret'])}")

    if false_alarms:
        print()
        print("  false alarms, by category:")
        _top(false_alarms)

    print()
    print("  This is the strongest number this project can quote: the labels were")
    print("  assigned by humans with no knowledge of these patterns, and the")
    print("  precision figure is measured against values a person examined and")
    print("  ruled out — not against decoys this repository invented.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
