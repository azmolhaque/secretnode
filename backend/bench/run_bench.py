"""
SecretNode — bench/run_bench.py  (R2: precision/recall harness)

Runs the deterministic detection layer (extract_secrets: regex + placeholder
allowlist + entropy gate + base64 pass — no network, no AI) over the labelled
corpus and reports precision / recall / F1, plus every miss so a regression is
visible line-by-line.

Usage:
    python -m bench.run_bench          # from backend/  (human-readable report)
    make bench                          # from repo root

Programmatic:
    from bench.run_bench import evaluate
    m = evaluate()   # -> {"precision":…, "recall":…, "f1":…, "tp":…, …, "misses":[…]}

Definitions (sample-level; each positive plants exactly one secret, each
negative plants none):
    TP  positive sample that produced >=1 finding   (planted secret caught)
    FN  positive sample that produced 0 findings     (missed a real secret)
    FP  negative sample that produced >=1 finding    (flagged noise/placeholder)
    TN  negative sample that produced 0 findings
    precision = TP / (TP + FP)      recall = TP / (TP + FN)
"""

from __future__ import annotations

from bench.corpus import CORPUS, Sample
from scanner import extract_secrets


def _detect(sample: Sample) -> list[str]:
    findings = extract_secrets("bench", "https://bench.local", "https://bench.local/x.js", sample.text)
    return [f.secret_type for f in findings]


def evaluate() -> dict:
    tp = fn = fp = tn = 0
    type_hits = 0            # positives that detected the EXACT expected type
    misses: list[dict] = []

    for s in CORPUS:
        detected = _detect(s)
        got = len(detected) > 0
        if s.is_positive:
            if got:
                tp += 1
                if s.expect in detected:
                    type_hits += 1
                else:
                    misses.append({"id": s.id, "kind": "WRONG_TYPE",
                                   "expected": s.expect, "detected": detected})
            else:
                fn += 1
                misses.append({"id": s.id, "kind": "FALSE_NEGATIVE",
                               "expected": s.expect, "detected": []})
        else:
            if got:
                fp += 1
                misses.append({"id": s.id, "kind": "FALSE_POSITIVE",
                               "expected": None, "detected": detected})
            else:
                tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    positives = tp + fn
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "type_accuracy": round(type_hits / positives, 4) if positives else 1.0,
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "positives": positives, "negatives": fp + tn,
        "misses": misses,
    }


def format_report(m: dict) -> str:
    lines = [
        "SecretNode — detection-layer precision/recall (R2)",
        "=" * 52,
        f"  corpus:        {m['positives']} positives · {m['negatives']} negatives",
        f"  precision:     {m['precision']:.3f}   (TP={m['tp']}  FP={m['fp']})",
        f"  recall:        {m['recall']:.3f}   (TP={m['tp']}  FN={m['fn']})",
        f"  F1:            {m['f1']:.3f}",
        f"  type accuracy: {m['type_accuracy']:.3f}   (right type on caught positives)",
    ]
    if m["misses"]:
        lines.append("  misses:")
        for x in m["misses"]:
            lines.append(f"    - [{x['kind']}] {x['id']}: expected={x['expected']} detected={x['detected']}")
    else:
        lines.append("  misses:        none — clean sweep")
    return "\n".join(lines)


if __name__ == "__main__":  # pragma: no cover
    print(format_report(evaluate()))
