"""
R2 — regression gate for detection-layer precision/recall.

Runs the labelled corpus (bench/) through extract_secrets() and fails the build
if precision or recall drops below threshold, so a change that starts missing
real secrets (FN) or flagging placeholders/noise (FP) is caught in CI — not in a
client's report.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRETNODE_API_KEY", "test-key-for-pytest")

from bench.run_bench import evaluate


def test_precision_recall_gate():
    m = evaluate()
    assert m["precision"] >= 0.95, f"precision regressed: {m['precision']} · {m['misses']}"
    assert m["recall"] >= 0.95, f"recall regressed: {m['recall']} · {m['misses']}"
    assert m["f1"] >= 0.95, f"F1 regressed: {m['f1']}"


def test_zero_false_positives_on_placeholders_and_noise():
    """Cindrasec's brand is 'no false positives'. Lock it in: placeholders,
    documentation examples, and high-entropy non-secrets must never be flagged."""
    m = evaluate()
    fps = [x for x in m["misses"] if x["kind"] == "FALSE_POSITIVE"]
    assert not fps, f"false positives introduced: {fps}"


def test_type_accuracy_high():
    m = evaluate()
    assert m["type_accuracy"] >= 0.9, f"type accuracy regressed: {m['type_accuracy']} · {m['misses']}"


def test_corpus_has_both_classes():
    # Guard the corpus itself: a benchmark with no negatives (or no positives) is
    # meaningless. Ensure both classes are present and non-trivial.
    m = evaluate()
    assert m["positives"] >= 10
    assert m["negatives"] >= 10
