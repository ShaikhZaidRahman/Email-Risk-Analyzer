"""Compare predicted risk levels with labelled ground truth."""

from __future__ import annotations

from collections import Counter
from typing import Any

from .models import LEVELS, Analysis


def evaluate(results: list[Analysis]) -> dict[str, Any] | None:
    """Return accuracy metrics for results that carry an expected label, else ``None``."""
    labelled = [r for r in results if r.expected in LEVELS]
    if not labelled:
        return None
    n = len(labelled)
    idx = {lvl: i for i, lvl in enumerate(LEVELS)}
    matrix = {e: {p: 0 for p in LEVELS} for e in LEVELS}
    for r in labelled:
        matrix[r.expected][r.level] += 1  # type: ignore[index]
    exact = sum(matrix[l][l] for l in LEVELS)
    adjacent = sum(1 for r in labelled if abs(idx[r.level] - idx[r.expected]) <= 1)  # type: ignore[index]
    # Binary view: "suspicious" = Medium or High versus Low.
    tp = sum(1 for r in labelled if r.expected != "Low" and r.level != "Low")
    fn = sum(1 for r in labelled if r.expected != "Low" and r.level == "Low")
    fp = sum(1 for r in labelled if r.expected == "Low" and r.level != "Low")
    tn = n - tp - fn - fp
    rec = lambda a, b: a / (a + b) if a + b else None
    return {
        "labelled": n,
        "exact_agreement": exact / n,
        "within_one_level": adjacent / n,
        "confusion_matrix": matrix,
        "suspicious_vs_low": {
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": rec(tp, fp), "recall": rec(tp, fn), "specificity": rec(tn, fp),
        },
        "per_level_recall": {
            l: (matrix[l][l] / sum(matrix[l].values()) if sum(matrix[l].values()) else None) for l in LEVELS
        },
        "expected_distribution": dict(Counter(r.expected for r in labelled)),
    }
