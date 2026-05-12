"""Shared detector math helpers."""

from __future__ import annotations

from collections import Counter, defaultdict
import math
from typing import Iterable

from threatlib.fusion.dempster_shafer import combine_many
from threatlib.signals.base import DEFAULT_CONFIDENCE, DetectorResult


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def bigram_transition_entropy(value: str) -> float:
    if len(value) < 2:
        return 0.0
    transitions: dict[str, Counter[str]] = defaultdict(Counter)
    for left, right in zip(value, value[1:]):
        transitions[left][right] += 1
    entropies = []
    for counter in transitions.values():
        total = sum(counter.values())
        entropies.append(-sum((count / total) * math.log2(count / total) for count in counter.values()))
    return sum(entropies) / len(entropies) if entropies else 0.0


def levenshtein(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    previous = list(range(len(right) + 1))
    for i, left_char in enumerate(left, start=1):
        current = [i]
        for j, right_char in enumerate(right, start=1):
            insert = current[j - 1] + 1
            delete = previous[j] + 1
            substitute = previous[j - 1] + (0 if left_char == right_char else 1)
            current.append(min(insert, delete, substitute))
        previous = current
    return previous[-1]


def mini_ds_from_lrs(
    detector_name: str,
    lrs: Iterable[tuple[float, str]],
    confidence: float = DEFAULT_CONFIDENCE,
) -> DetectorResult:
    results = [
        DetectorResult.from_likelihood_ratio(lr, confidence=confidence, detector_name=detector_name, reason=reason)
        for lr, reason in lrs
        if lr > 0
    ]
    if not results:
        return DetectorResult.uncertain(detector_name, "no sub-signals")
    return combine_many(results)

