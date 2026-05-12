"""Dempster-Shafer evidence fusion for ThreatLib."""

from __future__ import annotations

import math
from typing import Iterable

from threatlib.signals.base import DetectorResult


HIGH_CONFLICT_K = 0.8  # REF: Section E.1 - Murphy fallback threshold for conflicting evidence.
NON_TRIVIAL_MASS = 0.05  # REF: Invariant 4 - quorum detector evidence floor.


def _compute_conflict(m1: DetectorResult, m2: DetectorResult) -> float:
    return (m1.fraud_mass * m2.legitimate_mass) + (m1.legitimate_mass * m2.fraud_mass)


def combine(m1: DetectorResult, m2: DetectorResult) -> DetectorResult:
    """Combine two DS mass functions with Dempster's normalized rule."""

    conflict_k = _compute_conflict(m1, m2)
    if conflict_k >= 1.0:
        return _murphy_average([m1, m2])
    denominator = 1.0 - conflict_k
    fraud = (
        (m1.fraud_mass * m2.fraud_mass)
        + (m1.fraud_mass * m2.uncertainty_mass)
        + (m1.uncertainty_mass * m2.fraud_mass)
    ) / denominator
    legitimate = (
        (m1.legitimate_mass * m2.legitimate_mass)
        + (m1.legitimate_mass * m2.uncertainty_mass)
        + (m1.uncertainty_mass * m2.legitimate_mass)
    ) / denominator
    uncertainty = (m1.uncertainty_mass * m2.uncertainty_mass) / denominator
    return DetectorResult(
        fraud_mass=fraud,
        legitimate_mass=legitimate,
        uncertainty_mass=uncertainty,
        detector_name="combined",
        reason="dempster_rule",
        metadata={"inputs": [m1.detector_name, m2.detector_name]},
        combination_rule="dempster",
        conflict_k=conflict_k,
    )


def combine_many(results: Iterable[DetectorResult], minimum_detectors_required: int = 0) -> DetectorResult:
    usable = [result for result in results if not result.is_uncertain()]
    if minimum_detectors_required and non_trivial_count(usable) < minimum_detectors_required:
        return DetectorResult.uncertain(
            "combined",
            "insufficient_evidence",
            {"non_trivial_detectors": non_trivial_count(usable), "minimum_required": minimum_detectors_required},
        )
    if not usable:
        return DetectorResult.uncertain("combined", "no usable detector evidence")
    if len(usable) == 1:
        return usable[0]
    max_conflict = max(_compute_conflict(left, right) for i, left in enumerate(usable) for right in usable[i + 1 :])
    if max_conflict > HIGH_CONFLICT_K:
        return _murphy_average(usable, conflict_k=max_conflict)
    combined = usable[0]
    highest_k = 0.0
    for result in usable[1:]:
        combined = combine(combined, result)
        highest_k = max(highest_k, combined.conflict_k)
    return DetectorResult(
        fraud_mass=combined.fraud_mass,
        legitimate_mass=combined.legitimate_mass,
        uncertainty_mass=combined.uncertainty_mass,
        detector_name="combined",
        reason="dempster_rule",
        metadata={"detector_count": len(usable)},
        combination_rule="dempster",
        conflict_k=highest_k,
    )


def _murphy_average(results: list[DetectorResult], conflict_k: float | None = None) -> DetectorResult:
    count = len(results)
    if count == 0:
        return DetectorResult.uncertain("combined", "no evidence for Murphy averaging")
    avg = DetectorResult(
        fraud_mass=sum(result.fraud_mass for result in results) / count,
        legitimate_mass=sum(result.legitimate_mass for result in results) / count,
        uncertainty_mass=sum(result.uncertainty_mass for result in results) / count,
        detector_name="combined",
        reason="murphy_average_seed",
    )
    combined = avg
    for _ in range(max(1, count) - 1):
        combined = combine(combined, avg)
    return DetectorResult(
        fraud_mass=combined.fraud_mass,
        legitimate_mass=combined.legitimate_mass,
        uncertainty_mass=combined.uncertainty_mass,
        detector_name="combined",
        reason="high_conflict_murphy_fallback",
        metadata={"detector_count": count},
        combination_rule="murphy_averaging",
        conflict_k=conflict_k if conflict_k is not None else 0.0,
    )


def non_trivial_count(results: Iterable[DetectorResult]) -> int:
    return sum(1 for result in results if result.evidence_mass > NON_TRIVIAL_MASS)


def apply_temporal_decay(result: DetectorResult, halflife_days: float | None, age_days: float) -> DetectorResult:
    if halflife_days is None or halflife_days <= 0 or age_days <= 0:
        return result
    decay = math.exp(-math.log(2.0) / halflife_days * age_days)
    fraud = result.fraud_mass * decay
    legitimate = result.legitimate_mass * decay
    uncertainty = 1.0 - fraud - legitimate
    return DetectorResult(
        fraud_mass=fraud,
        legitimate_mass=legitimate,
        uncertainty_mass=uncertainty,
        detector_name=result.detector_name,
        reason=result.reason,
        metadata=result.metadata,
        age_days=age_days,
        combination_rule=result.combination_rule,
        conflict_k=result.conflict_k,
    )


def apply_weight(result: DetectorResult, weight: float) -> DetectorResult:
    if weight <= 0:
        return DetectorResult.uncertain(result.detector_name, "signal weight is zero", result.metadata)
    fraud = _weighted_mass(result.fraud_mass, weight)
    legitimate = _weighted_mass(result.legitimate_mass, weight)
    uncertainty = 1.0 - fraud - legitimate
    if uncertainty < 0.0:
        total = fraud + legitimate
        fraud = fraud / total
        legitimate = legitimate / total
        uncertainty = 0.0
    return DetectorResult(
        fraud_mass=fraud,
        legitimate_mass=legitimate,
        uncertainty_mass=uncertainty,
        detector_name=result.detector_name,
        reason=result.reason,
        metadata=result.metadata,
        age_days=result.age_days,
        combination_rule=result.combination_rule,
        conflict_k=result.conflict_k,
    )


def _weighted_mass(mass: float, weight: float) -> float:
    if mass <= 0.0:
        return 0.0
    if mass >= 1.0:
        return 1.0
    return math.tanh(weight * math.atanh(mass))
