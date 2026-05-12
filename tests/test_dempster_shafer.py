from __future__ import annotations

from threatlib.fusion.dempster_shafer import (
    _compute_conflict,
    apply_temporal_decay,
    apply_weight,
    combine,
    combine_many,
)
from threatlib.signals.base import DetectorResult


def test_combine_two_mass_functions():
    left = DetectorResult(fraud_mass=0.8, uncertainty_mass=0.2)
    right = DetectorResult(fraud_mass=0.8, uncertainty_mass=0.2)
    combined = combine(left, right)
    assert combined.fraud_mass > 0.9


def test_high_conflict_murphy_fallback():
    left = DetectorResult(fraud_mass=0.95, uncertainty_mass=0.05)
    right = DetectorResult(legitimate_mass=0.95, uncertainty_mass=0.05)
    assert _compute_conflict(left, right) > 0.8
    combined = combine_many([left, right])
    assert combined.combination_rule == "murphy_averaging"


def test_quorum_check_in_combine_many():
    result = combine_many([DetectorResult(fraud_mass=0.8, uncertainty_mass=0.2)], minimum_detectors_required=2)
    assert result.is_uncertain()
    assert result.reason == "insufficient_evidence"


def test_temporal_decay_halves_at_halflife():
    result = DetectorResult(fraud_mass=0.6, uncertainty_mass=0.4)
    decayed = apply_temporal_decay(result, halflife_days=10, age_days=10)
    assert abs(decayed.fraud_mass - 0.3) < 1e-6


def test_weight_zero_produces_uncertain():
    result = DetectorResult(fraud_mass=0.6, uncertainty_mass=0.4)
    assert apply_weight(result, 0.0).is_uncertain()

