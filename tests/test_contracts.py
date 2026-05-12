from __future__ import annotations

import pytest

from threatlib.config.policy import PolicyLoader
from threatlib.signals.base import BaseDetector, DetectorResult


class ThrowingDetector(BaseDetector):
    name = "throwing"
    required_fields = ("account_id",)

    def score(self, account_data):
        raise RuntimeError("boom")


def test_detector_result_masses_sum_to_one():
    result = DetectorResult(fraud_mass=0.4, legitimate_mass=0.2, uncertainty_mass=0.4)
    assert abs(result.fraud_mass + result.legitimate_mass + result.uncertainty_mass - 1.0) < 1e-6


@pytest.mark.parametrize("lr", [0.1, 0.5, 1.0, 2.0, 10.0])
def test_from_likelihood_ratio_contract(lr):
    result = DetectorResult.from_likelihood_ratio(lr, confidence=1.0)
    assert abs(result.fraud_mass + result.legitimate_mass + result.uncertainty_mass - 1.0) < 1e-6
    if lr > 1.0:
        assert result.fraud_mass > 0
    elif lr < 1.0:
        assert result.legitimate_mass > 0
    else:
        assert result.is_uncertain()


def test_safe_score_catches_exception():
    result = ThrowingDetector().safe_score({"account_id": "a"})
    assert result.is_uncertain()
    assert result.reason == "detector exception"


def test_policy_loads_and_rejects_extra(policy):
    assert policy.platform == "your-platform-name"
    raw = policy.model_dump()
    raw["unexpected"] = True
    with pytest.raises(ValueError):
        PolicyLoader.from_dict(raw)

