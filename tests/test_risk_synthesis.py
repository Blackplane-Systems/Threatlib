from __future__ import annotations

import random

from threatlib.cold_start.priors import blend_prior, deployment_phase
from threatlib.fusion.dempster_shafer import combine_many
from threatlib.risk.conformal import compute_band, compute_quantile, nonconformity_score
from threatlib.risk.synthesis import RiskSynthesizer, apply_jitter, check_quorum, compute_risk_score
from threatlib.signals.base import DetectorResult


def test_risk_score_range():
    combined = combine_many([
        DetectorResult(fraud_mass=0.6, uncertainty_mass=0.4),
        DetectorResult(legitimate_mass=0.3, uncertainty_mass=0.7),
    ])
    risk, low, high = compute_risk_score(combined)
    assert 0.0 <= risk <= 1.0
    assert 0.0 <= low <= high <= 1.0


def test_quorum_function():
    results = {
        "a": DetectorResult(fraud_mass=0.2, uncertainty_mass=0.8),
        "b": DetectorResult.uncertain("b"),
    }
    assert not check_quorum(results, 2)
    assert check_quorum(results, 1)


def test_cold_start_blending(policy):
    assert blend_prior(0.2, 0.8, 0, 100) == 0.2
    assert blend_prior(0.2, 0.8, 100, 100) == 0.8
    assert deployment_phase(0, policy) == "cold_start_p1"


def test_cold_start_blending_v2():
    assert blend_prior(0.1, 0.9, 50, 100) == 0.5


def test_conformal_band_coverage():
    low, high = compute_band(0.5, [0.1, 0.2, 0.3], alpha=0.1)
    assert low <= 0.5 <= high
    assert high - low > 0


def test_conformal_coverage_guarantee():
    assert compute_quantile([0.1, 0.2, 0.3], alpha=0.1) == 0.3


def test_nonconformity_score():
    assert nonconformity_score(0.2, 1) == 0.8


def test_jitter_range():
    rng = random.Random(7)
    for _ in range(100):
        assert 0.0 <= apply_jitter(0.5, 0.01, rng) <= 1.0


def test_synthetic_scores(active_policy, graph, bot_fixture, human_fixture):
    synth = RiskSynthesizer(active_policy, graph=graph, rng=random.Random(1))
    bot = synth.score(bot_fixture)
    assert bot["risk_score"] > 0.5
    assert bot["action"] != "monitor"

    human = synth.score(human_fixture)
    assert human["risk_score"] < 0.3
    assert human["action"] == "monitor"


def test_shadow_mode_forces_monitor(policy, graph, bot_fixture):
    result = RiskSynthesizer(policy, graph=graph, rng=random.Random(1)).score(bot_fixture)
    assert result["action"] == "monitor"
    assert all(value == 0.0 for value in result["restrictions"].values())


def test_insufficient_evidence(active_policy, graph):
    result = RiskSynthesizer(active_policy, graph=graph, rng=random.Random(1)).score({"account_id": "only_id"})
    assert result["threat_tier"] == "insufficient_evidence"
    assert result["action"] == "monitor"
