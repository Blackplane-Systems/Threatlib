from __future__ import annotations

import time

import pytest

from threatlib.graph.account_graph import ONE_DAY_SECONDS
from threatlib.risk.synthesis import RiskSynthesizer
from threatlib.signals.account_age_velocity import AccountAgeVelocityDetector, compute_velocity
from threatlib.signals.community_detection import CommunityDetectionDetector, compute_spectral_gap
from threatlib.signals.coordinated_behavior import compute_mutual_information, granger_test_pair
from threatlib.signals.cross_entropy_coherence import CrossEntropyCoherenceDetector
from threatlib.signals.cross_signal_coherence import CrossSignalCoherenceDetector
from threatlib.signals.external_link_pattern import ExternalLinkPatternDetector
from threatlib.signals.hawkes_burst_v2 import HawkesBurstDetectorV2, compute_intensity, log_likelihood
from threatlib.signals.hmm_intent import HMMIntentDetector, forward_algorithm
from threatlib.signals.orchestrator import DetectorDAGError, DetectorOrchestrator
from threatlib.signals.payment_signal import PaymentSignalDetector
from threatlib.signals.sir_contagion import SIRContagionDetector
from threatlib.signals.survival_analysis import SurvivalAnalysisDetector, compute_hazard
from threatlib.signals.base import BaseDetector, DetectorResult


def test_hawkes_bot_burst_vs_human(policy, graph):
    now = time.time()
    for index in range(6):
        graph.upsert_account({"account_id": f"burst_v2_{index}"}, created_at=now - index * 20)
    result = HawkesBurstDetectorV2(policy=policy, graph=graph).safe_score({"account_id": "burst_v2_0"})
    assert result.fraud_mass > 0.5


def test_hawkes_mle_convergence():
    series = [(0.0, "registration"), (60.0, "registration"), (120.0, "content_view")]
    params = {"mu": {"registration": 0.1, "content_view": 0.1}, "alpha": {("registration", "registration"): 0.5}, "beta": 1.0}
    assert all(value > 0 for value in compute_intensity(series, params))
    assert log_likelihood(series, params) < 10


def test_hmm_forward_escalating_sequence(policy, graph):
    observations = ["view_profile", "follow_user", "send_dm_with_link"]
    A = [[0.8, 0.2], [0.1, 0.9]]
    B = {"view_profile": [0.8, 0.2], "follow_user": [0.4, 0.6], "send_dm_with_link": [0.1, 0.9], "platform_custom": [0.5, 0.5]}
    alpha = forward_algorithm(observations, A, B, [0.9, 0.1])
    assert alpha[-1][1] > alpha[-1][0]

    for event in ["view_profile", "view_profile", "follow_user", "send_dm", "send_dm"]:
        graph.record_event("hmm_acct", event, {"has_link": event == "send_dm", "link_domain": "bad.test"})
    result = HMMIntentDetector(policy=policy, graph=graph).safe_score({"account_id": "hmm_acct"})
    assert result.fraud_mass > 0.3
    assert result.metadata["state"] in {"escalating", "acting"}


def test_survival_high_risk_shorter_eta(policy, graph):
    assert compute_hazard({"x": 2}, 0.1, {"x": 1.0}) > compute_hazard({"x": 0}, 0.1, {"x": 1.0})
    graph.upsert_account({"account_id": "survival", "ip_is_datacenter": True, "email_domain_age_days": 1})
    result = SurvivalAnalysisDetector(policy=policy, graph=graph).safe_score({"account_id": "survival", "ip_is_datacenter": True, "email_domain_age_days": 1})
    assert not result.is_uncertain()


def test_velocity_new_account_high_impact(policy, graph):
    now = time.time()
    graph.upsert_account({"account_id": "age_velocity"}, created_at=now - 600)
    for _ in range(4):
        graph.record_event("age_velocity", "send_dm", {"has_link": True}, timestamp=now)
    assert compute_velocity(graph.recent_events("age_velocity"), 0.5, set(policy.high_impact_actions)) > 5
    assert AccountAgeVelocityDetector(policy=policy, graph=graph).safe_score({"account_id": "age_velocity"}).fraud_mass > 0.5


def test_external_link_and_payment_detectors(policy, graph):
    graph.upsert_account({"account_id": "links"})
    for _ in range(5):
        graph.record_event("links", "send_dm", {"has_link": True, "link_domain": "scam.test"})
    assert ExternalLinkPatternDetector(policy=policy, graph=graph).safe_score({"account_id": "links"}).fraud_mass > 0.5
    payment = {"account_id": "pay", "metadata": {"transaction_velocity_24h": 30, "transaction_amount_variance": 1, "transaction_recipient_count_24h": 1, "transaction_max_amount": 20000, "upi_id_age_days": 1}}
    graph.upsert_account(payment)
    assert PaymentSignalDetector(policy=policy, graph=graph).safe_score(payment).fraud_mass > 0.5


def test_community_detects_bot_cluster(policy, graph):
    now = time.time()
    for index in range(5):
        account_id = f"cluster_{index}"
        graph.upsert_account({"account_id": account_id, "device_hash": "shared_device", "ip_prefix": "10.0.0"}, created_at=now - index)
    result = CommunityDetectionDetector(policy=policy, graph=graph).safe_score({"account_id": "cluster_4"})
    assert result.fraud_mass > 0.5


def test_spectral_gap_tight_cluster():
    import networkx as nx

    graph = nx.complete_graph(5)
    assert compute_spectral_gap(graph) >= 0


def test_coordination_mutual_info():
    mi = compute_mutual_information([1, 1, 2, 2], ["a", "a", "b", "b"])
    assert mi > 0.3


def test_granger_coordinated_accounts():
    assert 0.0 <= granger_test_pair([0, 1, 0, 1, 0, 1], [1, 0, 1, 0, 1, 0], 1) <= 1.0


def test_cross_coherence_detectors(policy, graph, bot_fixture):
    synth = RiskSynthesizer(policy, graph=graph)
    low_level = synth.run_all_detectors(bot_fixture)
    enriched = {**bot_fixture, "_detector_results": low_level}
    assert CrossEntropyCoherenceDetector(policy=policy, graph=graph).safe_score(enriched).fraud_mass > 0.3
    assert not CrossSignalCoherenceDetector(policy=policy, graph=graph).safe_score(enriched).is_uncertain()


def test_sir_detector_with_scored_neighbour(policy, graph, bot_fixture):
    graph.upsert_account({"account_id": "neighbour", "device_hash": "sir_device"})
    graph.upsert_account({"account_id": "sir_target", "device_hash": "sir_device"})
    RiskSynthesizer(policy, graph=graph).score(bot_fixture | {"account_id": "neighbour", "device_hash": "sir_device"})
    result = SIRContagionDetector(policy=policy, graph=graph).safe_score({"account_id": "sir_target"})
    assert not result.is_uncertain()


def test_detector_dag_cycle_detection(policy, graph):
    class A(BaseDetector):
        name = "a"
        depends_on = ("b",)
        def score(self, account_data):
            return DetectorResult.uncertain("a")
    class B(BaseDetector):
        name = "b"
        depends_on = ("a",)
        def score(self, account_data):
            return DetectorResult.uncertain("b")
    with pytest.raises(DetectorDAGError):
        DetectorOrchestrator(policy, graph, {"a": A, "b": B})

