from __future__ import annotations

import time

from threatlib.risk.synthesis import RiskSynthesizer
from threatlib.signals.behavioral_drift import BehavioralDriftDetector
from threatlib.signals.stalking_safety import StalkingSafetyDetector


def test_behavioral_drift_detects_established_account_shift(active_policy, graph):
    account_id = "drift_established"
    now = time.time()
    graph.upsert_account({"account_id": account_id}, created_at=now - 10 * 86400)
    for index in range(12):
        graph.record_event(account_id, "view_profile", {"target_account_id": f"user_{index}"}, timestamp=now - 5 * 86400 + index)
    for index in range(8):
        graph.record_event(account_id, "send_dm", {"recipient_id": f"target_{index}", "has_link": False}, timestamp=now - 3600 + index)

    result = BehavioralDriftDetector(policy=active_policy, graph=graph).safe_score({"account_id": account_id})

    assert result.fraud_mass > 0.5
    assert result.metadata["classification"] == "established_behavior_drift"
    assert result.metadata["temporary_restrictions"][0]["feature"] == "send_dm"


def test_behavioral_drift_treats_new_user_as_uncertain(active_policy, graph):
    account_id = "drift_new_user"
    graph.upsert_account({"account_id": account_id}, created_at=time.time() - 3600)
    for index in range(8):
        graph.record_event(account_id, "send_dm", {"recipient_id": f"target_{index}"})

    result = BehavioralDriftDetector(policy=active_policy, graph=graph).safe_score({"account_id": account_id})

    assert result.is_uncertain()
    assert result.metadata["classification"] == "new_user_behavior"


def test_temporary_restriction_caps_non_correlated_drift_action(active_policy, graph):
    active_policy.minimum_detectors_required = 1
    account_id = "drift_pipeline"
    now = time.time()
    graph.upsert_account({"account_id": account_id}, created_at=now - 10 * 86400)
    for index in range(12):
        graph.record_event(account_id, "view_profile", {"target_account_id": f"user_{index}"}, timestamp=now - 8 * 86400 + index)
    for index in range(8):
        graph.record_event(account_id, "send_dm", {"recipient_id": f"target_{index}"}, timestamp=now - 600 + index)

    payload = RiskSynthesizer(active_policy, graph=graph).score({"account_id": account_id, "device_hash": "known_device"})

    assert payload["temporary_restrictions"]
    assert payload["restrictions"]["send_dm"] >= 0.9
    assert payload["action"] in {"review_queue", "audience_narrow", "velocity_throttle", "monitor"}


def test_stalking_safety_detects_target_fixation(active_policy, graph):
    account_id = "safety_fixation"
    graph.upsert_account({"account_id": account_id}, created_at=time.time() - 20 * 86400)
    for _ in range(28):
        graph.record_event(account_id, "view_profile", {"target_account_id": "target_same"})
    graph.record_event(account_id, "send_dm", {"recipient_id": "target_same"})

    result = StalkingSafetyDetector(policy=active_policy, graph=graph).safe_score({"account_id": account_id})

    assert result.fraud_mass > 0.5
    assert result.metadata["top_target_view_count"] >= 25
    assert {item["feature"] for item in result.metadata["temporary_restrictions"]} == {"view_profile", "send_dm"}


def test_stalking_safety_broad_browsing_is_legitimate_or_uncertain(active_policy, graph):
    account_id = "safety_broad"
    graph.upsert_account({"account_id": account_id}, created_at=time.time() - 20 * 86400)
    for index in range(15):
        graph.record_event(account_id, "view_profile", {"target_account_id": f"target_{index}"})

    result = StalkingSafetyDetector(policy=active_policy, graph=graph).safe_score({"account_id": account_id})

    assert result.legitimate_mass > 0.3 or result.is_uncertain()
    assert StalkingSafetyDetector(policy=active_policy, graph=graph).safe_score({}).is_uncertain()
