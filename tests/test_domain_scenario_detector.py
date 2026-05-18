from __future__ import annotations

import time

from threatlib.domains import apply_domain_mode
from threatlib.risk.synthesis import RiskSynthesizer
from threatlib.signals.domain_scenario import DomainScenarioDetector


def test_social_scenario_detector_matches_dm_phishing_playbook(policy, graph):
    social = apply_domain_mode(policy, "social_media")
    account_id = "scenario_social"
    graph.upsert_account({"account_id": account_id}, created_at=time.time() - 1800)
    for index in range(4):
        graph.record_event(account_id, "view_profile", {"target_account_id": f"target_{index}"})
    graph.record_event(account_id, "follow_user", {"target_account_id": "target_0"})
    for index in range(4):
        graph.record_event(account_id, "send_dm", {"recipient_id": f"target_{index}", "has_link": True, "link_domain": "promo.test"})

    payload = RiskSynthesizer(social, graph=graph).score({"account_id": account_id})
    result = payload["detectors"]["domain_scenario"]

    assert result["fraud_mass"] > 0.5
    assert "social_dm_phishing_funnel" in result["metadata"]["matched_scenarios"]


def test_chat_scenario_detector_matches_forward_cascade(policy, graph):
    chat = apply_domain_mode(policy, "chat_app")
    account_id = "scenario_chat"
    graph.upsert_account({"account_id": account_id}, created_at=time.time() - 1800)
    for index in range(10):
        graph.record_event(account_id, "forward_message", {"recipient_id": f"user_{index}", "has_link": True, "link_domain": "claim.test"})

    result = DomainScenarioDetector(policy=chat, graph=graph).safe_score({"account_id": account_id})

    assert result.fraud_mass > 0.5
    assert "chat_forward_cascade" in result.metadata["matched_scenarios"]


def test_gaming_scenario_detector_matches_economy_mule(policy, graph):
    gaming = apply_domain_mode(policy, "gaming")
    account_id = "scenario_game"
    graph.upsert_account({"account_id": account_id}, created_at=time.time() - 3600)
    for index in range(4):
        graph.record_event(account_id, "trade_item", {"recipient_id": f"mule_{index}", "item_value": 400})

    result = DomainScenarioDetector(policy=gaming, graph=graph).safe_score({"account_id": account_id})

    assert result.fraud_mass > 0.5
    assert "new_account_economy_mule" in result.metadata["matched_scenarios"]


def test_domain_scenario_detector_clean_exploration_or_uncertain(policy, graph):
    social = apply_domain_mode(policy, "social_media")
    account_id = "scenario_clean"
    graph.upsert_account({"account_id": account_id}, created_at=time.time() - 7200)
    for index in range(6):
        graph.record_event(account_id, "view_profile", {"target_account_id": f"user_{index}"})

    result = DomainScenarioDetector(policy=social, graph=graph).safe_score({"account_id": account_id})

    assert result.legitimate_mass > 0.3 or result.is_uncertain()
    assert DomainScenarioDetector(policy=social, graph=graph).safe_score({}).is_uncertain()
