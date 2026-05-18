from __future__ import annotations

import time

from threatlib.domains import apply_domain_mode
from threatlib.risk.synthesis import RiskSynthesizer
from threatlib.signals.domain_behavior import ChatAbuseDetector, GamingIntegrityDetector, SocialBehaviorDetector


def test_social_behavior_detector_phishing_funnel(policy, graph):
    social = apply_domain_mode(policy, "social_media")
    account_id = "social_funnel"
    graph.upsert_account({"account_id": account_id}, created_at=time.time() - 1800)
    for index in range(35):
        graph.record_event(account_id, "follow_user", {"target_account_id": f"target_{index}"})
    for index in range(16):
        graph.record_event(account_id, "send_dm", {"recipient_id": f"user_{index}", "has_link": True, "link_domain": "promo.test"})

    result = SocialBehaviorDetector(policy=social, graph=graph).safe_score({"account_id": account_id})

    assert result.fraud_mass > 0.5
    assert result.metadata["dm_link_density"] > 0.6


def test_social_behavior_detector_human_or_uncertain(policy, graph):
    social = apply_domain_mode(policy, "social_media")
    account_id = "social_human"
    graph.upsert_account({"account_id": account_id}, created_at=time.time() - 7200)
    for _ in range(10):
        graph.record_event(account_id, "view_profile", {})
    graph.record_event(account_id, "send_dm", {"recipient_id": "friend_1", "has_link": False})

    result = SocialBehaviorDetector(policy=social, graph=graph).safe_score({"account_id": account_id})

    assert result.legitimate_mass > 0.3 or result.is_uncertain()
    assert SocialBehaviorDetector(policy=social, graph=graph).safe_score({}).is_uncertain()


def test_chat_abuse_detector_forward_and_broadcast_abuse(policy, graph):
    chat = apply_domain_mode(policy, "chat_app")
    account_id = "chat_fanout"
    graph.upsert_account({"account_id": account_id}, created_at=time.time() - 1800)
    for index in range(22):
        graph.record_event(account_id, "forward_message", {"recipient_id": f"recipient_{index}", "has_link": True, "link_domain": "claim.test"})
    for index in range(3):
        graph.record_event(account_id, "broadcast_message", {"recipient_id": f"broadcast_{index}", "has_link": True, "link_domain": "claim.test"})

    result = ChatAbuseDetector(policy=chat, graph=graph).safe_score({"account_id": account_id})

    assert result.fraud_mass > 0.5
    assert result.metadata["distinct_recipients_24h"] >= 20


def test_chat_abuse_detector_conversation_legitimate_or_uncertain(policy, graph):
    chat = apply_domain_mode(policy, "chat_app")
    account_id = "chat_human"
    sample = {
        "account_id": account_id,
        "metadata": {
            "message_count_24h": 5,
            "inbound_message_count_24h": 3,
            "outbound_message_count_24h": 5,
            "forward_count_24h": 0,
            "broadcast_count_24h": 0,
            "link_message_count_24h": 0,
        },
    }
    result = ChatAbuseDetector(policy=chat, graph=graph).safe_score(sample)

    assert result.legitimate_mass > 0.3 or result.is_uncertain()
    assert ChatAbuseDetector(policy=chat, graph=graph).safe_score({}).is_uncertain()


def test_gaming_integrity_detector_economy_and_match_farming(policy, graph):
    gaming = apply_domain_mode(policy, "gaming")
    account_id = "gaming_farm"
    graph.upsert_account({"account_id": account_id}, created_at=time.time() - 3600)
    for _ in range(10):
        graph.record_event(account_id, "finish_match", {"duration_s": 35, "result_code": 1})
    for index in range(4):
        graph.record_event(account_id, "trade_item", {"recipient_id": f"mule_{index}", "item_value": 350})
    for _ in range(5):
        graph.record_event(account_id, "ranked_match", {"duration_s": 40})

    result = GamingIntegrityDetector(policy=gaming, graph=graph).safe_score({"account_id": account_id})

    assert result.fraud_mass > 0.5
    assert result.metadata["economy_value_moved_24h"] >= 1000


def test_gaming_integrity_detector_normal_play_legitimate_or_uncertain(policy, graph):
    gaming = apply_domain_mode(policy, "gaming")
    account_id = "gaming_human"
    graph.upsert_account({"account_id": account_id}, created_at=time.time() - 172800)
    for duration in [300, 420, 690, 530]:
        graph.record_event(account_id, "finish_match", {"duration_s": duration})

    result = GamingIntegrityDetector(policy=gaming, graph=graph).safe_score({"account_id": account_id})

    assert result.legitimate_mass > 0.3 or result.is_uncertain()
    assert GamingIntegrityDetector(policy=gaming, graph=graph).safe_score({}).is_uncertain()


def test_domain_detectors_join_risk_pipeline(policy, graph):
    social = apply_domain_mode(policy, "social_media")
    account_id = "pipeline_social"
    graph.upsert_account({"account_id": account_id}, created_at=time.time() - 1200)
    for index in range(18):
        graph.record_event(account_id, "send_dm", {"recipient_id": f"target_{index}", "has_link": True, "link_domain": "drop.test"})

    payload = RiskSynthesizer(social, graph=graph).score({"account_id": account_id})

    assert "social_behavior" in payload["detectors"]
    assert payload["detectors"]["social_behavior"]["fraud_mass"] > 0.5
