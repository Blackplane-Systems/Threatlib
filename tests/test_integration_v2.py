from __future__ import annotations

import time

from fastapi.testclient import TestClient

from threatlib.config.policy import PolicyLoader
from threatlib.server import create_app


def test_integration_v2_twelve_steps(policy, active_policy, graph, bot_fixture, human_fixture):
    default_policy = PolicyLoader.load("threatlib.yaml")
    assert default_policy.shadow_mode is True

    app = create_app(policy=active_policy, graph=graph)
    client = TestClient(app)

    bot = client.post("/score", json=bot_fixture)
    assert bot.status_code == 200
    assert bot.json()["risk_score"] > 0.50
    assert bot.json()["action"] != "monitor"

    human = client.post("/score", json=human_fixture)
    assert human.status_code == 200
    assert human.json()["risk_score"] < 0.30
    assert human.json()["action"] == "monitor"

    shadow_policy = active_policy.model_copy(deep=True)
    shadow_policy.shadow_mode = True
    shadow_app = create_app(policy=shadow_policy, graph=graph)
    shadow_client = TestClient(shadow_app)
    shadow = shadow_client.post("/score", json=bot_fixture)
    assert shadow.json()["action"] == "monitor"

    insufficient = client.post("/score", json={"account_id": "insufficient_v2"})
    assert insufficient.json()["threat_tier"] == "insufficient_evidence"

    for index in range(5):
        event = client.post("/event", json={"account_id": "event_v2", "event_type": "view_profile", "event_data": {"index": index}, "session_id": "s"})
    assert event.json()["hmm_ready"] is True

    for index in range(3):
        report = client.post("/report", json={"target_account_id": "reported_v2", "reporter_account_id": f"r{index}", "category": "spam", "reporter_trust_score": 0.9})
    assert report.json()["review_triggered"] is True

    assert client.get("/health").json()["status"] == "ok"
    assert client.get("/metrics").json()["request_count"] > 0

    phishing = "phishing_v2"
    for event_type in ["view_profile", "view_profile", "search", "follow_user", "send_dm", "send_dm", "send_dm", "send_dm", "send_dm", "send_dm"]:
        client.post("/event", json={"account_id": phishing, "event_type": event_type, "event_data": {"has_link": event_type == "send_dm", "link_domain": "scam.test"}, "session_id": "phish"})
    phishing_score = client.post("/score", json={**bot_fixture, "account_id": phishing})
    hmm = phishing_score.json()["detectors"]["hmm_intent"]
    assert hmm["metadata"]["state"] in {"escalating", "acting"}

    now = time.time()
    for index in range(5):
        account_id = f"coord_{index}"
        graph.upsert_account({"account_id": account_id, "device_hash": "coord_device", "ip_prefix": "172.16.9", "email_domain": "new.xyz"}, created_at=now - index * 10)
        graph.record_event(account_id, "send_dm", {"has_link": True, "link_domain": "same-scam.test"}, timestamp=now - index)
    coordinated = client.post("/score", json={**bot_fixture, "account_id": "coord_4", "device_hash": "coord_device", "ip_prefix": "172.16.9"})
    assert coordinated.json()["threat_tier"] == "tier_3_cluster"

    csam = client.post("/report", json={"target_account_id": "child_safety", "reporter_account_id": "trusted", "category": "csam", "reporter_trust_score": 1.0})
    assert csam.json()["emergency_action"] == "suspend"
    csam_score = client.post("/score", json={"account_id": "child_safety", "email_domain": "gmail.com", "email_domain_age_days": 9999})
    assert csam_score.json()["threat_tier"] == "emergency_escalation"

    graph_response = client.get("/graph")
    assert graph_response.status_code == 200
    assert graph_response.json()["communities"]
    assert "spectral_gap" in graph_response.json()["communities"][0]
