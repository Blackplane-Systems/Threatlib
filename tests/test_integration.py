from __future__ import annotations

from fastapi.testclient import TestClient

from threatlib.server import create_app


def test_api_integration_sequence(active_policy, graph, bot_fixture, human_fixture):
    app = create_app(policy=active_policy, graph=graph)
    client = TestClient(app)

    bot = client.post("/score", json=bot_fixture)
    assert bot.status_code == 200
    bot_json = bot.json()
    assert bot_json["risk_score"] > 0.5
    assert bot_json["action"] != "monitor"

    human = client.post("/score", json=human_fixture)
    assert human.status_code == 200
    human_json = human.json()
    assert human_json["risk_score"] < 0.3
    assert human_json["action"] == "monitor"

    shadow_policy = active_policy.model_copy(deep=True)
    shadow_policy.shadow_mode = True
    shadow_app = create_app(policy=shadow_policy, graph=graph)
    shadow_client = TestClient(shadow_app)
    shadow = shadow_client.post("/score", json=bot_fixture)
    assert shadow.status_code == 200
    assert shadow.json()["action"] == "monitor"

    insufficient = client.post("/score", json={"account_id": "few_signals"})
    assert insufficient.status_code == 200
    assert insufficient.json()["threat_tier"] == "insufficient_evidence"

    for index in range(5):
        event = client.post(
            "/event",
            json={
                "account_id": "event_account",
                "event_type": "view_profile",
                "event_data": {"results_clicked": index},
                "session_id": "session_1",
            },
        )
    assert event.status_code == 200
    assert event.json()["hmm_ready"] is True

    for index in range(3):
        report = client.post(
            "/report",
            json={
                "target_account_id": "reported_account",
                "reporter_account_id": f"reporter_{index}",
                "category": "spam",
                "reporter_trust_score": 0.8,
            },
        )
    assert report.status_code == 200
    assert report.json()["review_triggered"] is True

    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"

    metrics = client.get("/metrics")
    assert metrics.status_code == 200
    assert metrics.json()["request_count"] > 0

