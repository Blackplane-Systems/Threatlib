from __future__ import annotations

import time

from fastapi.testclient import TestClient

from threatlib.server import create_app


def test_feedback_endpoint_records_all_confusion_outcomes(active_policy, graph, bot_fixture, human_fixture):
    app = create_app(policy=active_policy, graph=graph)
    client = TestClient(app)

    client.post("/score", json=bot_fixture)
    client.post("/score", json=human_fixture)

    labels = [
        {"account_id": bot_fixture["account_id"], "outcome": "true_positive", "notes": "confirmed abuse"},
        {"account_id": human_fixture["account_id"], "outcome": "true_negative"},
        {"account_id": "manual_fp", "outcome": "false_positive", "risk_score": 0.82},
        {"account_id": "manual_fn", "outcome": "false_negative", "risk_score": 0.12},
    ]
    for label in labels:
        response = client.post("/feedback", json=label)
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    metrics = client.get("/metrics/model").json()
    assert metrics["label_count"] == 4
    assert metrics["confusion_matrix"] == {
        "true_positive": 1,
        "true_negative": 1,
        "false_positive": 1,
        "false_negative": 1,
    }
    assert metrics["metrics"]["precision"] == 0.5
    assert metrics["metrics"]["recall"] == 0.5
    assert metrics["metrics"]["false_positive_rate"] == 0.5
    assert metrics["metrics"]["false_negative_rate"] == 0.5

    stored = graph.conn.execute("SELECT notes_hash FROM feedback_labels WHERE notes_hash IS NOT NULL").fetchone()
    assert stored is not None
    assert stored["notes_hash"] != "confirmed abuse"


def test_fast_deploy_status_after_one_day_observation(active_policy, graph, bot_fixture, human_fixture):
    active_policy.fast_deploy.enabled = True
    active_policy.fast_deploy.observation_hours = 24
    active_policy.fast_deploy.min_scores = 2
    active_policy.fast_deploy.min_labels = 2
    active_policy.fast_deploy.min_precision = 0.5
    active_policy.fast_deploy.min_recall = 0.5
    active_policy.fast_deploy.max_false_positive_rate = 0.5
    active_policy.fast_deploy.max_false_negative_rate = 0.5
    active_policy.fast_deploy.active_action_cap = "review_queue"

    app = create_app(policy=active_policy, graph=graph)
    client = TestClient(app)

    old_ts = time.time() - 25 * 3600
    graph.append_audit("old_fast_deploy_seed", "seed", [], {}, 0.0, "monitor", "scored", {}, timestamp=old_ts)
    client.post("/score", json=bot_fixture)
    client.post("/score", json=human_fixture)

    client.post("/feedback", json={"account_id": bot_fixture["account_id"], "outcome": "tp"})
    client.post("/feedback", json={"account_id": human_fixture["account_id"], "outcome": "tn"})

    status = client.get("/deployment/fast-status").json()
    assert status["eligible"] is True
    assert status["checks"]["observation_hours"] is True
    assert status["checks"]["min_scores"] is True
    assert status["checks"]["min_labels"] is True

    action = client.post("/score", json={**bot_fixture, "account_id": "fast_mode_bot"}).json()["action"]
    assert action in {"monitor", "velocity_throttle", "audience_narrow", "review_queue"}
