from __future__ import annotations

from fastapi.testclient import TestClient

from threatlib.replay import ReplayEngine, load_replay_file
from threatlib.server import create_app


def test_replay_engine_is_deterministic(active_policy, bot_fixture):
    records = [
        {"type": "event", "account_id": "replay_acct", "event_type": "view_profile", "event_data": {"results_clicked": 1}},
        {"type": "score", "account_data": {**bot_fixture, "account_id": "replay_acct"}},
    ]
    first = ReplayEngine(active_policy).replay(records)
    second = ReplayEngine(active_policy).replay(records)
    assert first["summary"]["score_count"] == 1
    assert first["timeline"][1]["risk_score"] == second["timeline"][1]["risk_score"]
    assert first["summary"]["policy_hash"] == second["summary"]["policy_hash"]


def test_load_replay_jsonl_example():
    records = load_replay_file("examples/replay/demo.jsonl")
    assert len(records) >= 3
    assert records[0]["type"] == "event"


def test_replay_api_and_metrics(active_policy, graph, bot_fixture):
    app = create_app(policy=active_policy, graph=graph)
    client = TestClient(app)
    payload = {
        "records": [
            {"type": "score", "account_data": {**bot_fixture, "account_id": "api_replay_acct"}},
        ]
    }
    response = client.post("/replay", json=payload)
    assert response.status_code == 200
    assert response.json()["summary"]["score_count"] == 1

    metrics = client.get("/metrics/replay").json()
    assert metrics["last_replay_available"] is True
    assert metrics["score_count"] == 1


def test_replay_default_does_not_mutate_primary_graph(active_policy, graph, bot_fixture):
    app = create_app(policy=active_policy, graph=graph)
    client = TestClient(app)
    before = graph.audit_count()
    client.post(
        "/replay",
        json={"records": [{"type": "score", "account_data": {**bot_fixture, "account_id": "isolated_replay"}}]},
    )
    assert graph.audit_count() == before
