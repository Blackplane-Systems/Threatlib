from __future__ import annotations

import json

import pytest

from threatlib.risk.synthesis import RiskSynthesizer


def test_username_raw_not_stored(policy, graph, bot_fixture):
    RiskSynthesizer(policy, graph=graph).score(bot_fixture)
    row = graph.get_account(bot_fixture["account_id"])
    stored = dict(row)
    assert "username_raw" not in stored
    assert row["username_pattern"] is not None
    assert bot_fixture["username_raw"] not in json.dumps(stored)


def test_event_query_sanitized(graph):
    graph.record_event("acct", "search", {"query": "private medical condition", "results_clicked": 1})
    row = graph.recent_events("acct")[0]
    stored = row["event_data_json"]
    assert "private medical condition" not in stored
    assert "query_sha256" in stored


def test_audit_log_append_only(policy, graph, bot_fixture):
    result = RiskSynthesizer(policy, graph=graph).score(bot_fixture)
    with pytest.raises(Exception):
        with graph.conn:
            graph.conn.execute("UPDATE audit_log SET action = 'changed' WHERE audit_id = ?", (result["audit_id"],))

