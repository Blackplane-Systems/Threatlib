"""Operational metrics built from privacy-safe persisted state."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from typing import Any

from threatlib.graph.account_graph import AccountGraph


def graph_metrics(graph: AccountGraph) -> dict[str, Any]:
    return {
        "account_count": graph.account_count(),
        "audit_count": graph.audit_count(),
        "edge_count": len(graph.all_edges()),
        "event_count": len(graph.all_recent_events()),
        "feedback_count": graph.feedback_count(),
        "threat_indicator_count": graph.threat_indicator_count(),
        "training_feature_count": graph.training_feature_count(),
    }


def detector_metrics(graph: AccountGraph, limit: int = 500) -> dict[str, Any]:
    rows = graph.conn.execute(
        "SELECT masses_json, timestamp FROM audit_log ORDER BY timestamp DESC LIMIT ?",
        (limit,),
    ).fetchall()
    aggregate: dict[str, dict[str, Any]] = defaultdict(_detector_bucket)
    for row in rows:
        try:
            masses = json.loads(row["masses_json"])
        except json.JSONDecodeError:
            continue
        for name, result in masses.items():
            bucket = aggregate[name]
            fraud = float(result.get("fraud_mass", 0.0))
            legitimate = float(result.get("legitimate_mass", 0.0))
            uncertainty = float(result.get("uncertainty_mass", 1.0))
            bucket["count"] += 1
            bucket["fraud_mass_total"] += fraud
            bucket["legitimate_mass_total"] += legitimate
            bucket["uncertainty_mass_total"] += uncertainty
            if fraud + legitimate > 0.05:
                bucket["non_trivial_count"] += 1
            if uncertainty >= 0.999:
                bucket["uncertain_count"] += 1
            bucket["last_seen"] = max(bucket["last_seen"] or 0.0, float(row["timestamp"]))
    return {
        name: {
            "count": bucket["count"],
            "non_trivial_count": bucket["non_trivial_count"],
            "uncertainty_rate": bucket["uncertain_count"] / bucket["count"] if bucket["count"] else 0.0,
            "avg_fraud_mass": bucket["fraud_mass_total"] / bucket["count"] if bucket["count"] else 0.0,
            "avg_legitimate_mass": bucket["legitimate_mass_total"] / bucket["count"] if bucket["count"] else 0.0,
            "avg_uncertainty_mass": bucket["uncertainty_mass_total"] / bucket["count"] if bucket["count"] else 0.0,
            "last_seen": bucket["last_seen"],
        }
        for name, bucket in sorted(aggregate.items())
    }


def replay_metrics(last_replay: dict[str, Any] | None) -> dict[str, Any]:
    if not last_replay:
        return {
            "last_replay_available": False,
            "score_count": 0,
            "action_distribution": {},
            "quorum_met_rate": 0.0,
        }
    summary = last_replay.get("summary", last_replay)
    return {
        "last_replay_available": True,
        "score_count": summary.get("score_count", 0),
        "action_distribution": summary.get("action_distribution", {}),
        "average_uncertainty": summary.get("average_uncertainty"),
        "quorum_met_rate": summary.get("quorum_met_rate", 0.0),
        "policy_hash": summary.get("policy_hash"),
        "finished_at": summary.get("finished_at"),
    }


def prometheus_text(
    counters: dict[str, int],
    graph: AccountGraph,
    last_replay: dict[str, Any] | None = None,
) -> str:
    graph_values = graph_metrics(graph)
    replay_values = replay_metrics(last_replay)
    actions = _action_counts(graph)
    lines = [
        "# HELP threatlib_requests_total Total API requests served by this process.",
        "# TYPE threatlib_requests_total counter",
        f"threatlib_requests_total {counters.get('request_count', 0)}",
        "# HELP threatlib_scores_total Total score requests served by this process.",
        "# TYPE threatlib_scores_total counter",
        f"threatlib_scores_total {counters.get('score_count', 0)}",
        "# HELP threatlib_accounts Total accounts known to the configured store.",
        "# TYPE threatlib_accounts gauge",
        f"threatlib_accounts {graph_values['account_count']}",
        "# HELP threatlib_audit_events Total append-only score audit records.",
        "# TYPE threatlib_audit_events counter",
        f"threatlib_audit_events {graph_values['audit_count']}",
        "# HELP threatlib_graph_edges Total privacy-safe graph edges.",
        "# TYPE threatlib_graph_edges gauge",
        f"threatlib_graph_edges {graph_values['edge_count']}",
        "# HELP threatlib_replay_last_scores Number of score records in the last replay.",
        "# TYPE threatlib_replay_last_scores gauge",
        f"threatlib_replay_last_scores {replay_values['score_count']}",
        "# HELP threatlib_replay_quorum_met_rate Quorum rate in the last replay.",
        "# TYPE threatlib_replay_quorum_met_rate gauge",
        f"threatlib_replay_quorum_met_rate {replay_values['quorum_met_rate']}",
    ]
    lines.extend(["# HELP threatlib_actions_total Action recommendations by action.", "# TYPE threatlib_actions_total counter"])
    for action, count in sorted(actions.items()):
        lines.append(f'threatlib_actions_total{{action="{action}"}} {count}')
    lines.append("")
    return "\n".join(lines)


def _detector_bucket() -> dict[str, Any]:
    return {
        "count": 0,
        "non_trivial_count": 0,
        "uncertain_count": 0,
        "fraud_mass_total": 0.0,
        "legitimate_mass_total": 0.0,
        "uncertainty_mass_total": 0.0,
        "last_seen": None,
    }


def _action_counts(graph: AccountGraph) -> dict[str, int]:
    rows = graph.conn.execute("SELECT action FROM audit_log").fetchall()
    return dict(Counter(row["action"] for row in rows))
