"""Streamlit operator dashboard."""

from __future__ import annotations

import argparse
import json

from threatlib.config.policy import PolicyLoader
from threatlib.graph.account_graph import AccountGraph
from threatlib.observability.metrics import detector_metrics, graph_metrics, replay_metrics
from threatlib.replay import ReplayEngine
from threatlib.risk.synthesis import RiskSynthesizer


def render(config_path: str = "threatlib.yaml") -> None:
    import streamlit as st

    policy = PolicyLoader.load(config_path)
    graph = AccountGraph(policy.graph_db_path())
    st.set_page_config(page_title="ThreatLib Dashboard", layout="wide")
    page = st.sidebar.radio(
        "Page",
        [
            "System Status",
            "Score Distribution",
            "Attack Vector Activity",
            "Detector Health",
            "Account Graph",
            "Threshold Calibration",
            "Replay Simulation",
            "Operational Metrics",
            "Live Scoring",
        ],
    )
    if page == "System Status":
        st.title("System Status")
        st.metric("Accounts", graph.account_count())
        st.metric("Audit Events", graph.audit_count())
        st.metric("Shadow Mode", str(policy.shadow_mode))
        st.write({"canary_count": len(policy.canary.accounts), "webhook_alert": policy.webhooks.high_risk_alert})
    elif page == "Score Distribution":
        st.title("Score Distribution")
        rows = graph.conn.execute("SELECT final_score, action, threat_tier, timestamp FROM audit_log ORDER BY timestamp DESC").fetchall()
        st.bar_chart([float(row["final_score"]) for row in rows] or [0.0])
        st.write({"actions": _count(row["action"] for row in rows), "tiers": _count(row["threat_tier"] for row in rows)})
    elif page == "Attack Vector Activity":
        st.title("Attack Vector Activity")
        st.write({f"AV-{index:02d}": 0 for index in range(1, 16)})
    elif page == "Detector Health":
        st.title("Detector Health")
        st.write({"enabled_v1": sorted(policy.signals), "enabled_v2": sorted(policy.detectors)})
    elif page == "Account Graph":
        st.title("Account Graph")
        st.write({"nodes": graph.account_count(), "edges": len(graph.all_edges())})
        st.dataframe([dict(row) for row in graph.all_edges()])
    elif page == "Threshold Calibration":
        st.title("Threshold Calibration")
        for feature, config in policy.feature_restrictions.items():
            st.slider(feature, 0.0, 1.0, float(config.threshold))
    elif page == "Replay Simulation":
        st.title("Replay Simulation")
        payload = st.text_area("Replay JSON records", "[]")
        deterministic = st.checkbox("Deterministic replay", value=True)
        if st.button("Run Replay"):
            records = json.loads(payload)
            result = ReplayEngine(policy, deterministic=deterministic).replay(records)
            st.json(result["summary"])
            st.dataframe(result["timeline"])
    elif page == "Operational Metrics":
        st.title("Operational Metrics")
        st.json(graph_metrics(graph))
        st.subheader("Detector Health")
        st.json(detector_metrics(graph))
        st.subheader("Replay")
        st.json(replay_metrics(None))
    else:
        st.title("Live Scoring")
        payload = st.text_area("Account JSON", "{}")
        if st.button("Score"):
            result = RiskSynthesizer(policy, graph=graph).score(json.loads(payload))
            st.json(result)


def _count(values):
    counts = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the ThreatLib Streamlit dashboard")
    parser.add_argument("--config", default="threatlib.yaml")
    args, _ = parser.parse_known_args()
    render(args.config)


if __name__ == "__main__":
    main()
