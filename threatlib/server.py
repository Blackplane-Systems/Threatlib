"""FastAPI server for ThreatLib."""

from __future__ import annotations

import argparse
import time
from typing import Any

from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel, Field
import uvicorn

from threatlib.config.policy import Policy, PolicyLoader
from threatlib.adapters import AdapterRegistry
from threatlib.graph.account_graph import AccountGraph, hash_value
from threatlib.observability.metrics import detector_metrics, prometheus_text, replay_metrics
from threatlib.policy.versioning import lint_policy, policy_summary
from threatlib.presets import list_presets, load_preset
from threatlib.replay import ReplayEngine
from threatlib.risk.feedback import fast_deploy_status, model_metrics
from threatlib.risk.synthesis import RiskSynthesizer


class EventRequest(BaseModel):
    account_id: str
    event_type: str
    event_data: dict[str, Any] = Field(default_factory=dict)
    session_id: str | None = None
    timestamp: float | None = None


class ReportRequest(BaseModel):
    target_account_id: str
    reporter_account_id: str
    category: str
    reporter_trust_score: float = Field(ge=0.0, le=1.0)
    timestamp: float | None = None


class AppealRequest(BaseModel):
    account_id: str
    appeal_text: str = ""


class FeedbackRequest(BaseModel):
    account_id: str
    outcome: str
    source: str = "manual"
    risk_score: float | None = Field(default=None, ge=0.0, le=1.0)
    threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    notes: str | None = None
    timestamp: float | None = None


class ReplayRequest(BaseModel):
    records: list[dict[str, Any]]
    deterministic: bool = True
    shadow_mode: bool | None = None
    persist: bool = False


def create_app(
    config_path: str = "threatlib.yaml",
    policy: Policy | None = None,
    graph: AccountGraph | None = None,
) -> FastAPI:
    app = FastAPI(title="ThreatLib", version="1.0.0")
    loaded_policy = policy or PolicyLoader.load(config_path)
    store = graph or AccountGraph(loaded_policy.graph_db_path())
    synthesizer = RiskSynthesizer(loaded_policy, graph=store)
    adapter = AdapterRegistry.from_policy(loaded_policy)
    metrics = {"request_count": 0, "score_count": 0, "event_count": 0, "report_count": 0, "feedback_count": 0}
    last_replay: dict[str, Any] | None = None

    @app.middleware("http")
    async def count_requests(request, call_next):  # type: ignore[no-untyped-def]
        metrics["request_count"] += 1
        return await call_next(request)

    @app.post("/score")
    async def score(account_data: dict[str, Any]) -> dict[str, Any]:
        metrics["score_count"] += 1
        account_data = adapter.preprocess_account_data(account_data)
        try:
            return synthesizer.score(account_data)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/event")
    async def event(payload: EventRequest) -> dict[str, Any]:
        metrics["event_count"] += 1
        timestamp = payload.timestamp if payload.timestamp is not None else time.time()
        event_type, event_data = adapter.translate_event(payload.event_type, payload.event_data)
        store.record_event(payload.account_id, event_type, event_data, payload.session_id, timestamp)
        if payload.session_id:
            store.record_session(
                account_id=payload.account_id,
                session_id=payload.session_id,
                device_hash=event_data.get("device_hash"),
                ip_prefix=event_data.get("ip_prefix"),
                ip_geo_country=event_data.get("ip_geo_country"),
                device_timezone=event_data.get("device_timezone"),
                duration_s=event_data.get("session_duration_s"),
                event_count=1,
                created_at=timestamp,
            )
        events_seen = store.count_events(payload.account_id)
        return {"status": "ok", "event_type": event_type, "events_seen": events_seen, "hmm_ready": events_seen >= 5}

    @app.post("/report")
    async def report(payload: ReportRequest) -> dict[str, Any]:
        metrics["report_count"] += 1
        store.add_report(
            payload.target_account_id,
            payload.reporter_account_id,
            payload.category,
            payload.reporter_trust_score,
            payload.timestamp,
        )
        reports = store.reports_for_account(payload.target_account_id, time.time() - 90.0 * 86400.0)
        severe = payload.category in loaded_policy.reporting.severe_category_immediate_review
        review_triggered = severe or len(reports) >= loaded_policy.reporting.reports_to_trigger_review
        emergency_action = "suspend" if payload.category == "csam" else None
        return {"status": "ok", "report_count": len(reports), "review_triggered": review_triggered, "emergency_action": emergency_action}

    @app.post("/appeal")
    async def appeal(payload: AppealRequest) -> dict[str, Any]:
        appeal_hash = hash_value(payload.appeal_text) if payload.appeal_text else ""
        with store.conn:
            store.conn.execute(
                "INSERT INTO appeals(account_id, appeal_text_hash, status, created_at) VALUES (?, ?, 'open', ?)",
                (payload.account_id, appeal_hash, time.time()),
            )
        return {"status": "ok", "appeal_opened": True}

    @app.post("/feedback")
    async def feedback(payload: FeedbackRequest) -> dict[str, Any]:
        metrics["feedback_count"] += 1
        risk_score = payload.risk_score
        if risk_score is None:
            risk_score = store.latest_risk_score(payload.account_id)
        threshold = payload.threshold
        if threshold is None:
            threshold = loaded_policy.action_thresholds.get("soft_restrict", 0.65)
        try:
            label = store.record_feedback_label(
                account_id=payload.account_id,
                outcome=payload.outcome,
                source=payload.source,
                risk_score=risk_score,
                threshold=threshold,
                notes=payload.notes,
                created_at=payload.timestamp,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"status": "ok", "label": label, "model_metrics": store.feedback_metrics()}

    @app.post("/replay")
    async def replay(payload: ReplayRequest) -> dict[str, Any]:
        nonlocal last_replay
        replay_policy = loaded_policy.model_copy(deep=True)
        if payload.shadow_mode is not None:
            replay_policy.shadow_mode = payload.shadow_mode
        replay_graph = store if payload.persist else AccountGraph(":memory:")
        result = ReplayEngine(
            replay_policy,
            graph=replay_graph,
            deterministic=payload.deterministic,
        ).replay(payload.records)
        last_replay = result
        app.state.last_replay = result
        return result

    @app.get("/account/{account_id}")
    async def account(account_id: str) -> dict[str, Any]:
        row = store.get_account(account_id)
        if row is None:
            raise HTTPException(status_code=404, detail="account not found")
        return {
            "account_id": row["account_id"],
            "created_at": row["created_at"],
            "email_domain": row["email_domain"],
            "ip_prefix": row["ip_prefix"],
            "device_hash": row["device_hash"],
            "device_model": row["device_model"],
            "status": row["status"],
            "human_review_confirmed": bool(row["human_review_confirmed"]),
            "username_entropy": row["username_entropy"],
            "username_bigram_entropy": row["username_bigram_entropy"],
            "username_digit_suffix": bool(row["username_digit_suffix"]) if row["username_digit_suffix"] is not None else None,
        }

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {"status": "ok", "shadow_mode": loaded_policy.shadow_mode}

    @app.get("/metrics")
    async def metrics_endpoint() -> dict[str, Any]:
        return {
            **metrics,
            "account_count": store.account_count(),
            "audit_count": store.audit_count(),
            "stored_feedback_count": store.feedback_count(),
            "model_metrics": store.feedback_metrics(),
        }

    @app.get("/metrics/detectors")
    async def detector_metrics_endpoint() -> dict[str, Any]:
        return detector_metrics(store)

    @app.get("/metrics/replay")
    async def replay_metrics_endpoint() -> dict[str, Any]:
        return replay_metrics(last_replay)

    @app.get("/metrics/model")
    async def model_metrics_endpoint(since_hours: float | None = None) -> dict[str, Any]:
        return model_metrics(store, since_hours)

    @app.get("/metrics/prometheus")
    async def prometheus_endpoint() -> Response:
        return Response(prometheus_text(metrics, store, last_replay), media_type="text/plain; version=0.0.4")

    @app.get("/policy/active")
    async def active_policy_endpoint() -> dict[str, Any]:
        return policy_summary(loaded_policy)

    @app.get("/policy/lint")
    async def policy_lint_endpoint() -> dict[str, Any]:
        return lint_policy(loaded_policy)

    @app.get("/presets")
    async def presets_endpoint() -> dict[str, Any]:
        return {"presets": list_presets()}

    @app.get("/presets/{preset_name}")
    async def preset_endpoint(preset_name: str) -> dict[str, Any]:
        try:
            return load_preset(preset_name)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/deployment/fast-status")
    async def fast_status() -> dict[str, Any]:
        return fast_deploy_status(loaded_policy, store)

    @app.get("/graph")
    async def graph_endpoint() -> dict[str, Any]:
        from threatlib.signals.community_detection import _load_graph, compute_spectral_gap, run_community_detection

        graph_obj = _load_graph(store)
        partition = run_community_detection(graph_obj) if graph_obj.number_of_nodes() else {}
        communities: dict[str, list[str]] = {}
        for node, cluster_id in partition.items():
            communities.setdefault(str(cluster_id), []).append(node)
        return {
            "node_count": graph_obj.number_of_nodes(),
            "edge_count": graph_obj.number_of_edges(),
            "communities": [
                {
                    "cluster_id": cluster_id,
                    "members": members,
                    "spectral_gap": compute_spectral_gap(graph_obj.subgraph(members).copy()),
                }
                for cluster_id, members in communities.items()
            ],
        }

    app.state.policy = loaded_policy
    app.state.graph = store
    app.state.synthesizer = synthesizer
    app.state.metrics = metrics
    app.state.adapter = adapter
    app.state.last_replay = last_replay
    return app


app = create_app()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the ThreatLib API server")
    parser.add_argument("--config", default="threatlib.yaml")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8000, type=int)
    args = parser.parse_args()
    uvicorn.run(create_app(args.config), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
