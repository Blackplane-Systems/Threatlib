from __future__ import annotations

from fastapi.testclient import TestClient

from threatlib.observability.metrics import detector_metrics, graph_metrics, prometheus_text
from threatlib.sdk.detector import DetectorContext, DetectorHarness, validate_detector_class
from threatlib.server import create_app
from threatlib.signals.email_entropy import EmailEntropyDetector


def test_score_explainability_is_structured(active_policy, graph, bot_fixture):
    app = create_app(policy=active_policy, graph=graph)
    client = TestClient(app)
    result = client.post("/score", json=bot_fixture).json()
    explainability = result["explainability"]
    assert explainability["quorum"]["met"] is True
    assert explainability["top_fraud_contributors"]
    assert explainability["policy"]["policy_hash"]
    assert explainability["action_reason"].startswith("threshold_action:")


def test_operational_metrics_and_prometheus(active_policy, graph, bot_fixture):
    app = create_app(policy=active_policy, graph=graph)
    client = TestClient(app)
    client.post("/score", json=bot_fixture)
    detector = client.get("/metrics/detectors").json()
    assert "email_entropy" in detector
    text = client.get("/metrics/prometheus").text
    assert "threatlib_requests_total" in text
    assert graph_metrics(graph)["audit_count"] == 1
    assert detector_metrics(graph)["email_entropy"]["count"] >= 1
    assert "threatlib_audit_events" in prometheus_text({"request_count": 1, "score_count": 1}, graph)


def test_detector_sdk_harness(policy, graph, bot_fixture, human_fixture):
    spec = validate_detector_class(EmailEntropyDetector)
    assert spec.name == "email_entropy"
    harness = DetectorHarness(EmailEntropyDetector, DetectorContext(policy=policy, graph=graph))
    results = harness.canonical_cases(bot_fixture, human_fixture)
    assert results["clear_bot"].fraud_mass > 0.5
    assert results["clear_human"].legitimate_mass > 0.0 or results["clear_human"].is_uncertain()
    assert results["absent_data"].is_uncertain()
