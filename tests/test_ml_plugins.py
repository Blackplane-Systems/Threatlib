from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from threatlib.config.policy import MLModelConfig
from threatlib.ml.plugins import validate_model_config
from threatlib.server import create_app
from threatlib.signals.ml_model import MLModelDetector


ROOT = Path(__file__).resolve().parents[1]


def _load_model(name: str) -> MLModelConfig:
    with (ROOT / "examples" / "ml" / name).open("r", encoding="utf-8") as handle:
        return MLModelConfig.model_validate(json.load(handle))


def _load_sample() -> dict:
    with (ROOT / "examples" / "ml" / "sample_account.json").open("r", encoding="utf-8") as handle:
        return json.load(handle)


def test_json_logistic_model_maps_selected_features_only() -> None:
    model = _load_model("logistic_model.json")
    response = validate_model_config(model, _load_sample())

    assert response["model_input"] == {
        "datacenter_ip": True,
        "failed_login_count": 8,
        "request_rate_per_minute": 95,
    }
    assert response["mapped_output"]["score"] > 0.95
    assert response["detector_result"]["fraud_mass"] > 0.60


def test_threshold_rules_model_supports_custom_output() -> None:
    model = _load_model("threshold_rules.json")
    response = validate_model_config(model, _load_sample())

    assert response["mapped_output"]["reason"] == "high_transaction_velocity"
    assert response["detector_result"]["fraud_mass"] > 0.40


def test_ml_model_detector_returns_uncertain_when_required_features_are_absent(policy, graph) -> None:
    model = _load_model("logistic_model.json")
    policy.ml_models = [model]

    result = MLModelDetector(policy=policy, graph=graph).safe_score({"account_id": "missing_ml_features"})

    assert result.is_uncertain()
    assert result.metadata["missing_features"]["demo-api-abuse-logistic"]


def test_ml_model_detector_combines_plugin_prediction_without_storing_inputs(policy, graph) -> None:
    model = _load_model("logistic_model.json")
    policy.ml_models = [model]

    result = MLModelDetector(policy=policy, graph=graph).safe_score(_load_sample())

    assert result.fraud_mass > 0.60
    assert "model_input" not in result.metadata
    assert result.metadata["models"][0]["name"] == "demo-api-abuse-logistic"


def test_ml_api_lists_and_validates_models(policy, graph) -> None:
    model = _load_model("logistic_model.json")
    policy.ml_models = [model]
    client = TestClient(create_app(policy=policy, graph=graph))

    listed = client.get("/ml/models")
    assert listed.status_code == 200
    assert listed.json()["configured_models"][0]["name"] == "demo-api-abuse-logistic"

    validated = client.post("/ml/validate", json={"model": model.model_dump(), "account_data": _load_sample()})
    assert validated.status_code == 200
    assert validated.json()["mapped_output"]["score"] > 0.95
