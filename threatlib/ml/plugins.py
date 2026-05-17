"""Model plugin adapters for developer-supplied JSON ML outputs."""

from __future__ import annotations

from dataclasses import dataclass
import json
import math
from pathlib import Path
from typing import Any

from threatlib.signals.base import DetectorResult


SCORE_EPSILON = 1e-6  # REF: Probability-odds conversion guard against exact 0 or 1 model scores.
NEUTRAL_SCORE = 0.5  # REF: Binary classifier neutral probability for fraud-vs-legitimate evidence.
MODEL_SCORE_CONFIDENCE = 0.65  # REF: Conservative default confidence for externally supplied model outputs.


class MLPluginError(ValueError):
    """Raised when a model plugin declaration is invalid."""


@dataclass(frozen=True)
class ModelExecution:
    name: str
    architecture: str
    model_input: dict[str, Any]
    raw_output: dict[str, Any]
    mapped_output: dict[str, Any]
    missing_features: list[str]


def model_catalog() -> dict[str, dict[str, Any]]:
    return {
        "json_logistic_v1": {
            "description": "Linear logistic model stored as JSON coefficients and intercept.",
            "required_model_keys": ["coefficients"],
            "output": {"score": "float in [0, 1]", "label": "fraud|legitimate", "confidence": "float"},
        },
        "threshold_rules_v1": {
            "description": "Ordered threshold rules over selected JSON features.",
            "required_model_keys": ["rules"],
            "output": {"score": "float in [0, 1]", "label": "fraud|legitimate", "reason": "string"},
        },
    }


def validate_model_config(model_config: Any, sample_account: dict[str, Any], detector_results: dict[str, DetectorResult] | None = None) -> dict[str, Any]:
    model_input, missing = build_model_input(sample_account, detector_results or {}, model_config)
    raw_output = run_model(model_config, model_input)
    mapped = map_model_output(raw_output, model_config)
    result = prediction_to_detector_result(model_config, mapped)
    return {
        "name": model_config.name,
        "architecture": model_config.architecture,
        "model_input": model_input,
        "missing_features": missing,
        "raw_output": raw_output,
        "mapped_output": mapped,
        "detector_result": result.to_dict(),
    }


def build_model_input(
    account_data: dict[str, Any],
    detector_results: dict[str, DetectorResult],
    model_config: Any,
) -> tuple[dict[str, Any], list[str]]:
    model_input: dict[str, Any] = {}
    missing: list[str] = []
    detectors = {name: result.to_dict() for name, result in detector_results.items()}
    source = {"account": account_data, "detectors": detectors, **account_data}
    for output_key, source_path in model_config.feature_map.items():
        found, value = read_path(source, source_path)
        if found:
            model_input[output_key] = value
        else:
            missing.append(output_key)
    required = set(model_config.required_features)
    missing_required = sorted(required - set(model_input))
    missing.extend(item for item in missing_required if item not in missing)
    return model_input, sorted(missing)


def read_path(source: Any, dotted_path: str) -> tuple[bool, Any]:
    current = source
    for part in dotted_path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return False, None
    return True, current


def run_model(model_config: Any, model_input: dict[str, Any]) -> dict[str, Any]:
    model = _load_model_body(model_config)
    if model_config.architecture == "json_logistic_v1":
        return _run_json_logistic(model_config, model, model_input)
    if model_config.architecture == "threshold_rules_v1":
        return _run_threshold_rules(model_config, model, model_input)
    raise MLPluginError(f"unsupported ML model architecture: {model_config.architecture}")


def map_model_output(raw_output: dict[str, Any], model_config: Any) -> dict[str, Any]:
    mapped: dict[str, Any] = {}
    for target_key, output_path in model_config.output_mapping.items():
        found, value = read_path(raw_output, output_path)
        if found:
            mapped[target_key] = value
    if "score" not in mapped:
        raise MLPluginError("model output mapping must expose a score field")
    return mapped


def prediction_to_detector_result(model_config: Any, mapped_output: dict[str, Any]) -> DetectorResult:
    score = _clamp01(float(mapped_output["score"]))
    confidence = _clamp01(float(mapped_output.get("confidence", model_config.confidence or MODEL_SCORE_CONFIDENCE)))
    if abs(score - NEUTRAL_SCORE) <= 0.01:
        return DetectorResult.uncertain(
            f"ml_model:{model_config.name}",
            "model score is neutral",
            {"model": model_config.name, "architecture": model_config.architecture},
        )
    bounded = min(1.0 - SCORE_EPSILON, max(SCORE_EPSILON, score))
    lr = bounded / (1.0 - bounded)  # REF: Convert binary fraud probability to likelihood-ratio odds.
    return DetectorResult.from_likelihood_ratio(
        lr,
        confidence=confidence,
        detector_name=f"ml_model:{model_config.name}",
        reason=str(mapped_output.get("reason", mapped_output.get("label", "model_prediction"))),
        metadata={
            "model": model_config.name,
            "architecture": model_config.architecture,
            "score": score,
            "label": mapped_output.get("label"),
            "tags": list(getattr(model_config, "tags", [])),
        },
    )


def _load_model_body(model_config: Any) -> dict[str, Any]:
    if model_config.inline_model:
        return dict(model_config.inline_model)
    if model_config.model_path:
        path = Path(model_config.model_path)
        with path.open("r", encoding="utf-8") as handle:
            loaded = json.load(handle)
        if not isinstance(loaded, dict):
            raise MLPluginError("model_path must contain a JSON object")
        return loaded
    return {}


def _run_json_logistic(model_config: Any, model: dict[str, Any], model_input: dict[str, Any]) -> dict[str, Any]:
    intercept = float(model.get("intercept", 0.0))
    coefficients = model.get("coefficients", {})
    if not isinstance(coefficients, dict):
        raise MLPluginError("json_logistic_v1 coefficients must be a JSON object")
    z = intercept
    for feature_name, coefficient in coefficients.items():
        z += float(coefficient) * _as_float(model_input.get(feature_name, 0.0))
    score = 1.0 / (1.0 + math.exp(-z))  # REF: Standard logistic sigmoid for binary probability calibration.
    return {
        "score": _clamp01(score),
        "label": "fraud" if score >= NEUTRAL_SCORE else "legitimate",
        "confidence": float(model.get("confidence", model_config.confidence)),
        "reason": "json_logistic_v1",
    }


def _run_threshold_rules(model_config: Any, model: dict[str, Any], model_input: dict[str, Any]) -> dict[str, Any]:
    rules = model.get("rules", [])
    if not isinstance(rules, list):
        raise MLPluginError("threshold_rules_v1 rules must be a list")
    default_score = _clamp01(float(model.get("default_score", NEUTRAL_SCORE)))
    for rule in rules:
        if _rule_matches(rule, model_input):
            score = _clamp01(float(rule.get("score", default_score)))
            return {
                "score": score,
                "label": str(rule.get("label", "fraud" if score >= NEUTRAL_SCORE else "legitimate")),
                "confidence": float(rule.get("confidence", model.get("confidence", model_config.confidence))),
                "reason": str(rule.get("reason", "threshold_rule_matched")),
            }
    return {
        "score": default_score,
        "label": "fraud" if default_score >= NEUTRAL_SCORE else "legitimate",
        "confidence": float(model.get("confidence", model_config.confidence)),
        "reason": "threshold_rules_default",
    }


def _rule_matches(rule: dict[str, Any], model_input: dict[str, Any]) -> bool:
    feature = rule.get("feature")
    op = rule.get("op", ">=")
    if feature not in model_input:
        return False
    left = model_input[feature]
    right = rule.get("value")
    if op == "==":
        return left == right
    if op == "!=":
        return left != right
    left_float = _as_float(left)
    right_float = _as_float(right)
    if op == ">":
        return left_float > right_float
    if op == ">=":
        return left_float >= right_float
    if op == "<":
        return left_float < right_float
    if op == "<=":
        return left_float <= right_float
    raise MLPluginError(f"unsupported threshold rule operator: {op}")


def _as_float(value: Any) -> float:
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if value is None:
        return 0.0
    return float(value)


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))
