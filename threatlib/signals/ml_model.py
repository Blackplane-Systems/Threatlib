"""Detector wrapper for developer-supplied ML model plugins."""

from __future__ import annotations

from typing import Any

from threatlib.fusion.dempster_shafer import combine_many
from threatlib.ml.plugins import MLPluginError, build_model_input, map_model_output, prediction_to_detector_result, run_model
from threatlib.signals.base import BaseDetector, DetectorResult


class MLModelDetector(BaseDetector):
    name = "ml_model"
    required_fields = ("account_id",)
    depends_on = (
        "email_entropy",
        "psycholinguistic",
        "device_fingerprint",
        "behavioral_timing",
        "ip_network",
        "content_signal",
        "payment_signal",
        "hmm_intent",
    )

    def score(self, account_data: dict[str, Any]) -> DetectorResult:
        model_configs = [model for model in getattr(self.policy, "ml_models", []) if model.enabled]
        if not model_configs:
            return DetectorResult.uncertain(self.name, "no enabled ML model plugins")

        detector_results = account_data.get("_detector_results", {})
        model_results: list[DetectorResult] = []
        metadata: dict[str, Any] = {"models": [], "missing_features": {}, "errors": {}}

        for model_config in model_configs:
            model_input, missing = build_model_input(account_data, detector_results, model_config)
            if missing:
                metadata["missing_features"][model_config.name] = missing
                model_results.append(
                    DetectorResult.uncertain(
                        f"ml_model:{model_config.name}",
                        "missing model features",
                        {"model": model_config.name, "missing_fields": missing},
                    )
                )
                continue
            try:
                raw_output = run_model(model_config, model_input)
                mapped_output = map_model_output(raw_output, model_config)
                result = prediction_to_detector_result(model_config, mapped_output)
                model_results.append(result)
                metadata["models"].append(
                    {
                        "name": model_config.name,
                        "architecture": model_config.architecture,
                        "score": mapped_output.get("score"),
                        "label": mapped_output.get("label"),
                    }
                )
            except (MLPluginError, ValueError, OSError) as exc:
                metadata["errors"][model_config.name] = str(exc)
                model_results.append(
                    DetectorResult.uncertain(
                        f"ml_model:{model_config.name}",
                        "model plugin error",
                        {"model": model_config.name, "error": str(exc)},
                    )
                )

        usable = [result for result in model_results if not result.is_uncertain()]
        if not usable:
            return DetectorResult.uncertain(self.name, "no usable ML model evidence", metadata)
        combined = combine_many(usable)
        return DetectorResult(
            fraud_mass=combined.fraud_mass,
            legitimate_mass=combined.legitimate_mass,
            uncertainty_mass=combined.uncertainty_mass,
            detector_name=self.name,
            reason="ml_model_plugins",
            metadata=metadata,
            combination_rule=combined.combination_rule,
            conflict_k=combined.conflict_k,
        )
