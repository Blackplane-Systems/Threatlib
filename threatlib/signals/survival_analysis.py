"""Cold-start survival analysis detector."""

from __future__ import annotations

import math
import time
from typing import Any

from threatlib.signals.base import BaseDetector, DetectorResult


PRIOR_HARM_RATE = 0.05  # REF: v2 C.2.4 - cold-start prior harm rate.


def compute_hazard(account_features: dict[str, float], baseline_hazard: float, cox_coefs: dict[str, float]) -> float:
    linear = sum(float(cox_coefs.get(key, 0.0)) * float(value) for key, value in account_features.items())
    return baseline_hazard * math.exp(linear)


class SurvivalAnalysisDetector(BaseDetector):
    name = "survival_analysis"
    depends_on = ("graph_distance",)
    required_fields = ("account_id",)

    def score(self, account_data: dict[str, Any]) -> DetectorResult:
        if not self.graph:
            return DetectorResult.uncertain(self.name, "no account store")
        account = self.graph.get_account(account_data["account_id"])
        if not account:
            return DetectorResult.uncertain(self.name, "account missing")
        age_hours = (time.time() - float(account["created_at"])) / 3600.0
        features = {
            "username_entropy": float(account["username_entropy"] or 0.0),
            "email_domain_age_days": float(account_data.get("email_domain_age_days") or 0.0),
            "account_age_hours": age_hours,
            "ip_is_datacenter": 1.0 if account_data.get("ip_is_datacenter") else 0.0,
        }
        graph_distance = account_data.get("_detector_results", {}).get("graph_distance")
        if graph_distance:
            features["graph_distance_k"] = float(graph_distance.metadata.get("distance", 999))
        coefs = {
            "username_entropy": 0.02,  # REF: v2 C.2.4 - cold-start weak covariate prior.
            "email_domain_age_days": -0.0001,  # REF: v2 C.2.4 - older domains lower hazard.
            "account_age_hours": -0.005,  # REF: v2 C.2.4 - risk decays with clean age.
            "ip_is_datacenter": 0.7,  # REF: v2 C.2.4 - datacenter IP hazard prior.
            "graph_distance_k": -0.1,  # REF: v2 C.2.4 - farther graph distance lower hazard.
        }
        scale = self.policy.survival_model.cold_start_weibull_scale_hours
        shape = self.policy.survival_model.cold_start_weibull_shape
        baseline_hazard = (shape / scale) * ((24.0 / scale) ** (shape - 1.0))
        hazard = compute_hazard(features, baseline_hazard, coefs)
        survival_24h = math.exp(-hazard * 24.0)
        lr = max(0.01, (1.0 - survival_24h) / PRIOR_HARM_RATE)
        return DetectorResult.from_likelihood_ratio(
            lr,
            confidence=0.6,
            detector_name=self.name,
            reason="cold-start survival analysis",
            metadata={"S24h": survival_24h, "hazard": hazard, "features": features},
        )

