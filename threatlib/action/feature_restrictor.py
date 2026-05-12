"""Feature restriction logistic calculator."""

from __future__ import annotations

import math
from typing import Any


def logistic(value: float) -> float:
    if value >= 0:
        z = math.exp(-value)
        return 1.0 / (1.0 + z)
    z = math.exp(value)
    return z / (1.0 + z)


def compute_restriction(feature: str, risk_score: float, policy: Any) -> float:
    config = policy.feature_restrictions.get(feature)
    if config is None:
        try:
            from threatlib.adapters import AdapterRegistry

            config = AdapterRegistry.from_policy(policy).get_feature_restriction_map().get(feature)
        except Exception:
            config = None
    if config is None:
        return 0.0
    threshold = config.threshold if hasattr(config, "threshold") else config["threshold"]
    steepness = config.steepness if hasattr(config, "steepness") else config["steepness"]
    return logistic(steepness * (risk_score - threshold))


def compute_restrictions(risk_score: float, policy: Any) -> dict[str, float]:
    features = set(policy.feature_restrictions.keys())
    try:
        from threatlib.adapters import AdapterRegistry

        features.update(AdapterRegistry.from_policy(policy).get_feature_restriction_map().keys())
    except Exception:
        pass
    return {feature: compute_restriction(feature, risk_score, policy) for feature in sorted(features)}


def check_emergency_bypass(reports: list[dict[str, Any]] | list[Any]) -> str | None:
    for report in reports:
        category = report.get("category") if isinstance(report, dict) else report["category"]
        # HARDCODED — NOT CONFIGURABLE — AV-14 child safety emergency bypass.
        if str(category).lower() == "csam":
            return "suspend"
    return None


def compute_network_isolation(account_ids: list[str], policy: Any) -> dict[str, Any]:
    return {
        "enabled": bool(policy.network_isolation.enabled and account_ids),
        "mode": policy.network_isolation.isolation_mode,
        "accounts": sorted(account_ids),
        "demote_search_results": policy.network_isolation.demote_search_results,
        "demote_recommendations": policy.network_isolation.demote_recommendations,
        "restrict_new_followers": policy.network_isolation.restrict_new_followers,
    }
