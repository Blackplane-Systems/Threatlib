"""Enhanced cross-signal coherence detector."""

from __future__ import annotations

from typing import Any

from threatlib.signals.base import BaseDetector, DetectorResult
from threatlib.signals.common import mini_ds_from_lrs
from threatlib.signals.device_fingerprint import _timezone_mismatch


class CrossSignalCoherenceDetector(BaseDetector):
    name = "cross_signal_coherence_v2"
    depends_on = ("cross_entropy_coherence", "device_fingerprint", "session_anomaly", "account_age_velocity")
    required_fields = ()

    def has_required_data(self, account_data: dict[str, Any]) -> bool:
        return bool(account_data.get("_detector_results") or account_data.get("account_id"))

    def score(self, account_data: dict[str, Any]) -> DetectorResult:
        lrs: list[tuple[float, str]] = []
        entropy = account_data.get("_detector_results", {}).get("cross_entropy_coherence")
        if entropy and entropy.fraud_mass > 0.5:
            lrs.append((20.0, "entropy signals coherent"))  # REF: v2 C.2.3 - all entropy coherent LR.
        if _timezone_mismatch(account_data.get("ip_geo_country"), account_data.get("device_timezone")):
            lrs.append((15.0, "temporal or geo incoherence"))  # REF: v2 C.2.3 - impossible geo coherence LR.
        platform = account_data.get("device_platform")
        if platform == "android" and account_data.get("metadata", {}).get("has_browser_fingerprint") is True:
            lrs.append((8.0, "platform incoherence"))  # REF: v2 C.2.3 - platform mismatch LR.
        age_velocity = account_data.get("_detector_results", {}).get("account_age_velocity")
        if age_velocity and age_velocity.fraud_mass > 0.4:
            lrs.append((6.0, "new account acting like veteran"))  # REF: v2 C.2.3 - behavioural incoherence LR.
        if not lrs:
            return DetectorResult.uncertain(self.name, "no cross-signal incoherence")
        result = mini_ds_from_lrs(self.name, lrs, confidence=0.8)
        return DetectorResult(result.fraud_mass, result.legitimate_mass, result.uncertainty_mass, self.name, "cross-signal coherence v2", {"subsignals": len(lrs)}, combination_rule=result.combination_rule, conflict_k=result.conflict_k)

