"""Cross-entropy coherence detector."""

from __future__ import annotations

from typing import Any

from threatlib.signals.base import BaseDetector, DetectorResult


class CrossEntropyCoherenceDetector(BaseDetector):
    name = "cross_entropy_coherence"
    depends_on = ("psycholinguistic", "email_entropy", "behavioral_timing", "ip_network", "imu_motion")
    required_fields = ()

    def has_required_data(self, account_data: dict[str, Any]) -> bool:
        return bool(account_data.get("_detector_results"))

    def missing_fields(self, account_data: dict[str, Any]) -> list[str]:
        return [] if self.has_required_data(account_data) else ["_detector_results"]

    def score(self, account_data: dict[str, Any]) -> DetectorResult:
        available = 0
        anomalous = 0
        username_entropy = _metadata_value(account_data, "psycholinguistic", "username_entropy")
        if username_entropy is not None:
            available += 1
            anomalous += int(username_entropy < 2.0 or username_entropy > 3.4)
        age = _metadata_value(account_data, "email_entropy", "email_domain_age_days")
        if age is not None:
            available += 1
            anomalous += int(age < 30)  # REF: v2 C.1.1 - email domain under 30 days is anomalous.
        for detector_name in ("behavioral_timing", "ip_network", "imu_motion"):
            result = account_data["_detector_results"].get(detector_name)
            if result and not result.is_uncertain():
                available += 1
                anomalous += int(result.fraud_mass > result.legitimate_mass)
        if available < 3:
            return DetectorResult.uncertain(self.name, "fewer than three coherence inputs")
        coherence_score = anomalous / available
        if coherence_score >= 0.8:
            lr = 20.0  # REF: v2 C.1.1 - all signals bot-like.
        elif coherence_score >= 0.6:
            lr = 8.0  # REF: v2 C.1.1 - majority bot-like.
        elif coherence_score >= 0.4:
            lr = 3.0  # REF: v2 C.1.1 - weak coherence.
        elif coherence_score < 0.2:
            lr = 0.5  # REF: v2 C.1.1 - inconsistent signs are weak human evidence.
        else:
            lr = 1.0
        return DetectorResult.from_likelihood_ratio(
            lr,
            confidence=0.8,
            detector_name=self.name,
            reason="entropy and low-level signal coherence",
            metadata={"available": available, "anomalous": anomalous, "coherence_score": coherence_score},
        )


def _metadata_value(account_data: dict[str, Any], detector: str, key: str) -> Any:
    result = account_data.get("_detector_results", {}).get(detector)
    if not result:
        return None
    return result.metadata.get(key)

