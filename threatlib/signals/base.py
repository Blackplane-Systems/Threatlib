"""Detector contracts for ThreatLib."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import math
import time
from typing import Any, ClassVar


EPSILON = 1e-9  # REF: Floating-point normalization guard for DS mass sums.
DEFAULT_CONFIDENCE = 0.8  # REF: Section E.1 - default detector confidence when LR is known.


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


@dataclass(frozen=True)
class DetectorResult:
    """A Dempster-Shafer mass function over {fraud, legitimate, uncertainty}."""

    fraud_mass: float = 0.0
    legitimate_mass: float = 0.0
    uncertainty_mass: float = 1.0
    detector_name: str = "unknown"
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict, compare=False)
    age_days: float = 0.0
    timestamp: float = field(default_factory=time.time, compare=False)
    combination_rule: str = "single"
    conflict_k: float = 0.0

    def __post_init__(self) -> None:
        fraud = _clamp01(self.fraud_mass)
        legitimate = _clamp01(self.legitimate_mass)
        uncertainty = _clamp01(self.uncertainty_mass)
        total = fraud + legitimate + uncertainty
        if total <= EPSILON:
            fraud, legitimate, uncertainty = 0.0, 0.0, 1.0
        elif abs(total - 1.0) > 1e-6:
            fraud, legitimate, uncertainty = fraud / total, legitimate / total, uncertainty / total
        object.__setattr__(self, "fraud_mass", fraud)
        object.__setattr__(self, "legitimate_mass", legitimate)
        object.__setattr__(self, "uncertainty_mass", uncertainty)

    @classmethod
    def uncertain(
        cls,
        detector_name: str = "unknown",
        reason: str = "uncertain",
        metadata: dict[str, Any] | None = None,
    ) -> "DetectorResult":
        return cls(
            fraud_mass=0.0,
            legitimate_mass=0.0,
            uncertainty_mass=1.0,
            detector_name=detector_name,
            reason=reason,
            metadata=metadata or {},
        )

    @classmethod
    def from_likelihood_ratio(
        cls,
        lr: float,
        confidence: float = DEFAULT_CONFIDENCE,
        detector_name: str = "unknown",
        reason: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> "DetectorResult":
        """Convert LR = P(observation|fraud)/P(observation|legitimate) into DS mass."""

        if lr <= 0 or not math.isfinite(lr):
            return cls.uncertain(detector_name, "invalid likelihood ratio", metadata)
        confidence = _clamp01(confidence)
        if abs(lr - 1.0) <= EPSILON:
            return cls.uncertain(detector_name, reason or "neutral likelihood ratio", metadata)
        if lr > 1.0:
            fraud_mass = ((lr - 1.0) / (lr + 1.0)) * confidence
            return cls(
                fraud_mass=fraud_mass,
                legitimate_mass=0.0,
                uncertainty_mass=1.0 - fraud_mass,
                detector_name=detector_name,
                reason=reason,
                metadata=metadata or {},
            )
        legitimate_mass = ((1.0 - lr) / (1.0 + lr)) * confidence
        return cls(
            fraud_mass=0.0,
            legitimate_mass=legitimate_mass,
            uncertainty_mass=1.0 - legitimate_mass,
            detector_name=detector_name,
            reason=reason,
            metadata=metadata or {},
        )

    @property
    def evidence_mass(self) -> float:
        return self.fraud_mass + self.legitimate_mass

    def is_uncertain(self) -> bool:
        return self.evidence_mass <= 1e-12 and abs(self.uncertainty_mass - 1.0) <= 1e-12

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector_name": self.detector_name,
            "fraud_mass": self.fraud_mass,
            "legitimate_mass": self.legitimate_mass,
            "uncertainty_mass": self.uncertainty_mass,
            "reason": self.reason,
            "metadata": self.metadata,
            "age_days": self.age_days,
            "combination_rule": self.combination_rule,
            "conflict_k": self.conflict_k,
        }


class BaseDetector(ABC):
    """Base class for independent signal detectors."""

    name: ClassVar[str] = "base"
    required_fields: ClassVar[tuple[str, ...]] = ()

    def __init__(self, policy: Any | None = None, graph: Any | None = None) -> None:
        self.policy = policy
        self.graph = graph

    def has_required_data(self, account_data: dict[str, Any]) -> bool:
        return all(field in account_data and account_data[field] is not None for field in self.required_fields)

    def missing_fields(self, account_data: dict[str, Any]) -> list[str]:
        return [field for field in self.required_fields if field not in account_data or account_data[field] is None]

    def safe_score(self, account_data: dict[str, Any]) -> DetectorResult:
        try:
            if not self.has_required_data(account_data):
                return DetectorResult.uncertain(
                    self.name,
                    "absent required data",
                    {"missing_fields": self.missing_fields(account_data)},
                )
            result = self.score(account_data)
            if not isinstance(result, DetectorResult):
                return DetectorResult.uncertain(self.name, "detector returned invalid result")
            return result
        except Exception as exc:  # pragma: no cover - explicitly tested through a throwing detector.
            return DetectorResult.uncertain(self.name, "detector exception", {"error": str(exc)})

    @abstractmethod
    def score(self, account_data: dict[str, Any]) -> DetectorResult:
        """Return a DS mass function for this detector."""
