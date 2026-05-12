"""Privacy-preserving federation payload schema."""

from __future__ import annotations

from dataclasses import dataclass, field
import time
from typing import Any


@dataclass
class FederationPayload:
    platform: str
    signal_type: str
    aggregate: dict[str, Any]
    differential_privacy_epsilon: float
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "signal_type": self.signal_type,
            "aggregate": self.aggregate,
            "differential_privacy_epsilon": self.differential_privacy_epsilon,
            "timestamp": self.timestamp,
        }


def build_federation_payload(policy: Any, signal_type: str, aggregate: dict[str, Any]) -> FederationPayload:
    return FederationPayload(
        platform=policy.platform,
        signal_type=signal_type,
        aggregate=aggregate,
        differential_privacy_epsilon=policy.federation.differential_privacy_epsilon,
    )
