"""Account age versus high-impact action velocity."""

from __future__ import annotations

import time
from typing import Any

from threatlib.signals.base import BaseDetector, DetectorResult


MIN_AGE_HOURS_DENOMINATOR = 0.5  # REF: v2 formula 29 - denominator floor for new accounts.


def compute_velocity(event_stream: list[Any], account_age_hours: float, high_impact_actions: set[str] | None = None) -> float:
    actions = high_impact_actions or {"send_dm", "create_group", "initiate_payment", "create_listing", "broadcast_message"}
    count = sum(1 for event in event_stream if event["event_type"] in actions)
    return count / max(account_age_hours, MIN_AGE_HOURS_DENOMINATOR)


class AccountAgeVelocityDetector(BaseDetector):
    name = "account_age_velocity"
    required_fields = ("account_id",)

    def score(self, account_data: dict[str, Any]) -> DetectorResult:
        if not self.graph:
            return DetectorResult.uncertain(self.name, "no event store")
        account = self.graph.get_account(account_data["account_id"])
        if not account:
            return DetectorResult.uncertain(self.name, "account creation timestamp unavailable")
        events = self.graph.recent_events(account_data["account_id"])
        if not events:
            return DetectorResult.uncertain(self.name, "no event stream")
        age_hours = (time.time() - float(account["created_at"])) / 3600.0
        actions = set(getattr(self.policy, "high_impact_actions", []))
        high_impact_count = sum(1 for event in events if event["event_type"] in actions)
        velocity = compute_velocity(events, age_hours, actions)
        if velocity < 0.1:
            lr = 1.0  # REF: v2 C.1.2 - low high-impact velocity is neutral.
        elif velocity <= 1.0:
            lr = 2.0  # REF: v2 C.1.2 - weak velocity band.
        elif velocity <= 5.0:
            lr = 5.0  # REF: v2 C.1.2 - high velocity band.
        else:
            lr = 15.0  # REF: v2 C.1.2 - extreme high-impact velocity.
        if age_hours < 1.0 and high_impact_count > 0:
            lr *= 2.0  # REF: v2 C.1.2 - first-hour high-impact multiplier.
        return DetectorResult.from_likelihood_ratio(
            lr,
            confidence=0.8,
            detector_name=self.name,
            reason="account age high-impact velocity",
            metadata={"account_age_hours": age_hours, "high_impact_count": high_impact_count, "velocity": velocity},
        )

