"""Multivariate Hawkes-inspired burst detector."""

from __future__ import annotations

import math
import time
from typing import Any

from threatlib.graph.account_graph import ONE_DAY_SECONDS
from threatlib.signals.base import BaseDetector, DetectorResult


EVENT_TYPES = ["registration", "login_attempt", "content_view", "content_create", "report_event"]
BETA_PER_HOUR = 1.0  # REF: v2 C.2.1 - exponential kernel beta default 1/hour.
HUMAN_REG_REG_ALPHA = 0.3  # REF: v2 C.2.1 - cold-start human alpha upper range.


def compute_intensity(event_series: list[tuple[float, str]], params: dict[str, Any]) -> list[float]:
    mu = params.get("mu", {event_type: 0.01 for event_type in EVENT_TYPES})
    alpha = params.get("alpha", {})
    beta = float(params.get("beta", BETA_PER_HOUR))
    intensities: list[float] = []
    for index, (timestamp, event_type) in enumerate(event_series):
        value = float(mu.get(event_type, 0.01))
        for previous_timestamp, previous_type in event_series[:index]:
            if previous_timestamp < timestamp:
                key = (previous_type, event_type)
                value += float(alpha.get(key, 0.1)) * math.exp(-beta * ((timestamp - previous_timestamp) / 3600.0))
        intensities.append(max(value, 1e-9))  # REF: numerical guard for log-likelihood.
    return intensities


def log_likelihood(event_series: list[tuple[float, str]], params: dict[str, Any]) -> float:
    if not event_series:
        return 0.0
    intensities = compute_intensity(event_series, params)
    horizon_hours = max((max(ts for ts, _ in event_series) - min(ts for ts, _ in event_series)) / 3600.0, 1e-6)
    integral = sum(intensities) * horizon_hours / max(len(intensities), 1)
    return sum(math.log(value) for value in intensities) - integral


class HawkesBurstDetectorV2(BaseDetector):
    name = "hawkes_burst_v2"
    depends_on = ("registration_velocity",)
    required_fields = ("account_id",)

    def score(self, account_data: dict[str, Any]) -> DetectorResult:
        if not self.graph:
            return DetectorResult.uncertain(self.name, "no graph store")
        now = time.time()
        registrations = self.graph.all_accounts(now - ONE_DAY_SECONDS)
        if len(registrations) < 3:
            return DetectorResult.uncertain(self.name, "insufficient registration series")
        series = [(float(row["created_at"]), "registration") for row in registrations]
        series.extend((float(row["timestamp"]), _map_event_type(row["event_type"])) for row in self.graph.all_recent_events(now - ONE_DAY_SECONDS))
        series = sorted(series)
        reg_times = [timestamp for timestamp, event_type in series if event_type == "registration"]
        gaps = [b - a for a, b in zip(reg_times, reg_times[1:]) if b > a]
        if not gaps:
            return DetectorResult.uncertain(self.name, "no registration gaps")
        mean_gap_hours = (sum(gaps) / len(gaps)) / 3600.0
        alpha_reg_reg = min(0.99, 1.0 / max(mean_gap_hours * 10.0, 1e-6))
        ratio = alpha_reg_reg / HUMAN_REG_REG_ALPHA
        if ratio <= 1.0:
            lr = 0.8  # REF: v2 C.2.1 - within human prior range.
        elif ratio <= 1.5:
            lr = 3.0  # REF: v2 C.2.1 - 1.5x above prior.
        elif ratio <= 3.0:
            lr = 8.0  # REF: v2 C.2.1 - 3x above prior.
        else:
            lr = 15.0  # REF: v2 C.2.1 - 5x above prior approximated by highest band.
        return DetectorResult.from_likelihood_ratio(
            lr,
            confidence=0.8,
            detector_name=self.name,
            reason="multivariate Hawkes burst approximation",
            metadata={"alpha_reg_reg": alpha_reg_reg, "mean_gap_hours": mean_gap_hours},
        )


def _map_event_type(event_type: str) -> str:
    if event_type in {"view_content", "view_profile", "search"}:
        return "content_view"
    if event_type in {"post_content", "send_dm", "create_listing"}:
        return "content_create"
    if event_type == "report_user":
        return "report_event"
    return "login_attempt" if event_type == "login_attempt" else "content_view"

