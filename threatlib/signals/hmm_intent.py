"""Hidden Markov intent detector."""

from __future__ import annotations

import json
import math
from typing import Any

from threatlib.signals.base import BaseDetector, DetectorResult


STATES = ["benign", "watching", "escalating", "acting"]
OBS = ["view_profile", "search", "follow_user", "join_group", "send_dm", "send_dm_with_link", "post_content", "share_external_link", "report_user", "screen_capture", "platform_custom"]


def forward_algorithm(obs_sequence: list[str], A: list[list[float]], B: dict[str, list[float]], pi: list[float]) -> list[list[float]]:
    if not obs_sequence:
        return []
    alpha: list[list[float]] = []
    first = B.get(obs_sequence[0], B["platform_custom"])
    row = [pi[i] * first[i] for i in range(len(pi))]
    alpha.append(_normalize(row))
    for obs in obs_sequence[1:]:
        emission = B.get(obs, B["platform_custom"])
        previous = alpha[-1]
        current = []
        for i in range(len(pi)):
            current.append(sum(previous[j] * A[j][i] for j in range(len(pi))) * emission[i])
        alpha.append(_normalize(current))
    return alpha


class HMMIntentDetector(BaseDetector):
    name = "hmm_intent"
    required_fields = ("account_id",)

    def score(self, account_data: dict[str, Any]) -> DetectorResult:
        if not self.graph:
            return DetectorResult.uncertain(self.name, "no event store")
        events = list(reversed(self.graph.recent_events(account_data["account_id"])))
        if len(events) < self.policy.hmm.min_events:
            return DetectorResult.uncertain(self.name, "fewer than five events")
        obs = [_event_observation(event) for event in events]
        A, B, pi = _cold_start_hmm()
        alpha = forward_algorithm(obs, A, B, pi)
        final = alpha[-1]
        intent_probability = final[STATES.index("escalating")] + final[STATES.index("acting")]
        benign_probability = max(final[STATES.index("benign")], 1e-6)
        lr = max(0.01, intent_probability / benign_probability)
        entropy = -sum(value * math.log(value, 2) for value in final if value > 0)
        confidence = max(0.1, 1.0 - entropy / math.log(len(STATES), 2))
        return DetectorResult.from_likelihood_ratio(
            lr,
            confidence=confidence,
            detector_name=self.name,
            reason="HMM intent inference",
            metadata={"state_distribution": dict(zip(STATES, final)), "intent_probability": intent_probability, "state": STATES[final.index(max(final))]},
        )


def _event_observation(event: Any) -> str:
    data = {}
    try:
        data = json.loads(event["event_data_json"])
    except Exception:
        pass
    event_type = event["event_type"]
    if event_type == "send_dm" and (data.get("has_link") or data.get("link_domain")):
        return "send_dm_with_link"
    if event_type in {"click_external_link"}:
        return "share_external_link"
    if event_type in {"screenshot_detected", "screen_record_detected"}:
        return "screen_capture"
    return event_type if event_type in OBS else "platform_custom"


def _cold_start_hmm() -> tuple[list[list[float]], dict[str, list[float]], list[float]]:
    A = [
        [0.80, 0.15, 0.04, 0.01],
        [0.10, 0.70, 0.15, 0.05],
        [0.05, 0.10, 0.60, 0.25],
        [0.02, 0.03, 0.15, 0.80],
    ]  # REF: v2 C.3.1 - BIRDNEST-style cold-start transition prior.
    B = {
        "view_profile": [0.15, 0.30, 0.10, 0.05],
        "search": [0.20, 0.25, 0.10, 0.05],
        "follow_user": [0.10, 0.20, 0.20, 0.10],
        "join_group": [0.05, 0.15, 0.20, 0.10],
        "send_dm": [0.05, 0.10, 0.20, 0.25],
        "send_dm_with_link": [0.01, 0.03, 0.35, 0.20],
        "post_content": [0.10, 0.05, 0.15, 0.20],
        "share_external_link": [0.01, 0.03, 0.35, 0.20],
        "report_user": [0.05, 0.05, 0.10, 0.10],
        "screen_capture": [0.02, 0.05, 0.15, 0.15],
        "platform_custom": [0.27, 0.19, 0.10, 0.05],
    }  # REF: v2 C.3.1 - cold-start emission prior; calibrated after 100 harmful accounts.
    pi = [0.70, 0.20, 0.08, 0.02]  # REF: v2 C.3.1 - cold-start initial intent prior.
    return A, B, pi


def _normalize(values: list[float]) -> list[float]:
    total = sum(values)
    if total <= 0:
        return [1.0 / len(values)] * len(values)
    return [value / total for value in values]
