"""Established-account behavioral drift and temporary hold detector."""

from __future__ import annotations

from collections import Counter
import json
import time
from typing import Any

from threatlib.graph.account_graph import ONE_DAY_SECONDS
from threatlib.signals.base import BaseDetector, DetectorResult
from threatlib.signals.common import mini_ds_from_lrs


RECENT_WINDOW_SECONDS = ONE_DAY_SECONDS  # REF: Drift needs fast response to repeated high-impact actions in the last day.
BASELINE_WINDOW_SECONDS = 30.0 * ONE_DAY_SECONDS  # REF: Thirty-day behavioral baseline balances recency with enough established-account history.
NEW_USER_GRACE_HOURS = 72.0  # REF: New users often explore features unpredictably during first three days; do not treat this as established drift.
MIN_BASELINE_EVENTS = 5  # REF: Minimum history before comparing current behavior to an account's own baseline.
MIN_RECENT_REPEATED_ACTIONS = 6  # REF: Repetition threshold before temporary feature holds are considered.
DRIFT_RATIO_THRESHOLD = 5.0  # REF: Current action rate five times historical rate is a conservative drift threshold.
TEMPORARY_HOLD_LEVEL = 0.90  # REF: Temporary analysis hold should materially restrict the repeated feature without implying suspension.


class BehavioralDriftDetector(BaseDetector):
    """Finds established accounts suddenly repeating actions they historically did not perform."""

    name = "behavioral_drift"
    required_fields = ("account_id",)
    depends_on = ("session_anomaly", "account_age_velocity", "domain_scenario")

    def score(self, account_data: dict[str, Any]) -> DetectorResult:
        if self.graph is None:
            return DetectorResult.uncertain(self.name, "no event store")
        account = self.graph.get_account(account_data["account_id"])
        if not account:
            return DetectorResult.uncertain(self.name, "account history unavailable")
        age_hours = (time.time() - float(account["created_at"])) / 3600.0
        if age_hours < NEW_USER_GRACE_HOURS:
            return DetectorResult.uncertain(
                self.name,
                "new user behavior not treated as established drift",
                {"classification": "new_user_behavior", "account_age_hours": age_hours},
            )

        rows = self.graph.recent_events(account_data["account_id"], time.time() - BASELINE_WINDOW_SECONDS)
        recent_rows, baseline_rows = _split_recent_baseline(rows)
        if len(baseline_rows) < MIN_BASELINE_EVENTS:
            return DetectorResult.uncertain(self.name, "insufficient established baseline", {"baseline_event_count": len(baseline_rows)})
        if not recent_rows:
            return DetectorResult.uncertain(self.name, "no recent behavior to compare")

        high_impact = set(getattr(self.policy, "high_impact_actions", [])) or {
            "send_dm",
            "send_message",
            "forward_message",
            "post_content",
            "trade_item",
            "gift_item",
        }
        recent_counts = _counts(recent_rows)
        baseline_counts = _counts(baseline_rows)
        candidate, recent_count, baseline_count = _strongest_drift(recent_counts, baseline_counts, high_impact)
        if candidate is None:
            if _stable_behavior(recent_counts, baseline_counts):
                return DetectorResult.from_likelihood_ratio(
                    0.55,
                    confidence=0.70,
                    detector_name=self.name,
                    reason="recent behavior remains close to established baseline",
                    metadata={"classification": "stable_established_behavior"},
                )
            return DetectorResult.uncertain(self.name, "no material action drift")

        detector_results = account_data.get("_detector_results") if isinstance(account_data.get("_detector_results"), dict) else {}
        session_fraud = _fraud(detector_results, "session_anomaly")
        scenario_fraud = _fraud(detector_results, "domain_scenario")
        velocity_fraud = _fraud(detector_results, "account_age_velocity")
        ratio = recent_count / max(baseline_count, 1)
        lrs: list[tuple[float, str]] = []
        classification = "established_behavior_drift"
        if baseline_count == 0:
            lrs.append((10.0, "established account repeats a previously unseen high-impact action"))  # REF: Repeated new high-impact action is stronger than ordinary novelty.
        elif ratio >= DRIFT_RATIO_THRESHOLD:
            lrs.append((8.0, "recent high-impact action rate far exceeds account baseline"))  # REF: Fivefold account-level drift threshold.
        if session_fraud >= 0.40:
            classification = "possible_account_hijack"
            lrs.append((12.0, "behavior drift coincides with session anomaly"))  # REF: ATO signal when behavior shift and session anomaly agree.
        elif scenario_fraud >= 0.45:
            lrs.append((8.0, "behavior drift aligns with domain scenario evidence"))  # REF: Drift plus scenario playbook is stronger than drift alone.
        elif velocity_fraud >= 0.35:
            lrs.append((5.0, "behavior drift aligns with high-impact velocity"))  # REF: Velocity corroborates repeated action drift.

        result = mini_ds_from_lrs(self.name, lrs, confidence=0.78)
        return DetectorResult(
            result.fraud_mass,
            result.legitimate_mass,
            result.uncertainty_mass,
            self.name,
            "established account behavior drift analysis",
            {
                "classification": classification,
                "drift_action": candidate,
                "recent_action_count": recent_count,
                "baseline_action_count": baseline_count,
                "drift_ratio": ratio,
                "temporary_restrictions": [
                    {
                        "feature": candidate,
                        "level": TEMPORARY_HOLD_LEVEL,
                        "reason": "temporary hold while account behavior drift is reviewed",
                    }
                ],
                "analysis_without_suspension": True,
                "action_cap": "review_queue",
                "session_anomaly_fraud_mass": session_fraud,
            },
            combination_rule=result.combination_rule,
            conflict_k=result.conflict_k,
        )


def _split_recent_baseline(rows: list[Any]) -> tuple[list[Any], list[Any]]:
    cutoff = time.time() - RECENT_WINDOW_SECONDS
    recent = [row for row in rows if float(row["timestamp"]) >= cutoff]
    baseline = [row for row in rows if float(row["timestamp"]) < cutoff]
    return recent, baseline


def _counts(rows: list[Any]) -> Counter[str]:
    return Counter(str(row["event_type"]) for row in rows)


def _strongest_drift(
    recent_counts: Counter[str],
    baseline_counts: Counter[str],
    high_impact: set[str],
) -> tuple[str | None, int, int]:
    best: tuple[str | None, int, int, float] = (None, 0, 0, 0.0)
    for action in high_impact:
        recent_count = recent_counts[action]
        if recent_count < MIN_RECENT_REPEATED_ACTIONS:
            continue
        baseline_count = baseline_counts[action]
        ratio = recent_count / max(baseline_count, 1)
        if baseline_count == 0 or ratio >= DRIFT_RATIO_THRESHOLD:
            score = ratio + (3.0 if baseline_count == 0 else 0.0)
            if score > best[3]:
                best = (action, recent_count, baseline_count, score)
    return best[0], best[1], best[2]


def _stable_behavior(recent_counts: Counter[str], baseline_counts: Counter[str]) -> bool:
    if not recent_counts or not baseline_counts:
        return False
    recent_total = sum(recent_counts.values())
    baseline_total = sum(baseline_counts.values())
    if recent_total < 3 or baseline_total < MIN_BASELINE_EVENTS:
        return False
    top_recent = recent_counts.most_common(1)[0][0]
    recent_share = recent_counts[top_recent] / recent_total
    baseline_share = baseline_counts[top_recent] / baseline_total
    return abs(recent_share - baseline_share) <= 0.25


def _fraud(results: dict[str, DetectorResult], name: str) -> float:
    result = results.get(name)
    return float(result.fraud_mass) if result else 0.0
