"""Behavioral timing detector."""

from __future__ import annotations

import math
import statistics
from typing import Any

from threatlib.signals.base import BaseDetector, DetectorResult
from threatlib.signals.common import mini_ds_from_lrs


KS_REJECT_P = 0.05  # REF: Section D.5 - p-value threshold for human timing inconsistency.
UNIFORM_CV_THRESHOLD = 0.05  # REF: Section D.5 - near-zero interval variance threshold.


def weibull_cdf(x: float, shape: float, scale: float) -> float:
    if x <= 0:
        return 0.0
    return 1.0 - math.exp(-((x / scale) ** shape))


def ks_test_vs_baseline(intervals: list[float], baseline_params: dict[str, float]) -> tuple[float, float]:
    if not intervals:
        return 0.0, 1.0
    values = sorted(float(item) for item in intervals)
    shape = float(baseline_params.get("shape", 1.5))
    scale_ms = float(baseline_params.get("scale_ms", 180.0))
    n = len(values)
    statistic = 0.0
    for index, value in enumerate(values, start=1):
        empirical_upper = index / n
        empirical_lower = (index - 1) / n
        baseline = weibull_cdf(value, shape, scale_ms)
        statistic = max(statistic, abs(empirical_upper - baseline), abs(baseline - empirical_lower))
    pvalue = min(1.0, 2.0 * math.exp(-2.0 * n * statistic * statistic))
    return statistic, pvalue


class BehavioralTimingDetector(BaseDetector):
    name = "behavioral_timing"
    required_fields = ("timing_field_intervals",)

    def has_required_data(self, account_data: dict[str, Any]) -> bool:
        intervals = account_data.get("timing_field_intervals")
        return isinstance(intervals, dict) and any(intervals.values())

    def score(self, account_data: dict[str, Any]) -> DetectorResult:
        field_intervals = account_data["timing_field_intervals"]
        timing_policy = getattr(self.policy, "timing", None)
        baseline = getattr(timing_policy, "keystroke_human_prior", None) or {"shape": 1.5, "scale_ms": 180.0}
        corrections = getattr(timing_policy, "field_correction_factors", None) or {}
        lrs: list[tuple[float, str]] = []
        fields_seen = 0
        near_zero_any = False

        for field_name, raw_intervals in field_intervals.items():
            intervals = [float(item) for item in raw_intervals if isinstance(item, (int, float)) and item > 0]
            if not intervals:
                continue
            fields_seen += 1
            correction = float(corrections.get(field_name, 1.0))
            adjusted = [item / correction for item in intervals]
            _, pvalue = ks_test_vs_baseline(adjusted, baseline)
            if pvalue < KS_REJECT_P:
                lrs.append((8.0, f"{field_name} timing rejects human baseline"))  # REF: Section D.5 - KS rejection LR.
            elif 50.0 <= statistics.mean(adjusted) <= 300.0:
                lrs.append((0.8, f"{field_name} timing mean in human range"))  # REF: Section D.5 - typical 50-300 ms.

            if len(adjusted) > 5:
                mean = statistics.mean(adjusted)
                cv = statistics.pstdev(adjusted) / mean if mean > 0 else 0.0
                if cv < UNIFORM_CV_THRESHOLD:
                    near_zero_any = True
                    lrs.append((12.0, f"{field_name} near-zero interval variance"))  # REF: Section D.5 - scripted fixed delay.

        paste_events = account_data.get("timing_paste_events") or {}
        all_pasted = bool(paste_events) and all(bool(value) for value in paste_events.values())
        if all_pasted and near_zero_any:
            lrs.append((15.0, "all fields pasted with fixed intervals"))  # REF: Section D.5 - combined paste/script LR.
        elif all_pasted:
            lrs.append((4.0, "all fields pasted"))  # REF: Section D.5 - paste-only LR.
        elif paste_events:
            lrs.append((0.9, "not all fields pasted"))  # REF: Section D.5 - weak normal-use evidence.

        if account_data.get("timing_tos_scrolled") is False:
            lrs.append((1.5, "terms not scrolled"))  # REF: Section D.5 - weak signal.
        elif account_data.get("timing_tos_scrolled") is True:
            lrs.append((0.9, "terms scrolled"))  # REF: Section D.5 - weak legitimacy evidence.

        first_action_s = account_data.get("timing_install_to_first_action_s")
        if isinstance(first_action_s, (int, float)) and first_action_s < 5:
            lrs.append((10.0, "first action under five seconds"))  # REF: Section D.5 - scripted navigation LR.
        elif isinstance(first_action_s, (int, float)) and first_action_s >= 30:
            lrs.append((0.8, "human-paced first action"))  # REF: Section D.5 - normal navigation evidence.

        if (
            account_data.get("timing_back_nav_count") == 0
            and isinstance(account_data.get("timing_registration_duration_s"), (int, float))
            and account_data["timing_registration_duration_s"] < 30
        ):
            lrs.append((2.0, "fast registration with no corrections"))  # REF: Section D.5 - weak automation evidence.
        elif account_data.get("timing_back_nav_count", 0) > 0:
            lrs.append((0.8, "registration included corrections"))  # REF: Section D.5 - weak human evidence.

        if fields_seen == 0:
            return DetectorResult.uncertain(self.name, "no valid timing fields")

        result = mini_ds_from_lrs(self.name, lrs, confidence=min(0.9, 0.6 + 0.1 * fields_seen))
        return DetectorResult(
            result.fraud_mass,
            result.legitimate_mass,
            result.uncertainty_mass,
            self.name,
            "behavioral timing analysis",
            {"fields_seen": fields_seen, "near_zero_variance": near_zero_any},
            combination_rule=result.combination_rule,
            conflict_k=result.conflict_k,
        )

