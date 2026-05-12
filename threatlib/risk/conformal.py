"""Conformal prediction confidence bands."""

from __future__ import annotations

import math
from typing import Iterable


def nonconformity_score(risk_score: float, true_label: int | float) -> float:
    return abs(float(risk_score) - float(true_label))


def compute_quantile(calibration_scores: Iterable[float], alpha: float) -> float:
    scores = sorted(abs(float(score)) for score in calibration_scores)
    n = len(scores)
    if n == 0:
        return 0.0
    rank = math.ceil((n + 1) * (1.0 - alpha))  # REF: Vovk et al. 2005 conformal finite-sample quantile.
    index = min(max(rank, 1), n) - 1
    return scores[index]


def compute_band(risk_score: float, calibration_scores: Iterable[float], alpha: float) -> tuple[float, float]:
    q = compute_quantile(calibration_scores, alpha)
    return max(0.0, risk_score - q), min(1.0, risk_score + q)


class ConformalPredictor:
    def __init__(self, min_calibration_set_size: int, coverage: float) -> None:
        self.min_calibration_set_size = min_calibration_set_size
        self.coverage = coverage
        self.calibration_scores: list[float] = []

    def add_calibration_score(self, score: float) -> None:
        self.calibration_scores.append(abs(float(score)))

    def band_or_ds(
        self,
        risk_score: float,
        ds_low: float,
        ds_high: float,
    ) -> tuple[float, float, str]:
        if len(self.calibration_scores) < self.min_calibration_set_size:
            return ds_low, ds_high, "conformal_not_available"
        alpha = 1.0 - self.coverage
        cp_low, cp_high = compute_band(risk_score, self.calibration_scores, alpha)
        return min(ds_low, cp_low), max(ds_high, cp_high), "conformal"
